import { DurableObject } from 'cloudflare:workers'
import { createHash, randomBytes, timingSafeEqual } from 'node:crypto'
import { mint, type IssuerKey } from './auth.ts'

type Client = { client_id: string; redirect_uris: string[]; client_name?: string }
type RecordValue = { value: string; expires: number }

const b64url = (bytes: Uint8Array) => Buffer.from(bytes).toString('base64url')
const random = (size = 32) => b64url(randomBytes(size))
const sha256 = (value: string) => createHash('sha256').update(value).digest('base64url')
const json = (value: unknown, status = 200, headers: HeadersInit = {}) =>
  Response.json(value, { status, headers: { 'cache-control': 'no-store', ...headers } })

// Hidden form values are HTML attributes, not URL components. Escape them for HTML
// so the browser submits the original URI/state exactly once via form encoding.
const escapeHtml = (value: string) => value
  .replaceAll('&', '&amp;')
  .replaceAll('<', '&lt;')
  .replaceAll('>', '&gt;')
  .replaceAll('"', '&quot;')
  .replaceAll("'", '&#39;')

/** Durable, single-purpose storage for OAuth clients and one-time authorization codes. */
export class OAuthStore extends DurableObject {
  constructor(ctx: DurableObjectState, env: unknown) {
    super(ctx, env)
    ctx.storage.sql.exec(`
      CREATE TABLE IF NOT EXISTS oauth_clients (
        client_id TEXT PRIMARY KEY, redirect_uris TEXT NOT NULL, client_name TEXT
      );
      CREATE TABLE IF NOT EXISTS oauth_codes (
        code_hash TEXT PRIMARY KEY, client_id TEXT NOT NULL, redirect_uri TEXT NOT NULL,
        challenge TEXT NOT NULL, subject TEXT NOT NULL, audience TEXT NOT NULL, expires INTEGER NOT NULL
      );
    `)
  }
  async fetch(request: Request): Promise<Response> {
    if (request.method !== 'POST') return json({ error: 'method_not_allowed' }, 405)
    const body = await request.json() as Record<string, unknown>
    const op = body.op
    if (op === 'register') {
      const client = body.client as Client
      this.ctx.storage.sql.exec(
        'INSERT INTO oauth_clients (client_id, redirect_uris, client_name) VALUES (?, ?, ?)',
        client.client_id, JSON.stringify(client.redirect_uris), client.client_name ?? null,
      )
      return json({ ok: true })
    }
    if (op === 'client') {
      const row = this.ctx.storage.sql.exec<{ client_id: string; redirect_uris: string; client_name: string | null }>(
        'SELECT * FROM oauth_clients WHERE client_id = ?', String(body.client_id),
      ).toArray()[0]
      return json(row ? { ...row, redirect_uris: JSON.parse(row.redirect_uris) } : null)
    }
    if (op === 'issue') {
      this.ctx.storage.sql.exec(
        'INSERT INTO oauth_codes (code_hash, client_id, redirect_uri, challenge, subject, audience, expires) VALUES (?, ?, ?, ?, ?, ?, ?)',
        sha256(String(body.code)), body.client_id, body.redirect_uri, body.challenge,
        body.subject, body.audience, body.expires,
      )
      return json({ ok: true })
    }
    if (op === 'consume') {
      // Match every proof before consuming. A bad verifier or mismatched client cannot burn a valid code.
      // DELETE ... RETURNING is a single atomic SQLite operation, so only one concurrent exchange wins.
      const row = this.ctx.storage.sql.exec<{ client_id: string; redirect_uri: string; challenge: string; subject: string; audience: string; expires: number }>(
        'DELETE FROM oauth_codes WHERE code_hash = ? AND client_id = ? AND redirect_uri = ? AND challenge = ? AND expires >= ? RETURNING client_id, redirect_uri, challenge, subject, audience, expires',
        sha256(String(body.code)), String(body.client_id), String(body.redirect_uri), String(body.challenge), Date.now(),
      ).toArray()[0]
      return json(row ?? null)
    }
    return json({ error: 'unknown_operation' }, 400)
  }
}

export type OAuthEnv = {
  OAUTH: { getByName(name: string): { fetch(input: RequestInfo | URL, init?: RequestInit): Promise<Response> } }
  OAUTH_OWNER_PASSWORD: string
  BOARD_ISSUER_KEY: string
  BOARD_ORIGIN?: string
}

const store = (env: OAuthEnv) => env.OAUTH.getByName('workbus-oauth')
const callStore = async (env: OAuthEnv, value: unknown) =>
  store(env).fetch('https://oauth-store/', { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify(value) })
const same = (a: string, b: string) => {
  const aa = Buffer.from(a), bb = Buffer.from(b)
  return aa.length === bb.length && timingSafeEqual(aa, bb)
}
const allowedRedirect = (uri: string) => {
  try {
    const url = new URL(uri)
    if (url.username || url.password || url.hash) return false
    if (url.protocol === 'https:') return true
    return url.protocol === 'http:' && ['localhost', '127.0.0.1', '[::1]'].includes(url.hostname)
  } catch { return false }
}
const html = (body: string) => new Response(
  `<!doctype html><html><head><meta name="viewport" content="width=device-width,initial-scale=1"><title>Workbus sign in</title></head><body style="font:16px system-ui;max-width:440px;margin:48px auto;padding:20px"><h2>Workbus Owner sign in</h2>${body}</body></html>`,
  { headers: { 'content-type': 'text/html; charset=utf-8', 'cache-control': 'no-store', 'x-content-type-options': 'nosniff', 'content-security-policy': "default-src 'none'; style-src 'unsafe-inline'; form-action 'self'; base-uri 'none'; frame-ancestors 'none'" } },
)

/** OAuth 2.1 authorization server endpoints shared by MCP clients (ChatGPT and Claude). */
export async function handleOAuth(request: Request, env: OAuthEnv): Promise<Response | null> {
  const url = new URL(request.url)
  const origin = (env.BOARD_ORIGIN ?? url.origin).replace(/\/+$/, '')
  const issuer = origin + '/oauth'
  const resource = url.origin + url.pathname.replace(/\/(?:\.well-known\/.*|oauth\/.*)$/, '')
  if (url.pathname === '/.well-known/oauth-authorization-server' || url.pathname === '/.well-known/oauth-authorization-server/oauth' || url.pathname === '/oauth/.well-known/oauth-authorization-server') {
    // RFC 8414 requires the metadata issuer to match the issuer identifier used
    // to construct its well-known URL. The root and /oauth issuers are distinct.
    const metadataIssuer = url.pathname === '/.well-known/oauth-authorization-server' ? origin : issuer
    return json({ issuer: metadataIssuer, authorization_endpoint: origin + '/oauth/authorize', token_endpoint: origin + '/oauth/token',
      registration_endpoint: origin + '/oauth/register', response_types_supported: ['code'],
      grant_types_supported: ['authorization_code'], code_challenge_methods_supported: ['S256'],
      token_endpoint_auth_methods_supported: ['none'], client_id_metadata_document_supported: false })
  }
  if (url.pathname === '/.well-known/oauth-protected-resource' || url.pathname.startsWith('/.well-known/oauth-protected-resource/')) {
    return json({ resource: origin + '/b/bridge-check', authorization_servers: [issuer],
      bearer_methods_supported: ['header'], scopes_supported: ['board:read', 'board:write'] })
  }
  if (url.pathname === '/oauth/register' && request.method === 'POST') {
    const input = await request.json() as { redirect_uris?: unknown; client_name?: unknown; token_endpoint_auth_method?: unknown }
    const redirects = input.redirect_uris
    if (!Array.isArray(redirects) || redirects.length < 1 || redirects.length > 10 ||
      !redirects.every((v) => typeof v === 'string' && allowedRedirect(v)) ||
      input.token_endpoint_auth_method && input.token_endpoint_auth_method !== 'none') {
      return json({ error: 'invalid_client_metadata' }, 400)
    }
    const client: Client = { client_id: random(24), redirect_uris: [...new Set(redirects as string[])], ...(typeof input.client_name === 'string' ? { client_name: input.client_name.slice(0, 100) } : {}) }
    const saved = await callStore(env, { op: 'register', client })
    if (!saved.ok) return json({ error: 'server_error' }, 500)
    return json({ ...client, token_endpoint_auth_method: 'none', grant_types: ['authorization_code'], response_types: ['code'] }, 201)
  }
  if (url.pathname === '/oauth/authorize' && request.method === 'GET') {
    const p = url.searchParams
    const clientId = p.get('client_id') ?? ''
    const clientResponse = await callStore(env, { op: 'client', client_id: clientId })
    const client = await clientResponse.json() as (Client & { redirect_uris: string[] }) | null
    const redirect = p.get('redirect_uri') ?? ''
    const state = p.get('state') ?? ''
    const challenge = p.get('code_challenge') ?? ''
    if (!client || !client.redirect_uris.includes(redirect) || !allowedRedirect(redirect) ||
      p.get('response_type') !== 'code' || p.get('code_challenge_method') !== 'S256' ||
      !/^[A-Za-z0-9_-]{43,128}$/.test(challenge) || !state || state.length > 1024 ||
      (p.get('resource') ?? p.get('audience')) !== origin + '/b/bridge-check') return json({ error: 'invalid_request' }, 400)
    const hidden = Object.entries({ client_id: clientId, redirect_uri: redirect, state, challenge, audience: p.get('resource') ?? p.get('audience')! })
      .map(([k,v]) => `<input type="hidden" name="${escapeHtml(k)}" value="${escapeHtml(v)}">`).join('')
    return html(`<p>Sign in to authorize this MCP client to access your Workbus board.</p><form method="post" action="/oauth/authorize">${hidden}<label>Owner password<br><input name="password" type="password" required autocomplete="current-password" style="width:100%;padding:12px;margin:8px 0"></label><button style="padding:12px 20px">Authorize</button></form>`)
  }
  if (url.pathname === '/oauth/authorize' && request.method === 'POST') {
    const form = await request.formData()
    const password = String(form.get('password') ?? '')
    if (!env.OAUTH_OWNER_PASSWORD || !same(password, env.OAUTH_OWNER_PASSWORD)) return html('<p>Incorrect password. Go back and try again.</p><a href="javascript:history.back()">Back</a>')
    const clientId = String(form.get('client_id') ?? '')
    const redirect = String(form.get('redirect_uri') ?? '')
    const state = String(form.get('state') ?? '')
    const challenge = String(form.get('challenge') ?? '')
    const audience = String(form.get('audience') ?? '')
    const clientResponse = await callStore(env, { op: 'client', client_id: clientId })
    const client = await clientResponse.json() as Client | null
    if (!client || !client.redirect_uris.includes(redirect) || !allowedRedirect(redirect) ||
      !/^[A-Za-z0-9_-]{43,128}$/.test(challenge) || audience !== origin + '/b/bridge-check') return json({ error: 'invalid_request' }, 400)
    const code = random(32)
    const saved = await callStore(env, { op: 'issue', code, client_id: clientId, redirect_uri: redirect, challenge, subject: 'rk-owner', audience, expires: Date.now() + 300_000 })
    if (!saved.ok) return json({ error: 'server_error' }, 500)
    const target = new URL(redirect)
    target.searchParams.set('code', code)
    target.searchParams.set('state', state)
    return Response.redirect(target.toString(), 302)
  }
  if (url.pathname === '/oauth/token' && request.method === 'POST') {
    const form = await request.formData()
    if (form.get('grant_type') !== 'authorization_code') return json({ error: 'unsupported_grant_type' }, 400)
    const code = String(form.get('code') ?? '')
    const clientId = String(form.get('client_id') ?? '')
    const redirect = String(form.get('redirect_uri') ?? '')
    const verifier = String(form.get('code_verifier') ?? '')
    if (!/^[A-Za-z0-9._~-]{43,128}$/.test(verifier)) return json({ error: 'invalid_request' }, 400)
    const consumed = await callStore(env, {
      op: 'consume', code, client_id: clientId, redirect_uri: redirect, challenge: sha256(verifier),
    })
    const record = await consumed.json() as { client_id: string; redirect_uri: string; challenge: string; subject: string; audience: string; expires: number } | null
    if (!record) return json({ error: 'invalid_grant' }, 400)
    const key = JSON.parse(env.BOARD_ISSUER_KEY) as IssuerKey
    const accessToken = await mint({ origin, key, sub: record.subject, audience: record.audience, ttlSeconds: 3600, claims: { role: 'owner', scope: 'board:read board:write' } })
    return json({ access_token: accessToken, token_type: 'Bearer', expires_in: 3600, scope: 'board:read board:write' })
  }
  return null
}
