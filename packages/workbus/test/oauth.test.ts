import { SELF } from 'cloudflare:test'
import { createHash } from 'node:crypto'
import { describe, expect, it } from 'vitest'

const origin = 'https://workbus.test'
const redirectUri = 'https://client.example/callback?tenant=a&mode=b'
const verifier = 'verifier-value-that-is-long-enough-for-pkce-123456'
const challenge = createHash('sha256').update(verifier).digest('base64url')

async function registerClient(redirect = redirectUri) {
  const response = await SELF.fetch(origin + '/oauth/register', {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ redirect_uris: [redirect], token_endpoint_auth_method: 'none', client_name: 'OAuth test client' }),
  })
  expect(response.status).toBe(201)
  return await response.json() as { client_id: string; redirect_uris: string[] }
}

async function authorize(clientId: string) {
  const state = 'test-state-123'
  const audience = origin + '/b/bridge-check'
  const url = new URL(origin + '/oauth/authorize')
  url.search = new URLSearchParams({
    client_id: clientId,
    redirect_uri: redirectUri,
    response_type: 'code',
    code_challenge: challenge,
    code_challenge_method: 'S256',
    state,
    resource: audience,
  }).toString()

  const page = await SELF.fetch(url)
  expect(page.status).toBe(200)
  const html = await page.text()
  // The query ampersand must be HTML-escaped in the attribute, then submitted unchanged.
  expect(html).toContain('value="https://client.example/callback?tenant=a&amp;mode=b"')

  const approved = await SELF.fetch(origin + '/oauth/authorize', {
    method: 'POST',
    redirect: 'manual',
    headers: { 'content-type': 'application/x-www-form-urlencoded' },
    body: new URLSearchParams({
      client_id: clientId,
      redirect_uri: redirectUri,
      state,
      challenge,
      audience,
      password: 'workbus-test-only-owner-password-2026',
    }),
  })
  expect(approved.status).toBe(302)
  const location = approved.headers.get('location')
  expect(location).toBeTruthy()
  const callback = new URL(location!)
  expect(callback.origin + callback.pathname).toBe('https://client.example/callback')
  expect(callback.searchParams.get('tenant')).toBe('a')
  expect(callback.searchParams.get('mode')).toBe('b')
  expect(callback.searchParams.get('state')).toBe(state)
  return callback.searchParams.get('code')!
}

async function exchange(code: string, clientId: string) {
  return SELF.fetch(origin + '/oauth/token', {
    method: 'POST',
    headers: { 'content-type': 'application/x-www-form-urlencoded' },
    body: new URLSearchParams({
      grant_type: 'authorization_code',
      code,
      client_id: clientId,
      redirect_uri: redirectUri,
      code_verifier: verifier,
    }),
  })
}

let currentClientId = ''

describe('Workbus OAuth', () => {
  it('publishes authorization-server and protected-resource metadata', async () => {
    const authorization = await SELF.fetch(origin + '/.well-known/oauth-authorization-server')
    expect(authorization.status).toBe(200)
    const metadata = await authorization.json() as Record<string, unknown>
    expect(metadata.issuer).toBe(origin + '/oauth')
    expect(metadata.authorization_endpoint).toBe(origin + '/oauth/authorize')
    expect(metadata.token_endpoint).toBe(origin + '/oauth/token')
    expect(metadata.registration_endpoint).toBe(origin + '/oauth/register')
    expect(metadata.code_challenge_methods_supported).toEqual(['S256'])

    const resource = await SELF.fetch(origin + '/.well-known/oauth-protected-resource/b/bridge-check')
    expect(resource.status).toBe(200)
    const protectedResource = await resource.json() as Record<string, unknown>
    expect(protectedResource.resource).toBe(origin + '/b/bridge-check')
    expect(protectedResource.authorization_servers).toEqual([origin + '/oauth'])
  })

  it('rejects insecure redirect URIs during dynamic registration', async () => {
    const response = await SELF.fetch(origin + '/oauth/register', {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ redirect_uris: ['http://attacker.example/callback'] }),
    })
    expect(response.status).toBe(400)
    expect(await response.json()).toMatchObject({ error: 'invalid_client_metadata' })
  })

  it('preserves redirect URI query parameters and exchanges a code only once', async () => {
    const client = await registerClient()
    currentClientId = client.client_id
    expect(client.redirect_uris).toEqual([redirectUri])

    const code = await authorize(client.client_id)
    expect(code).toBeTruthy()
    const tokenResponse = await exchange(code, client.client_id)
    expect(tokenResponse.status).toBe(200)
    const token = await tokenResponse.json() as { access_token: string; token_type: string; expires_in: number; scope: string }
    expect(token.access_token).toBeTruthy()
    expect(token.token_type).toBe('Bearer')
    expect(token.expires_in).toBe(3600)
    expect(token.scope).toBe('board:read board:write')

    const replay = await exchange(code)
    expect(replay.status).toBe(400)
    expect(await replay.json()).toMatchObject({ error: 'invalid_grant' })
  })

  it('allows only one of two concurrent exchanges to consume an authorization code', async () => {
    const client = await registerClient()
    currentClientId = client.client_id
    const code = await authorize(client.client_id)
    const responses = await Promise.all([exchange(code), exchange(code)])
    expect(responses.map((response) => response.status).sort()).toEqual([200, 400])
  })
})
