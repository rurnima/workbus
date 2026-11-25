// The Gateway: stateless, in every location. It routes each request to its board's Ledger by name
// (no lookup: getByName derives the ID), checks it, says who is calling, and holds every wait
// itself, woken by the board's Relay, so a client waiting half an hour costs CPU-milliseconds.
import { z } from 'zod'
import { WorkbusError, failureOf, failureResponse, type Failure } from '../errors.ts'
import type { Caller, Principal } from '../ledger/core.ts'
import { GATEWAY, match, ROUTES, type Route } from '../protocol/routes.ts'
import '../protocol/index.ts'
import { authenticate, publicJwks, type IssuerKey } from './auth.ts'
import { handleOAuth } from './oauth.ts'
import { parseNarrow, parseProfile } from './headers.ts'
import { courierId, inboxName, type SyncProvider } from '../sync/provider.ts'

export const VERSION = '0.1.0'
const BOARD_NAME = /^[a-z0-9][a-z0-9_-]{0,63}$/
const STREAM_MAX_MS = 280_000
const PING_MS = 15_000

/** A Durable Object namespace as Workbus uses it: stubs by name, untyped. DurableObjectNamespace<any>
 * makes tsc give up on its stubs' types (TS2589, "excessively deep"). */
export type Namespace = { getByName(name: string): any }

export type GatewayEnv = {
  LEDGER: Namespace
  RELAY: Namespace
  INBOX?: Namespace
  MAILBOX?: Namespace
  BOARD_ISSUER_KEY: string
  OAUTH: { getByName(name: string): { fetch(input: RequestInfo | URL, init?: RequestInit): Promise<Response> } }
  OAUTH_OWNER_PASSWORD: string
  BOARD_ORIGIN?: string
  ACCESS_TEAM?: string
  ACCESS_AUD?: string
}

export type Mount = { name: string; origin: string; url: string }

/** Gateway handlers for routes the Gateway serves itself (files' bytes, webhooks), by route name. */
export { GATEWAY }
/** What discovery lists of a board's sync entries. */
export const SYNC_ENTRIES: { key: string; platform: string }[] = []

export type LedgerStub = { call(caller: Caller, method: string, input: unknown, mount?: Mount): Promise<{ ok: true; value: unknown } | { ok: false; failure: Failure }>; [key: string]: any }

const json = (value: unknown, status = 200) => new Response(JSON.stringify(value), { status, headers: { 'content-type': 'application/json' } })

/** A zod failure as the protocol says it: the first issue, its path, its message. */
export function validationFailure(error: z.ZodError): WorkbusError {
  let issue: any = error.issues[0]
  let path: (string | number)[] = issue.path ?? []
  for (let depth = 0; issue && depth < 8; depth++) {
    if (issue.code === 'invalid_union' && Array.isArray(issue.errors) && issue.errors.length) {
      const option = [...issue.errors].sort((a: unknown[], b: unknown[]) => a.length - b.length)[0] as any[]
      if (!option?.length) break
      path = [...path, ...(option[0].path ?? [])]
      issue = option[0]
      continue
    }
    if (issue.code === 'invalid_key' && Array.isArray(issue.issues) && issue.issues.length) {
      issue = issue.issues[0]
      continue
    }
    break
  }
  if (issue?.code === 'too_big' && path.length === 1 && path[0] === 'text' && issue.maximum === 10000)
    return new WorkbusError(400, 'text_too_long', "A message's text is at most 10,000 characters.", { hint: 'Put the long part in a file and attach it to a message, with a short summary as the text.' })
  const prefix = path.length ? path.join('.') + ': ' : ''
  return new WorkbusError(400, 'invalid_request', prefix + (issue?.message ?? 'invalid request'))
}

function queryObject(url: URL): Record<string, string | string[]> {
  const out: Record<string, string | string[]> = {}
  for (const [key, value] of url.searchParams) {
    const had = out[key]
    out[key] = had === undefined ? value : Array.isArray(had) ? [...had, value] : [had, value]
  }
  return out
}

async function readInput(request: Request, definition: Route, params: Record<string, string>, url: URL): Promise<unknown> {
  let parsed: unknown = {}
  if (definition.query) {
    const result = definition.query.safeParse(queryObject(url))
    if (!result.success) throw validationFailure(result.error)
    parsed = result.data
  } else if (definition.body) {
    const text = await request.text()
    let body: unknown
    if (text.trim() === '') body = undefined
    else {
      try {
        body = JSON.parse(text)
      } catch {
        throw new WorkbusError(400, 'invalid_request', 'request body is not valid JSON')
      }
    }
    if (body === undefined && definition.optionalBody) body = {}
    const result = definition.body.safeParse(body)
    if (!result.success) throw validationFailure(result.error)
    parsed = result.data
  }
  return { ...(parsed as object), ...params }
}

/** A doorbell on the board's Relay for this region: resolves on a ring, or at the deadline. */
export class Bell {
  private socket: WebSocket | null = null
  private waiters: (() => void)[] = []
  private env: GatewayEnv
  private board: string
  private region: string
  constructor(env: GatewayEnv, board: string, region: string) {
    this.env = env
    this.board = board
    this.region = region
  }
  async open() {
    if (this.socket) return
    const name = 'relay:' + this.board + ':' + this.region
    const relay = this.env.RELAY.getByName(name)
    await relay.named(name)
    const response = await relay.fetch('https://relay/', { headers: { upgrade: 'websocket', 'x-board-name': this.board } })
    const socket = response.webSocket
    if (!socket) throw new Error('relay: no WebSocket')
    socket.accept()
    socket.addEventListener('message', () => {
      for (const wake of this.waiters.splice(0)) wake()
    })
    socket.addEventListener('close', () => {
      this.socket = null
      for (const wake of this.waiters.splice(0)) wake()
    })
    this.socket = socket
  }
  ring(deadline: number): Promise<void> {
    const left = deadline - Date.now()
    if (left <= 0) return Promise.resolve()
    return new Promise((resolve) => {
      const timer = setTimeout(resolve, left)
      this.waiters.push(() => (clearTimeout(timer), resolve()))
    })
  }
  close() {
    try {
      this.socket?.close(1000)
    } catch {}
    this.socket = null
  }
}

const regionOf = (request: Request) => String((request as { cf?: { continent?: string } }).cf?.continent ?? 'xx').toLowerCase()

export type GatewayOptions = { name?: string }

/** The deployment's config, as far as the Gateway needs it: its syncs' providers. */
type Configure = (env: any) => { sync?: Record<string, SyncProvider> }

export function createGateway(configure: Configure = () => ({})) {
  const configs = new WeakMap<object, Record<string, SyncProvider>>()
  const syncsOf = (env: GatewayEnv) => {
    let found = configs.get(env)
    if (!found) configs.set(env, (found = configure(env).sync ?? {}))
    return found
  }
  return async function gateway(request: Request, env: GatewayEnv): Promise<Response> {
    const url = new URL(request.url)
    const oauth = await handleOAuth(request, env as GatewayEnv & import('./oauth.ts').OAuthEnv)
    if (oauth) return oauth
    const origin = (env.BOARD_ORIGIN ?? url.origin).replace(/\/+$/, '')
    if (url.pathname === '/issuer/.well-known/jwks.json') return json(publicJwks(JSON.parse(env.BOARD_ISSUER_KEY) as IssuerKey))
    const mounted = /^\/b\/([^/]+)(\/.*)?$/.exec(url.pathname)
    if (!mounted) return failureResponse({ status: 404, code: 'not_found', message: 'boards live at /b/<name>' })
    const name = decodeURIComponent(mounted[1]!).toLowerCase()
    if (!BOARD_NAME.test(name)) return failureResponse({ status: 400, code: 'invalid_board', message: 'a board name is lowercase letters, digits, - and _, up to 64' })
    const mount: Mount = { name, origin, url: origin + '/b/' + name }
    const ledger = env.LEDGER.getByName(name) as unknown as LedgerStub
    const rest = mounted[2] ?? '/'
    const found = match(request.method, rest)
    if (!found) return failureResponse({ status: 404, code: 'not_found', message: 'no route: ' + request.method + ' ' + url.pathname })
    const { route: definition, params } = found
    try {
      if (definition.name === 'discovery') await (ledger as unknown as { remember(mount: Mount): Promise<void> }).remember(mount)
      if (definition.name === 'discovery') return json({ version: VERSION, url: mount.url, audience: mount.url, team_id: null, project_id: null, sync: [...SYNC_ENTRIES, ...Object.entries(syncsOf(env)).map(([key, provider]) => ({ key, platform: provider.platform }))] })
      if (definition.name === 'webhook') return await webhook(request, env, mount, params.key!, syncsOf(env))
      if (definition.name === 'openapi') {
        // Every method of every path: two routes on one path are two operations under it.
        const paths: Record<string, Record<string, { operationId: string }>> = {}
        for (const entry of ROUTES) (paths[entry.path.replace(/:(\w+)/g, '{$1}')] ??= {})[entry.method.toLowerCase()] = { operationId: entry.name }
        return json({ openapi: '3.1.0', info: { title: 'Workbus', version: VERSION }, paths })
      }
      if (definition.open && GATEWAY[definition.name]) return GATEWAY[definition.name]!(request, env, { mount, caller: null, params, input: undefined, ledger })
      if (request.headers.has('x-board-scope')) throw new WorkbusError(400, 'invalid_scope', 'x-board-scope is x-board-can now: send the same value as x-board-can')
      const profile = parseProfile(request.headers.get('x-board-profile'))
      const narrow = parseNarrow(request.headers.get('x-board-can'))
      const principal = await authenticate(request, {
        origin,
        audience: mount.url,
        issuerKey: JSON.parse(env.BOARD_ISSUER_KEY) as IssuerKey,
        issuers: () => ledger.issuers() as Promise<string[]>,
        ...(env.ACCESS_TEAM && env.ACCESS_AUD ? { access: { team: env.ACCESS_TEAM, aud: env.ACCESS_AUD } } : {}),
      })
      const caller: Caller = { principal, profile, narrow, via: 'http' }
      const input = await readInput(request, definition, params, url)
      if (GATEWAY[definition.name]) return GATEWAY[definition.name]!(request, env, { mount, caller, params, input, ledger })
      if (definition.name === 'typing') return await typingThrough(env, ledger, caller, mount, input as { id: string; status?: string }, syncsOf(env))
      if (definition.name === 'inbox' && Object.hasOwn(syncsOf(env), (input as { key: string }).key)) return await ownInbox(env, ledger, caller, mount, input as { key: string; channel?: string; limit?: number })
      if (definition.name === 'inboxReplay') {
        const key = (input as { key: string }).key
        if (!Object.hasOwn(syncsOf(env), key) || !env.INBOX) return failureResponse({ status: 404, code: 'not_found', message: 'this board has no sync ' + key + ' of its own, so no inbox to replay' })
        const allowed = await ledger.call(caller, 'inboxReplay', input, mount)
        if (!allowed.ok) return failureResponse(allowed.failure)
        return json(await (env.INBOX.getByName(inboxName(mount.name, key)) as any).replay((input as { ids?: string[] }).ids))
      }
      if (definition.name === 'events') {
        if (request.headers.get('last-event-id') && (input as { after?: string }).after === undefined) {
          ;(input as { after?: string }).after = request.headers.get('last-event-id')!.slice(0, 128)
          delete (input as { last?: number }).last
        }
        if ((request.headers.get('accept') ?? '').includes('text/event-stream')) return sse(request, env, ledger, caller, mount, input as Record<string, unknown>)
        return held(request, env, ledger, caller, mount, 'events', input as Record<string, unknown>, Math.min(Number((input as { wait?: number }).wait ?? 0), 300), (value) => ((value as { events: unknown[] }).events.length > 0), (value, asked) => ({ ...asked, after: (value as { cursor: string }).cursor }))
      }
      if (definition.name === 'matches') return held(request, env, ledger, caller, mount, 'matches', input as Record<string, unknown>, Math.min(Number((input as { wait?: number }).wait ?? 0), 25), (value) => ((value as { matches: unknown[] }).matches.length > 0), (_, asked) => asked)
      if (definition.name === 'claimReadyTask') return held(request, env, ledger, caller, mount, 'claimReadyTask', input as Record<string, unknown>, Math.min(Number((input as { wait?: number }).wait ?? 0), 300), (value) => (value as { task: unknown }).task !== null, (_, asked) => asked)
      return answer(definition, await ledger.call(caller, definition.name, input, mount))
    } catch (error) {
      if (error instanceof WorkbusError) {
        const headers: Record<string, string> = error.status === 401 && rest === '/mcp'
          ? { 'www-authenticate': `Bearer resource_metadata=\"${origin}/.well-known/oauth-protected-resource/b/${name}\"` }
          : {}
        return failureResponse(error.toFailure(), headers)
      }
      // failureOf says what the platform's errors mean (an overloaded board is a 503 to retry) and logs the rest.
      return failureResponse(failureOf(error))
    }
  }
}

/**
 * A platform's webhook for one of the board's own syncs: the provider verifies it, the sync's Inbox
 * keeps its events, and the platform hears 200 only once they're durable there.
 */
async function webhook(request: Request, env: GatewayEnv, mount: Mount, key: string, syncs: Record<string, SyncProvider>): Promise<Response> {
  const provider = Object.hasOwn(syncs, key) ? syncs[key] : undefined
  if (!provider) return failureResponse({ status: 404, code: 'no_sync', message: 'this board has no sync ' + key })
  if (!env.INBOX) return failureResponse({ status: 501, code: 'no_inbox', message: 'this deployment binds no INBOX, so it keeps no webhooks' })
  const received = await provider.receive(request, { key })
  if (received.events.length) await env.INBOX.getByName(inboxName(mount.name, key)).push(mount.name, key, mount, received.events)
  return received.response ?? new Response(received.events.length ? 'kept ' + received.events.length + '\n' : 'nothing to keep\n')
}

/** Typing: the Ledger says where the thread syncs (and checks the caller may post there); each sync's courier shows it. */
async function typingThrough(env: GatewayEnv, ledger: LedgerStub, caller: Caller, mount: Mount, input: { id: string; status?: string }, syncs: Record<string, SyncProvider>): Promise<Response> {
  const result = await ledger.call(caller, 'typing', input, mount)
  if (!result.ok) return failureResponse(result.failure)
  const { targets, thread } = result.value as { targets: string[]; thread: string | null }
  if (thread !== null && env.MAILBOX) {
    const byKey = new Map<string, string[]>()
    for (const target of targets) {
      const key = target.slice(0, target.indexOf(':'))
      if (Object.hasOwn(syncs, key)) byKey.set(key, [...(byKey.get(key) ?? []), target])
    }
    await Promise.all([...byKey].map(([key, list]) => (env.MAILBOX!.getByName(mount.name + ':' + courierId(key)) as any).typing(mount.name, key, thread, list, input.status).catch((error: unknown) => console.warn('[workbus] typing through ' + key + ':', error))))
  }
  return json({ targets })
}

/** GET /inbox/<key> for one of the board's own syncs: what its Inbox holds, raw payloads and all, for a caller the Ledger lets read inboxes. */
async function ownInbox(env: GatewayEnv, ledger: LedgerStub, caller: Caller, mount: Mount, input: { key: string; channel?: string; limit?: number }): Promise<Response> {
  const allowed = await ledger.call(caller, 'inbox', input, mount)
  if (!allowed.ok) return failureResponse(allowed.failure)
  if (!env.INBOX) return json({ events: [] })
  const rows = await (env.INBOX.getByName(inboxName(mount.name, input.key)) as any).list(input.limit ?? 50, input.channel)
  return json({ events: rows.map((row: { id: string; channel: string; createdAt: string; state: string; attempts: number; error: string | null; event: unknown; raw: unknown }) => ({ id: row.id, channel: row.channel, createdAt: row.createdAt, sync: input.key, state: row.state, attempts: row.attempts, error: row.error, event: row.event, raw: row.raw })) })
}

function answer(definition: Route, result: { ok: true; value: unknown } | { ok: false; failure: Failure }): Response {
  if (!result.ok) return failureResponse(result.failure, result.failure.status === 429 ? { 'retry-after': '1' } : {})
  const status = definition.status === 201 ? 201 : definition.status === 'created' && (result.value as { created?: boolean }).created ? 201 : 200
  return json(result.value, status)
}

/** A method asked with no wait, and again after each ring, until it has something or the wait ends. */
async function held(request: Request, env: GatewayEnv, ledger: LedgerStub, caller: Caller, mount: Mount, method: string, input: Record<string, unknown>, wait: number, found: (value: unknown) => boolean, next: (value: unknown, asked: Record<string, unknown>) => Record<string, unknown>): Promise<Response> {
  const definition = ROUTES.find((entry) => entry.name === method)!
  let asked: Record<string, unknown> = { ...input, wait: 0 }
  let result = await ledger.call(caller, method, asked, mount)
  if (wait <= 0 || !result.ok || found(result.value)) return answer(definition, result)
  const deadline = Date.now() + wait * 1000
  const bell = new Bell(env, mount.name, regionOf(request))
  try {
    await bell.open()
    for (;;) {
      asked = next(result.ok ? result.value : null, asked)
      // A ring that came while the bell opened is caught by asking once more now.
      result = await ledger.call(caller, method, asked, mount)
      if (!result.ok || found(result.value) || Date.now() >= deadline || request.signal.aborted) return answer(definition, result)
      await bell.ring(deadline)
    }
  } finally {
    bell.close()
  }
}

/** GET /events as SSE: written by the Gateway from long-poll pages, the caller checked again each page. */
async function sse(request: Request, env: GatewayEnv, ledger: LedgerStub, caller: Caller, mount: Mount, input: Record<string, unknown>): Promise<Response> {
  const first = await ledger.call(caller, 'events', { ...input, wait: 0 }, mount)
  if (!first.ok) return failureResponse(first.failure)
  const encoder = new TextEncoder()
  const { readable, writable } = new TransformStream<Uint8Array, Uint8Array>()
  const writer = writable.getWriter()
  const write = (text: string) => writer.write(encoder.encode(text))
  const deadline = Date.now() + STREAM_MAX_MS
  const run = async () => {
    const bell = new Bell(env, mount.name, regionOf(request))
    let ping: ReturnType<typeof setInterval> | null = null
    let previous: string | null = null
    try {
      await write(': connected\n\n')
      ping = setInterval(() => void write(': ping\n\n').catch(() => {}), PING_MS)
      await bell.open()
      let page = first.value as { events: { cursor: string }[]; cursor: string }
      let firstPage = true
      for (;;) {
        for (const event of page.events) await write('id: ' + event.cursor + '\nevent: board\ndata: ' + JSON.stringify(event) + '\n\n')
        const lastSent = page.events.at(-1)?.cursor ?? null
        if ((page.events.length === 0 && (firstPage || page.cursor !== previous)) || (lastSent !== null && page.cursor !== lastSent)) await write('id: ' + page.cursor + '\n\n')
        previous = page.cursor
        firstPage = false
        if (Date.now() >= deadline || request.signal.aborted) break
        const { last: _last, ...rest } = input
        let result = await ledger.call(caller, 'events', { ...rest, after: page.cursor, wait: 0 }, mount)
        if (result.ok && (result.value as { events: unknown[] }).events.length === 0) {
          await bell.ring(deadline)
          result = await ledger.call(caller, 'events', { ...rest, after: page.cursor, wait: 0 }, mount)
        }
        if (!result.ok) break
        page = result.value as typeof page
      }
    } catch {
      // The client went away.
    } finally {
      if (ping) clearInterval(ping)
      bell.close()
      await writer.close().catch(() => {})
    }
  }
  void run()
  return new Response(readable, { headers: { 'content-type': 'text/event-stream', 'cache-control': 'no-cache, no-transform', connection: 'keep-alive' } })
}

export type { Principal }