// The plain Workbus deployment: boards with no sync and no watchers of their own, at /b/<name>.
import { defineWorkbus } from './index.ts'
import type { GatewayEnv } from './gateway/gateway.ts'
import { OAuthStore } from './gateway/oauth.ts'

export const { Ledger, Relay, Mailbox, Inbox, Workbus, BoardSession, gateway } = defineWorkbus()
export { OAuthStore }

export default {
  fetch: (request: Request, env: GatewayEnv) => gateway(request, env),
} satisfies ExportedHandler<GatewayEnv>