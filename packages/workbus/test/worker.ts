// The Worker the suite runs: the deployment's Gateway, with a Ledger whose watchers deliver to URLs a
// test answers (test/sink.ts), one watcher that a test deploys partway through, and a sync of its
// own (test/sync-provider.ts) under the key "test".
import { defineWorkbus } from '../src/index.ts'
import './sink.ts'
import type { GatewayEnv } from '../src/gateway/gateway.ts'
import { OAuthStore } from '../src/gateway/oauth.ts'
import type { WatchConfig } from '../src/ledger/ledger.ts'
import { testProvider } from './sync-provider.ts'

/** Watchers deployed after a board was already in use: a test adds one, then restarts the Ledger. */
export const lateWatchers: Record<string, WatchConfig> = {}

const provider = testProvider()

export { OAuthStore }
export const { Ledger, Relay, Mailbox, Inbox, gateway } = defineWorkbus(() => ({
  watch: {
    everything: { tail: '', sink: { kind: 'url', url: 'https://sink.test/everything' } },
    flaky: { tail: 'flaky', sink: { kind: 'url', url: 'https://sink.test/flaky' } },
    // What reaches ada (design/follows.md): follows.test.ts.
    'for-ada': { tail: '--for @ada', sink: { kind: 'url', url: 'https://sink.test/for-ada' } },
    ...lateWatchers,
  },
  sync: { test: provider },
}))

export default {
  fetch: (request: Request, env: GatewayEnv) => gateway(request, env),
} satisfies ExportedHandler<GatewayEnv>