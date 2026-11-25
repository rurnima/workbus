// The workerd suite: tests run inside workerd, against the real Ledger, Relay, and Mailbox Durable
// Objects on real SQLite storage, with the Gateway as the main Worker's fetch (SELF). The board's
// issuer key is made fresh for each run and handed to the Worker as its BOARD_ISSUER_KEY binding.
import { cloudflareTest } from '@cloudflare/vitest-plugin'
import { exportJWK, generateKeyPair } from 'jose'
import { defineConfig } from 'vitest/config'

export default defineConfig(async () => {
  const { privateKey } = await generateKeyPair('ES256', { extractable: true })
  const issuerKey = { ...(await exportJWK(privateKey)), kid: 'test-' + Date.now().toString(36), alg: 'ES256' }
  return {
    plugins: [
      cloudflareTest({
        main: './test/worker.ts',
        wrangler: { configPath: './wrangler.jsonc' },
        miniflare: { bindings: { ARCHIVE: 'off', BOARD_ISSUER_KEY: JSON.stringify(issuerKey), OAUTH_OWNER_PASSWORD: 'workbus-test-only-owner-password-2026' } },
      }),
    ],
    test: { include: ['test/**/*.test.ts'], testTimeout: 30_000 },
  }
})