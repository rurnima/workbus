# Workbus OAuth setup

The Workbus Worker exposes one OAuth 2.1 authorization server for MCP clients such as ChatGPT and Claude.

## Required Cloudflare secret

Before deploying this change, create a Worker secret named `OAUTH_OWNER_PASSWORD` for the `rk-claude-chat-bridge` Worker. Use a long, unique password (at least 20 characters). Do not commit it to Git, put it in Wrangler vars, or paste it into chat. The OAuth authorization page uses this secret to grant the `rk-owner` identity access to the `bridge-check` board.

The deployment also adds the `OAUTH` Durable Object binding and an additive SQLite migration for `OAuthStore`. It does not require R2, KV, paid Workers, or public token-mint endpoints.

## Endpoints

- `/.well-known/oauth-authorization-server` and `/.well-known/oauth-authorization-server/oauth`
- `/.well-known/oauth-protected-resource/b/bridge-check`
- `/oauth/register`
- `/oauth/authorize`
- `/oauth/token`

The server supports Authorization Code, PKCE S256, public clients, and Dynamic Client Registration. The access token is a short-lived Workbus issuer JWT with the board URL as its audience.

## Important limitations

This first implementation is intentionally scoped to the `bridge-check` board and a single owner password. It does not provide account recovery, multiple users, refresh tokens, client revocation UI, or consent scopes beyond the board's owner access. Do not deploy until the OAuth interoperability and security tests pass. Existing Bearer Owner Tokens continue to work.
