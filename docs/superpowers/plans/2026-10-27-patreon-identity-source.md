# Patreon entitlements from identity /entities: implementation plan

**Goal:** a composite ERS source that reads a person's Patreon campaign and campaign-tier grants (and the `.patreon` properties) from identity's `GET /entities/arkavo:<uuid>` instead of from the token, rolled out in shadow first.

**Decisions (owner, 2026-10-27, relayed by the identity session; confirmed in this session with "go"):**
- Order: add the source while tokens still carry the data, compare in production (log only), switch, and only later drop the data from tokens (that also waits on arkavo-ios).
- Stale-on-error: when identity is unavailable, serve the last answer for the account, up to `stale_max_age` (default and cap 3600 s, the longest a person token lives).

**Identity contract (authnz-rs#127, 0.26.0):** `GET /entities/arkavo:<uuid>` with a service CWT in `X-Auth-Token`. Returns 200 `{id, category, npe_type, claims{sub, arkavo_account_id, username, did, arkavo_roles, arkavo_entitlements, arkavo_patreon?}}`, where the claims are exactly what a freshly minted token would carry. 404 means an unknown account. 503 `{"error":"patreon_unavailable"}` means there is a link but no snapshot. The gate is ENTITY_CLIENT_IDS; the client is `opentdf-platform`. On a cold lookup identity waits up to 3 s.

## Design

- **One owner per definition**, so the new source replaces `patreon-token` (it owns the same two definitions). It has `serve: token | identity`:
  - `token` (default, shadow): grants from the token exactly as `patreon-token` does, and compares with identity in the background (`context.WithoutCancel`, its own timeout, at most once per `cache_ttl` per account). The comparison logs the FQN-set difference of the two owned definitions at INFO, account id only.
  - `identity`: grants from the lookup. Unavailable with no usable stale answer gives `OutcomeUnavailable`, so those grants are withheld.
- **Grant derivation is delegated** to `patreon.NewTokenSource(cfg).Resolve` over the fetched claims, so there is no new parsing and the output has the same shape.
- **Persons only;** an empty `AccountID` is not applicable.
- **The client config is a top-level block** `services.entityresolution.identity_entities` (not inside `sources[]`, which env vars cannot reach), so `OPENTDF_SERVICES_ENTITYRESOLUTION_IDENTITY_ENTITIES_CLIENT_SECRET` works with `client_secret: ""` present. Fields: `url`, `client_id`, `client_secret`, `timeout` (default 4 s), `cache_ttl` (default 60 s, max 60 s), `stale_max_age` (default 3600 s, max 3600 s), `failure_backoff` (default 30 s).
- **Client `service/internal/identityentities`:**
  - Per-account cache of the last good answer; single-flight per account.
  - Failure memo: during `failure_backoff`, serve a stale answer or report unavailable immediately.
  - Response handling: a mismatched `arkavo_account_id`, a 401/403 (WARN, misconfiguration), and 5xx/503/timeouts are unavailable. 404, and a 200 without `arkavo_patreon`, are fresh negatives.
- **Per-source `deadline`** override in `SourceConfig` (default: the global one), needed for `serve: identity` at about 4 s.

## Files
- `service/internal/identityentities/{config,client}.go` + tests
- `service/entityresolution/composite/v2/{config,register,composite}.go`, new `patreon_identity.go` + tests, decision test
- `examples/config/opentdf-patreon-prod.yaml`, `docs/Configuring.md`
