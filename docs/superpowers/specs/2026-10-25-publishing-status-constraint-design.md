# Publishing-status constraint: design

Issue: arkavo-org/opentdf-platform#59 (as amended by the owner decisions of
2026-10-22). Read contract: arkavo-org/arkavo-rs#93, owner-approved comment of
2026-10-25.

## Intent

The tdf-iroh-s3 node asks the platform, through arks's AuthZEN facade,
whether a subject may publish. When a moderator suspends a creator, that
answer must turn to "no" within seconds, with the token the creator already
holds. There is one suspension authority: arks's moderation store. The
platform reads the status from it on the decision path. Identity is not
consulted, and the node keeps no suspension records of its own.

## Goals

- A new composite-resolver constraint, `constraints.publishing_status`. It
  withholds a subject's `https://patreon.arkavo.com/attr/arkavo-creator`
  grants while arks reports the subject as suspended, or while arks can't
  give a clear answer.
- Every other grant stays untouched, and so does every subject without an
  `arkavo-creator` grant.
- Prod config and policy that make the publish entitlement grantable through
  the node's claims chain.

## Non-goals

- The arks side: the suspension record, the read and lift routes, and the
  `MODERATION_SUSPENSION_READER_IDS` allowlist. All of it is arkavo-rs#93.
- Re-checking sealed `arkavo_evidence`. `openSealed`
  (`service/entityresolution/composite/v2/composite.go`) reopens evidence
  without running constraints, so evidence sealed for a token keeps its
  `arkavo-creator` grant until that evidence expires (at most the token's
  `exp`). The node's claims-mode path is unaffected, because it resolves
  unsealed claims on every call. Document this limit; do not fix it here.
- Recording the catalog node's client ID in `claims_chain_peps`. That is the
  #59 pre-check, which is measured in production and isn't known yet. Leave
  the existing placeholder comment in place.
- Turning the constraint on in production.

## Anti-goals (failure even if it "works")

- **Fail open.** Any answer other than HTTP 200 with a JSON boolean
  `suspended` must count as suspended. That includes 404, 3xx, a timeout, a
  TLS failure, a non-JSON body, a missing or non-boolean field, and a
  `subject` that doesn't match. 404 in particular must never mean "not
  suspended": arks answers 404 when the route isn't mounted.
- **Calls for viewers.** A subject with no `arkavo-creator` grant must make no
  call. Catalog viewers must never depend on arks's moderation store.
- **Over-withholding.** Withholding anything other than the `arkavo-creator`
  grants on a suspension or an outage.
- **Leaking secrets.** The client secret or the service CWT appearing in a
  log, an error string or a `%v`/`%+v`/`%#v` rendering (see
  `agentstatus.Secret`).
- **Caching a denial.** A suspended or failed answer is never cached.

## How it behaves (decided)

### Where it runs

`resolveSubject` runs it after `capGrants`, on the final grant list. If no
grant's FQN belongs to the `https://patreon.arkavo.com/attr/arkavo-creator`
attribute (any value, compared lowercased as the merged keys are), it returns
the grants unchanged and makes no call. Otherwise it asks arks about the
subject's `sub`. On "not suspended" the grants stay. On anything else it drops
every `arkavo-creator` grant and logs why.

- **Subject identifier:** the subject's `sub` claim exactly as the token
  carries it, never `arkavo_account_id`. A subject that has the grant but no
  `sub` string is withheld (fail closed), with no call.
- **The chain carries `sub`.** arks's facade (`pe_claims` in arkavo-rs
  `src/modules/authzen/translate.rs`) always sets the claims entity's `sub`
  to the AuthZEN `subject.id`. That is the person's CWT `sub` with an
  `arkavo:` prefix. arks keys suspensions on the `sub` with any `arkavo:`
  prefix removed, so the prefixed form (from a PEP chain) and the bare form
  (from a verified token) both find the same record (arkavo-rs#93,
  PR #124). Send `sub` as the subject carries it, unchanged; the response
  echoes it as sent.
- **Applies to every subject kind** that holds the grant. In practice only
  persons do. A device's or agent's `sub` will simply not be suspended unless
  arks says so.

### The arks read (contract: arkavo-rs#93)

- **Request:** `GET {base_url}/moderation/v1/suspensions/{subject}`.
  `{subject}` is percent-encoded as one path segment
  (`url.PathEscape`; a `/` in a `sub` must not create a new segment).
- **Auth:** `Authorization: Bearer <service CWT>`. This is not
  `X-Auth-Token`, which is what authnz-rs uses. The CWT comes from
  `client_credentials` at the identity token endpoint, minted the way
  `agentstatus` mints its token today. The request is a bare
  `grant_type=client_credentials` with HTTP Basic client auth and no
  audience or scope. identity puts the client ID in `aud`, which is what
  arks requires; the catalog node's service tokens already pass the same
  check in arks's facade. The minting details: `{identity_url}/oauth/token`, cached until shortly before it
  expires, capped at one hour, and re-minted once after a 401.
- **"Not suspended"** is exactly: 200, a JSON body, `suspended == false`, and
  `subject` equal to the requested `sub`.
- **"Suspended"** is 200 with `suspended == true`. `since` and `reportId` are
  logged when present.
- **Everything else** fails closed. 401 after one re-mint, 403 (not on the
  allowlist), a token-endpoint 401/403 and a missing configuration each get
  their own log reason, because each one is a misconfiguration an operator
  must fix. Everything else is logged as "unreachable".
- **Redirects are not followed**, as in `agentstatus`: Go would forward the
  `Authorization` header to the redirect target.
- **Response bodies are capped**, as in `agentstatus` (64 KiB).

### Caching

Only "not suspended" is cached, keyed by `sub`, for 5 s (configurable,
capped at 5 s). A suspension therefore takes effect on the next decision
after an allowed answer's lease ends: within about 5 s. A suspended or
failed answer is never cached.

### Timeouts

A per-call timeout defaults to 3 s and is capped at 5 s. One check is bounded
at twice that (a token call plus a status call), and also by the caller's
context. The composite's source `deadline` (300 ms) does not apply: the
constraint runs after the sources.

### The connection: "loopback"

arks and the platform share the production host. arks serves TLS only, on
`0.0.0.0:443`, with the `platform.arkavo.net` certificate. The client
therefore uses:

- `url`: base URL, `https://platform.arkavo.net` in prod. TLS verification,
  SNI and the Host header all use this URL's host.
- `dial_address`: optional `host:port`. When set, every connection to the
  base URL's host dials this address instead (prod: `127.0.0.1:443`).
- `dial_socket`: optional Unix socket path. When set, every connection dials
  the socket instead. It is mutually exclusive with `dial_address`, and it is
  for a future arks socket listener. It is supported and tested now, but
  unused in prod. Over a socket the request is still HTTPS to `url`, or plain
  HTTP if `url` is `http://`. The service CWT is still sent either way.

The identity token endpoint is not affected by the dial override. It is a
separate host and uses normal dialing.

### Config

`services.entityresolution.constraints.publishing_status`:

```yaml
publishing_status:
  url: https://platform.arkavo.net          # arks base URL
  dial_address: 127.0.0.1:443               # optional; or dial_socket: /path
  identity_url: https://identity.arkavo.net # client_credentials token endpoint base
  client_id: opentdf-platform
  client_secret: ""                         # supplied by the deployment as a secret
  timeout: 3s                               # optional, ≤ 5s
  cache_ttl: 5s                             # optional, ≤ 5s
```

- **Unset (every field empty):** the constraint is off and no grant is
  withheld for suspension. This is today's behavior and the default.
- **Partly set:** a startup error, as with `agentstatus.Config.Enabled`.
- **Validation:** the URLs reject userinfo, so the URL carries no
  credentials, and errors don't echo the URL. `dial_address` and
  `dial_socket` together is an error.
- **Plain `http://`** is allowed only when `dial_socket` is set or the
  URL's host is loopback, as `agentstatus` already requires. A typo can then
  never send the service CWT across the network in cleartext.
- **`dial_address`** is not restricted to loopback. TLS still verifies the
  URL's host name, so a wrong address fails closed rather than leaking.
  (My call.)
- **Logging:** the config's `LogValue` redacts the secret, and the composite
  config's `LogValue` gains `publishing_status_url`.

### Logging

Each withholding logs at WARN with `sub`, the reason, the dropped FQNs, and
`since`/`reportId` when suspended. Misconfiguration reasons log at ERROR, as
`LogAgentDenial` does for its configuration reasons. "Not suspended" logs at
DEBUG.

### Prod config and policy (in this change)

- **`examples/config/policy.patreon.yaml`:** define the attribute
  `arkavo-creator` in the `patreon.arkavo.com` namespace, with rule `anyOf`
  and value `publish`. Add no subject mapping: composite grants are direct
  entitlements, and `campaign` has no subject mapping either.
- **`examples/config/opentdf-patreon-prod.yaml`:**
  - on source `identity-core`, set `pep_assertable: true`, so the node's
    claims chain can carry the publish grant. Leave its `actions` at the
    default `read`: the node asks for action `read` on resource type
    `publisher`, and the attribute value carries the meaning (#59).
    `capability.admits` also needs `iss` and `arkavo_entitlements` in the
    claims entity. arks's `pe_claims` forwards both; `arkavo_entitlements`
    is filtered to the Patreon definitions plus the publish entitlement
    (arkavo-rs#95);
  - add a commented-out `publishing_status` block with the prod values above.
    Its comment must say not to enable it until arks serves
    `GET /moderation/v1/suspensions/{subject}` with moderation on (arkavo-rs#93):
    it fails closed, so enabling it early refuses publishing for every creator.
- **`examples/config/opentdf-patreon-local-test.yaml`:** mirror the
  `pep_assertable` change if the local test relies on it.

## Tests (required)

- A suspended account loses every `arkavo-creator` grant and keeps all
  others.
- An arks outage (connection refused, timeout, 503) withholds only
  `arkavo-creator`.
- Fail-closed cases: 404, 3xx, non-JSON, missing `suspended`, string
  `"false"`, mismatched `subject`, a 401 that persists after the re-mint, a
  403, and a token-endpoint 401.
- A subject without the grant makes no call (zero requests at the test
  server).
- "Not suspended" is cached for ≤ 5 s and re-asked after. "Suspended" and
  failures are never cached.
- `sub` with `/`, `%`, spaces and non-ASCII is percent-encoded as a single
  segment.
- `dial_address` override: TLS to a test server presented as a different
  host name, with SNI and Host kept. Also `dial_socket` to a Unix-socket
  listener.
- The client secret and the service CWT never appear in logs or in
  `fmt`/`slog` renderings of the config or the client.
- Constraint unset: no behavior change from `main`, and existing tests pass.

## Rollout order (record in the PR)

1. arks ships the route with moderation on, and adds `opentdf-platform` to
   `MODERATION_SUSPENSION_READER_IDS` (arkavo-rs#93).
2. The owner registers the `opentdf-platform` client at identity.arkavo.net.
3. The platform deploys this change with the constraint off.
4. The owner enables `publishing_status` in the prod config and checks #59's
   acceptance: allowed, then denied within about 5 s of a suspend, and a
   catalog viewer causes no call.

## Overlap with PR #61

PR #61 (`fix/chain-device-constraints`) rewrites the composite's
`resolveSubject`, `constraints.go`, `register.go` and `evidence.go`, which is
where this constraint lands. This branch starts from `main`. Whichever PR
merges second rebases onto the other. Keep the new constraint
a self-contained function called from `resolveSubject`, so the rebase is
confined to the call site and to `register.go`.

## Left to the builder

- **Shared token minting.** Whether to extract `agentstatus`'s
  service-token minting (cache, refresh slack, one re-mint after a 401, no
  redirects) into a shared internal package, or to wrap it. My call: extract
  it rather than copy it, with no behavior change for `agentstatus`, because
  two hand-maintained copies of secret-handling code will drift. The
  difference in header (`X-Auth-Token` versus `Authorization: Bearer`)
  belongs to each caller.
- **Package name and layout.** For example,
  `service/internal/publishingstatus`.
- **Exact log message wording.**
