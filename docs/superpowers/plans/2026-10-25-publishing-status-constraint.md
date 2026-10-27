# Publishing-status Constraint Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** The composite entity resolver withholds a subject's
`arkavo-creator` grants while arks reports the subject suspended or can't
answer. Prod config grants publish only for the `publish` action.

**Architecture:** The service-token minting is extracted from `agentstatus`
into a shared `internal/servicetoken`. A new `internal/publishingstatus`
client reads arks's `GET /moderation/v1/suspensions/{subject}` over a dialer
pinned to loopback or to a Unix socket. It fails closed, and caches only
"not suspended". The composite's `resolveSubject` calls it after `capGrants`,
and only when an `arkavo-creator` grant is present.

**Tech Stack:** Go (service module), `net/http`, `httptest`, testify, the
composite v2 resolver, the v2 JIT PDP over `filestore`.

**Spec:** `docs/superpowers/specs/2026-10-25-publishing-status-constraint-design.md`

## Global Constraints

- Fail closed: anything but HTTP 200 + JSON boolean `suspended` + `subject` equal to the sent value withholds.
- 404 is never "not suspended". Redirects are never followed. Bodies are read through a 64 KiB limit.
- Header `Authorization: Bearer <service CWT>` (not `X-Auth-Token`). Path segment `url.PathEscape(sub)`. `sub` is sent exactly as carried; never `arkavo_account_id`.
- Cache only "not suspended", keyed by `sub`. `cache_ttl` defaults to 5s, max 5s. Per-call `timeout` defaults to 3s, max 5s. One check is bounded at 2×timeout and by the caller's context.
- Plain `http://` only when `dial_socket` is set or the URL's host is loopback. `dial_address` and `dial_socket` are mutually exclusive. URLs reject userinfo, query and fragment, and errors never echo a URL.
- Client secret and service CWT never in logs, errors, or `fmt`/`slog` renderings.
- The constraint is off when every `publishing_status` field is empty. A partial block is a startup error.
- Attribute definition matched: `https://patreon.arkavo.com/attr/arkavo-creator` (by parsed definition, so `arkavo-creator-pro` is not matched).
- No behavior change for `agentstatus`.
- Before each commit: `gofumpt -w` on changed files, `golangci-lint run` on changed packages (0 issues), `go test` on changed packages. Commits use Conventional Commits, `git commit -s`, ending with `Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>`.
- All commands run from `service/` in the worktree `/Users/paul/Projects/arkavo/opentdf-platform-publishing-status`.

## Review Focus

1. A grant on another value of the definition (`.../arkavo-creator/value/admin`, or mixed case) is withheld too. `.../arkavo-creator-pro/value/x` is untouched. Test in Task 4.
2. The caller's context is already cancelled or nearly expired: withhold, and resolution still returns the other grants without an error. Test in Task 4.
3. arks answers 302 to another host: not followed, and no `Authorization` header reaches the redirect target. Test in Task 3.
4. arks answers 200 `{"suspended":false,"subject":"<other sub>"}`: withheld (a cross-wired answer). Test in Task 3.
5. Constraint unset, subject holds `arkavo-creator`: the grant survives unchanged (today's prod behavior). Test in Task 4.

---

### Task 1: Extract service-token minting into `internal/servicetoken`

**Files:**
- Create: `service/internal/servicetoken/servicetoken.go`, `service/internal/servicetoken/servicetoken_test.go`
- Modify: `service/internal/agentstatus/client.go` (`serviceToken`, the token fields and `errCredentialsRejected` move out), `service/internal/agentstatus/config.go` (`Secret` becomes an alias)
- Test: existing `service/internal/agentstatus/*_test.go` must pass unchanged, except tests that reached into the moved token fields, which are adapted without changing what they assert

**Interfaces:**
- Produces:
  - `type Secret string`, with the `String`, `LogValue`, `Format` and `MarshalJSON` behavior moved verbatim from `agentstatus.Secret`;
  - `type Config struct { TokenURL string; ClientID string; ClientSecret Secret }`, where `TokenURL` is the full token endpoint;
  - `var ErrCredentialsRejected error`;
  - `func New(cfg Config, hc *http.Client) *Minter`;
  - `func (m *Minter) Token(ctx context.Context, fresh bool) (Secret, error)`, with a bare `grant_type=client_credentials` form, HTTP Basic auth, a cache until `issued + lifetime − 1 min`, a lifetime of `expires_in` capped at 1 h, and a 401/403 from the endpoint wrapped as `ErrCredentialsRejected`;
  - `Format`/`LogValue` on `*Minter` that render only the token URL and client ID.
- `agentstatus`: `type Secret = servicetoken.Secret`; `errCredentialsRejected` is replaced by `servicetoken.ErrCredentialsRejected`; the token URL is `endpoint(tokenPath)`.

- [ ] **Step 1: Write failing tests in `servicetoken_test.go`**
  - `TestToken_CachedUntilRefreshSlack`: `expires_in: 600`. Two calls → 1 request. Advance the clock to 540 s → 2 requests.
  - `TestToken_FreshForcesMint`: `Token(ctx, true)` mints even with a cached token.
  - `TestToken_CredentialsRejected`: the endpoint answers 401, then 403 → `errors.Is(err, ErrCredentialsRejected)`.
  - `TestToken_LifetimeCappedAtHour`: `expires_in: 999999` → re-minted after 59 min.
  - `TestToken_NegativeExpiresIn`: `expires_in: -5` → treated as 1 h.
  - `TestToken_EmptyAccessToken`: → error.
  - `TestToken_FormAndBasicAuth`: the server asserts `grant_type=client_credentials`, no `audience`/`scope`, and Basic `id:secret`.
  - `TestMinter_RenderingHidesSecret`: `fmt.Sprintf("%v %+v %#v")` and a slog JSON handler output contain neither the secret nor the token.
- [ ] **Step 2: Run** `go test ./internal/servicetoken/...` → FAIL (package missing).
- [ ] **Step 3: Implement** `servicetoken.go` by moving the code from `agentstatus/client.go` (`serviceToken`, `tokenResponse`, the expiry math) and the `Secret` methods from `agentstatus/config.go`. Use an unexported `now func() time.Time` for tests.
- [ ] **Step 4: Point `agentstatus` at it.** `Client` holds a `*servicetoken.Minter`, built in `New` with the same `http.Client`. `fetchFailureReason` uses `servicetoken.ErrCredentialsRejected`.
- [ ] **Step 5: Run** `go test ./internal/servicetoken/... ./internal/agentstatus/... ./entityresolution/...` → PASS.
- [ ] **Step 6: Lint, format and commit:** `refactor(ers): share service-token minting (servicetoken)`.

### Task 2: `publishingstatus.Config` and its dialer

**Files:**
- Create: `service/internal/publishingstatus/config.go`, `service/internal/publishingstatus/config_test.go`

**Interfaces:**
- Consumes: `servicetoken.Secret`.
- Produces:
  ```go
  type Config struct {
      URL          string              `mapstructure:"url" json:"url"`
      DialAddress  string              `mapstructure:"dial_address" json:"dial_address"`
      DialSocket   string              `mapstructure:"dial_socket" json:"dial_socket"`
      IdentityURL  string              `mapstructure:"identity_url" json:"identity_url"`
      ClientID     string              `mapstructure:"client_id" json:"client_id"`
      ClientSecret servicetoken.Secret `mapstructure:"client_secret" json:"client_secret"`
      Timeout      time.Duration       `mapstructure:"timeout" json:"timeout"`
      CacheTTL     time.Duration       `mapstructure:"cache_ttl" json:"cache_ttl"`
  }
  func (c Config) Enabled() bool      // any field non-zero
  func (c Config) validate() error
  func (c Config) LogValue() slog.Value // no secret
  func (c Config) transport() *http.Transport // DialContext pinned per dial_address / dial_socket
  ```

- [ ] **Step 1: Write failing tests** (table-driven `TestValidate`):
  - valid prod block (`https://platform.arkavo.net`, `127.0.0.1:443`, `https://identity.arkavo.net`, id, secret) → ok;
  - `http://platform.arkavo.net` with no socket → error;
  - `http://platform.arkavo.net` + `dial_socket` → ok;
  - `http://127.0.0.1:9000` → ok;
  - `dial_address` + `dial_socket` → error;
  - userinfo, query or fragment in `url` or `identity_url` → error whose text doesn't contain the URL;
  - missing `client_id`, `client_secret`, `url` or `identity_url` → error;
  - `timeout: 6s` → error; `cache_ttl: 6s` → error.

  Also:
  - `TestEnabled`: empty → false; `client_id` only → true.
  - `TestConfigRenderingHidesSecret`: as in Task 1.
  - `TestTransport_DialAddress`: an `httptest.NewTLSServer`, with `url` `https://example.test` and `dial_address` = the server's address. A client trusting the server cert, using `ServerName` `example.test`, gets 200, and the handler sees `r.Host == "example.test"`. Generate the test cert for `example.test`.
  - `TestTransport_DialSocket`: an `http.Server` on a `net.Listen("unix", t.TempDir()+"/s")`, `url` `http://platform.test`, → 200.
- [ ] **Step 2: Run** `go test ./internal/publishingstatus/...` → FAIL.
- [ ] **Step 3: Implement.** `transport()` clones `http.DefaultTransport` and replaces `DialContext`: it dials the socket (`"unix"`) or `DialAddress` for every address. TLS `ServerName` stays derived from the request URL. The identity token client does **not** use this transport.
- [ ] **Step 4: Run** → PASS.
- [ ] **Step 5: Lint, format and commit:** `feat(ers): publishing_status config with loopback and socket dialing`.

### Task 3: `publishingstatus.Client`

**Files:**
- Create: `service/internal/publishingstatus/client.go`, `service/internal/publishingstatus/client_test.go`

**Interfaces:**
- Consumes: `Config` (Task 2), `servicetoken.New`/`Token`/`ErrCredentialsRejected` (Task 1). The token URL is `strings.TrimRight(IdentityURL, "/") + "/oauth/token"`.
- Produces:
  ```go
  type Checker interface { Check(ctx context.Context, sub string) error } // nil == not suspended
  type DenialError struct { Reason, Subject, Since, ReportID string; Cause error }
  func (*DenialError) Error() string
  const (
      ReasonSuspended           = "suspended by moderation"
      ReasonMissingSubject      = "subject has no sub"
      ReasonUnreachable         = "suspension service unreachable"
      ReasonMalformedAnswer     = "suspension service answer is not a clear not-suspended"
      ReasonForbidden           = "misconfiguration: this platform's client is not in arks MODERATION_SUSPENSION_READER_IDS (403)"
      ReasonUnauthorized        = "misconfiguration: arks rejected the service CWT after a fresh mint (401)"
      ReasonCredentialsRejected = "misconfiguration: identity rejected publishing_status.client_id/client_secret at /oauth/token"
  )
  func New(cfg Config) (*Client, error) // validates; http.Client{Transport: cfg.transport(), Timeout, CheckRedirect: ErrUseLastResponse}
  func (c *Client) Check(ctx context.Context, sub string) error
  // Format/LogValue: url and client_id only
  ```
- Response body type: `{ "subject": string, "suspended": *bool, "since": string, "reportId": string }`. A nil `suspended` → `ReasonMalformedAnswer`.

- [ ] **Step 1: Write failing tests.** Use a fake identity (`httptest`) and a fake arks (`httptest`, plain `http://127.0.0.1`), plus a counting handler.
  - `TestCheck_NotSuspended`: 200 `{"subject":S,"suspended":false}` → nil. The request carries `Authorization: Bearer <token>`, path `/moderation/v1/suspensions/` + `url.PathEscape(S)`, and `Accept: application/json`.
  - `TestCheck_Suspended`: 200 `{"subject":S,"suspended":true,"since":"2026-10-25T00:00:00Z","reportId":"r1"}` → `*DenialError{Reason: ReasonSuspended, Since, ReportID}`.
  - `TestCheck_FailClosed` (table): 404, 400, 503, 500, 302 (`Location` to a second server that records any request → zero requests), body `not json`, `{}`, `{"suspended":"false","subject":S}`, `{"suspended":false,"subject":"other"}` (Review Focus 4), and a 70 KiB body with leading whitespace → each a `*DenialError` with a reason other than `ReasonSuspended`.
  - `TestCheck_Timeout`: the handler sleeps past `timeout: 100ms` → `ReasonUnreachable` within 2×timeout + slack.
  - `TestCheck_401RemintsOnce`: first 401, then 200 not-suspended → nil, with 2 token mints. Always 401 → `ReasonUnauthorized`, with exactly 2 arks requests.
  - `TestCheck_403`: → `ReasonForbidden`. `TestCheck_TokenRejected`: identity 401 → `ReasonCredentialsRejected`, with no arks request.
  - `TestCheck_EmptySub`: → `ReasonMissingSubject`, with no requests.
  - `TestCheck_SubEncoding`: subs `arkavo:abc`, `a/b`, `a%2Fb`, `a b`, `ü` → the handler's `r.URL.RawPath` (or `EscapedPath()`) is exactly `/moderation/v1/suspensions/` + `url.PathEscape(sub)`, and the echoed `subject` matches.
  - `TestCheck_CachesOnlyNotSuspended`: not-suspended twice within the TTL → 1 request; after `now` advances past `cache_ttl` → 2 requests. Suspended twice → 2 requests. 503 twice → 2 requests.
  - `TestCheck_CacheTTLDefaultAndCap`: an unset `cache_ttl` → 5 s.
  - `TestCheck_ContextCancelled`: an already-cancelled ctx → `*DenialError` (not a panic, and not nil).
  - `TestClient_RenderingHidesSecret`.
- [ ] **Step 2: Run** `go test ./internal/publishingstatus/...` → FAIL.
- [ ] **Step 3: Implement** `Check`. Bound it with `context.WithTimeout(ctx, 2*timeout)`. Check the cache, then fetch; on a 401, `Token(ctx, true)` and fetch once more. Decode through `io.LimitReader(body, 64<<10)`. Cache only when `*suspended == false && subject == sub`. Return `*DenialError` through explicit nil checks (as `agentstatus.Check` does). Use an unexported `now` for tests.
- [ ] **Step 4: Run** → PASS (also with `-race`).
- [ ] **Step 5: Lint, format and commit:** `feat(ers): publishingstatus client for arks suspension reads`.

### Task 4: The composite constraint

**Files:**
- Create: `service/logger/audit/entitlementWithheld.go`, `service/logger/audit/entitlementWithheld_test.go`
- Modify: `service/logger/audit/logger.go` (non-panicking transaction check), `service/entityresolution/composite/v2/config.go` (adds `PublishingStatus` to `ConstraintsConfig`, validates it, and logs `publishing_status_url` in `LogValue`), `constraints.go` (new function), `composite.go` (`Service` field; call after `capGrants`), `register.go` (build the client)
- Test: `service/entityresolution/composite/v2/publishing_test.go` (new), `config_test.go`

**Interfaces:**
- Consumes: `publishingstatus.Checker`, `publishingstatus.New`, `*publishingstatus.DenialError`, and the reason constants (Task 3).
- Produces:
  ```go
  // ConstraintsConfig
  PublishingStatus publishingstatus.Config `mapstructure:"publishing_status"`
  // Service
  publishing publishingstatus.Checker // nil == constraint off
  const publishingDefinition = "https://patreon.arkavo.com/attr/arkavo-creator"
  func (s *Service) withholdSuspendedPublishing(ctx context.Context, subj source.Subject, grants []sealedGrant) []sealedGrant
  ```
- Audit (in `service/logger/audit`):
  ```go
  type EntitlementWithheldEventParams struct {
      Constraint, Subject, Reason, Since, ReportID string
      WithheldFQNs []string
  }
  func CreateEntitlementWithheldEvent(ctx context.Context, p EntitlementWithheldEventParams) (*EventObject, error)
  func (a *Logger) EntitlementWithheld(ctx context.Context, p EntitlementWithheldEventParams) // no-op without a transaction
  func HasTransaction(ctx context.Context) bool
  ```
  Event shape: verb `VerbDecision`; object `{ID: sub+"-"+constraint, Type: ObjectTypeEntityObject, Name: "entitlementWithheld-"+constraint}`; action `{Type: ActionTypeRead, Result: ActionResultFailure}`; actor ID = sub; metadata `constraint`, `reason`, `since`, `report_id`, `withheld_fqns`; `ClientInfo.Platform` `entityresolution.composite`; `RequestID`/`UserAgent`/`RequestIP` from `GetAuditDataFromContext`. The `cause` text is never included.
- The composite calls `s.logger.Audit.EntitlementWithheld(...)` on every withholding, after the WARN/ERROR log line.
- `New`'s signature is unchanged. `Register` sets `svc.publishing` after `New`, only from a successful `publishingstatus.New` (a typed nil must not land in the interface). This keeps the rebase with PR #61 to the call site and to `register.go`.
- Behavior:
  - `s.publishing == nil` → grants unchanged.
  - No grant's `source.ParseFQN(g.FQN).DefinitionFQN()` equals `publishingDefinition` → unchanged, no call.
  - Otherwise, call `Check(ctx, sub)` with the claims' `sub` string (an empty one fails closed inside `Check`). Recover a panic into a denial, as `checkStatus` does.
  - On a denial, drop every grant of that definition and log `composite: publishing grants withheld` with `sub`, `reason`, `withheld` (FQNs), `since`, `report_id` and `cause`. Log at ERROR for `ReasonForbidden`, `ReasonUnauthorized`, `ReasonCredentialsRejected` and a panic; WARN otherwise.

- [ ] **Step 1: Write failing tests** in `publishing_test.go`, using a `fakePublishing{err error; calls *int; gotSub *string}` and `newTestService` then `svc.publishing = …`, with `identityCoreSource()` plus `patreonSource()`.
  - `TestPublishing_SuspendedLosesOnlyCreator`: grants `publishValue` + a campaign FQN, checker → `ReasonSuspended` → `grantFQNs` = only the campaign FQN.
  - `TestPublishing_OutageWithholdsOnlyCreator`: `ReasonUnreachable` → the same.
  - `TestPublishing_NoGrantNoCall`: campaign only → calls == 0.
  - `TestPublishing_NotSuspendedKeeps`: nil → both kept, and `gotSub` == the token's `sub`.
  - `TestPublishing_PEPChainSendsPrefixedSub`: a claims entity with `sub: "arkavo:abc"` via `claimsEntity` + `callerContext` → `gotSub == "arkavo:abc"`.
  - `TestPublishing_AllValuesOfDefinition` (Review Focus 1): grants `.../arkavo-creator/value/publish`, `.../arkavo-creator/value/admin`, `.../arkavo-creator-pro/value/x` and the per-creator `https://arkavo.net/attr/creator/value/<uuid>` (opentdf-platform#64; from fake sources owning them) → suspended leaves `arkavo-creator-pro` and the per-creator attribute, both untouched.
  - `TestPublishing_CancelledContext` (Review Focus 2): a real `publishingstatus.Client` against an `httptest` server, with an already-cancelled ctx → the creator grant is withheld, other grants are kept, and there's no error.
  - `TestPublishing_UnsetKeepsGrant` (Review Focus 5): `svc.publishing` nil → `publishValue` is kept.
  - `TestPublishing_PanicWithholds`.
  - `TestPublishing_LogsWithoutSecret`: `bufferLogger`, a denial → the log has `sub`, `reason`, `withheld`, and no client secret.
  - In `entitlementWithheld_test.go`:
    - `TestEntitlementWithheldEvent_Shape`: the fields above, exactly.
    - `TestEntitlementWithheld_NoTransactionNoPanic`: `t.Context()` → no panic, nothing logged.
    - `TestEntitlementWithheld_EmittedOnClose`: with a transaction opened as the interceptor does, closing it logs one `AUDIT` line with verb `decision`, plus `report_id` and `withheld_fqns`.
  - `TestPublishing_AuditEventOnWithhold`: the decision path through `pdpFor` with an audit transaction in ctx, suspended → the audit output holds both the deny decision event and the `entitlementWithheld-publishing_status` event, with the same `request_id`, `reason` = `ReasonSuspended` and `report_id` `r1`.
  - `TestPublishing_NoAuditWhenKept`: not suspended → no `entitlementWithheld` event.
  - In `config_test.go`: a partial `publishing_status` block → a `Validate` error mentioning `constraints.publishing_status`; a full block decodes from YAML (`url`, `dial_address`, `identity_url`, `client_id`, `client_secret`, `timeout`, `cache_ttl`).
- [ ] **Step 2: Run** `go test ./entityresolution/composite/...` → FAIL.
- [ ] **Step 3: Implement** the audit event and `HasTransaction`, the config field and validation (mirroring `AgentStatus`), the `Service` field, `withholdSuspendedPublishing`, the call `ev.Grants = s.withholdSuspendedPublishing(ctx, subj, capGrants(...))`, and the `Register` wiring.
- [ ] **Step 4: Run** `go test ./entityresolution/... ./internal/...` → PASS.
- [ ] **Step 5: Lint, format and commit:** `feat(ers): constraints.publishing_status withholds arkavo-creator for suspended creators (#59)`.

### Task 5: Policy, prod config and the end-to-end `publish` decision

**Files:**
- Modify: `examples/config/policy.patreon.yaml` (attribute `arkavo-creator`, rule `anyOf`, value `publish`, in the `patreon.arkavo.com` namespace, with no subject mapping), `examples/config/opentdf-patreon-prod.yaml` (`identity-core`: `pep_assertable: true`, `actions: [publish]`; `evidence.claims_chain_peps: ["client:catalog-node"]`, replacing `[]` and keeping the comment's never-an-account-UUID warning; a commented-out `publishing_status` block), `examples/config/opentdf-patreon-local-test.yaml` (mirror `pep_assertable` and `actions`)
- Test: `service/entityresolution/composite/v2/decision_test.go`

**Interfaces:**
- Consumes: `pdpFor`, `chainIdentifier`, `claimsEntity`, `callerContext` and `identityCoreSource` from the existing test helpers; Task 4's `svc.publishing`.
- `identityCoreSource()` in `helpers_test.go` gains `Actions: []string{"publish"}`, matching prod. Update any existing test that asserted `read` on the creator grant.
- The commented prod block uses exactly these values: `url: https://platform.arkavo.net`, `dial_address: 127.0.0.1:443`, `identity_url: https://identity.arkavo.net`, `client_id: opentdf-platform`, `client_secret: ""`. Its comment, in substance: do not enable until arks serves `GET /moderation/v1/suspensions/{subject}` with moderation on (arkavo-rs#93, PR #124). It fails closed, so enabling it early refuses publishing for every creator. A second comment line records the known limit: sealed `arkavo_evidence` isn't re-checked, so a token's sealed grant lasts until that evidence expires.

- [ ] **Step 1: Write a failing test** `TestPublishDecision_ThroughTheV2PDP` with the `patreonPolicy` PDP, a PEP claims chain carrying `iss` and `arkavo_entitlements: [publishValue]`, and a caller on `claims_chain_peps`. Generalize `permitted` into `permittedFor(t, pdp, clientID, id, action string, fqns...)`.
  - Action `publish` on `publishValue`, checker nil → permit.
  - Action `read` on `publishValue` → deny.
  - Action `publish`, checker → `ReasonSuspended` → deny.
  - Action `publish`, checker → `ReasonUnreachable` → deny.
  - A campaign `read` for the same subject while suspended → still permitted, if the chain also carries a campaign entitlement.
- [ ] **Step 2: Run** `go test ./entityresolution/composite/... -run TestPublishDecision` → FAIL (no attribute in the policy, or action `read`).
- [ ] **Step 3: Edit the policy and the configs.** If the PDP rejects the custom action `publish` with the file-backed policy, declare it in `policy.patreon.yaml` in whatever form `filestore` accepts for actions, and record that in the commit message.
- [ ] **Step 4: Run** `go test ./...` from `service/` → PASS. Also run the config tests that load the example YAMLs.
- [ ] **Step 5: Lint, format and commit:** `feat(config): arkavo-creator publish attribute, identity-core publish action, publishing_status block (#59)`.

### Task 6: Branch verification

- [ ] **Step 1:** Run `golangci-lint run ./...` from `service/` → 0 issues.
- [ ] **Step 2:** Run `go test ./...` from `service/` → PASS. Run `go test -race ./internal/publishingstatus/... ./internal/servicetoken/... ./entityresolution/composite/...` → PASS.
- [ ] **Step 3:** Check `git diff origin/main --stat`: only the files above, plus the spec and the plan.
