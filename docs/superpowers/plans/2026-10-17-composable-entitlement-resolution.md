# Composable Entitlement Resolution Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Replace the `patreon` and `arkavo` ERS modes with one composite resolver that runs every applicable entitlement source on every decision, so a creator is permitted for their own campaign's content on the licence, KAS rewrap and catalog routes. Hard cutover: no shadow period, no legacy path.

**Architecture:** A new `composite` ERS verifies the viewer's CWT in `CreateEntityChainsFromTokens`, runs every source a capability admits, unions their grants, applies subtractive constraints, and seals the result into the chain as `arkavo_evidence` for `ResolveEntities`. Unsealed claims chains are accepted only from allowlisted PEPs, and only into `pep_assertable` sources. The `patreon` and `arkavo` modes are deleted in the same change; their reusable parts (claim parsing, the `.patreon` view, the agent gate) stay behind the sources.

**Tech Stack:** Go 1.25 (`service` module), connect-go, protobuf `structpb`, go-cose / fxamacker cbor (the existing CWT verifier), testify.

**Spec:** `docs/superpowers/specs/2026-10-17-composable-entitlement-resolution-design.md`. Read it before starting; this plan argues from it.

**Companion plan (other repo; must be live before the cutover):** arkavo-rs `docs/superpowers/plans/2026-10-17-forward-patreon-entitlements.md`, on branch `feat/forward-patreon-entitlements`. arks forwards the filtered `arkavo_entitlements` in AuthZEN `pe_claims`. Without it, after the cutover every patron's catalog rows show Locked, because the platform no longer derives grants from memberships.

**Not in this plan (the spec defers them):**
- the live-source cache and single-flight. Phase 1 has no live source, and the cache is a decorator around a `source.Source`, so adding it changes no combiner code;
- narrowing a shared definition by value prefix;
- per-audience minting;
- per-source signed envelopes;
- the authorization-service changes in spec §6;
- `enforce_namespaced_entitlements`, which stays off.

## Global Constraints

- Issuer `https://identity.arkavo.net`; COSE key set `https://identity.arkavo.net/.well-known/cose-keys`; audience `https://platform.arkavo.net`; algorithm ES256.
- Patreon namespace `patreon.arkavo.com`; definitions `https://patreon.arkavo.com/attr/campaign` and `https://patreon.arkavo.com/attr/campaign-tier`. Campaign values are all digits; tier values are `<campaign digits>_<slug>` with the slug in `[a-z0-9-]+`.
- Patreon grants come only from `arkavo_entitlements`. `arkavo_patreon` feeds only the `.patreon` properties.
- Every attribute value FQN the composite emits is lowercased. The PDP lowercases resource FQNs; see `directEntitlements` in `entityresolution/arkavo/v2/entity_resolution.go`.
- Default action `read`. Default source deadline 300 ms.
- One owner per attribute definition: two sources listing the same definition is a startup error.
- No source, constraint or PEP decision branches on `role` (spec §2 anti-goal).
- Fail closed: a source error, panic, timeout or `unavailable` outcome contributes no grants and is never served stale. Constraints only remove grants.
- `agent_status` unset means every agent subject is withheld, as `patreon` mode does today.
- `device_class_caps`: a class missing from the map means no cap; a cap intersects and never adds. Device-class *grants* are a source, not a constraint.
- Only verified CWTs count as tokens. An unsigned JWT (`alg=none`), including the RAR bridge, is invalid.
- Commit after each task. Do not push or deploy without the owner's go-ahead.
- Run Go commands from `service/`. Tests: `go test ./entityresolution/... ./internal/auth/...`. `golangci-lint` isn't installed on the dev Mac; CI runs it (`.golangci.yaml`).

## Review Focus

1. **Catalog claims with no `iss`.** arks forwards `iss` only when the PEP supplied it. A PEP-asserted subject without `iss` must get no grants from any issuer-bound source, and no error. Pinned in Task 8 (`TestResolve_PEPChainWithoutIssGrantsNothing`).
2. **A forged `arkavo_evidence` from an allowlisted PEP.** It must be invalid (no grants), never downgraded to a PEP-asserted chain. Pinned in Task 8 (`TestResolve_ForgedSealGrantsNothing`).
3. **Two sources configured for one definition.** Startup fails naming both source IDs; no silent union. Pinned in Task 5 (`TestValidate`, case `shared definition`).
4. **A source exceeding the deadline.** The RPC still returns within about the deadline, that source is `unavailable` with no grants, and other sources' grants stand. Pinned in Task 7 (`TestTokenRoute_SlowSourceIsUnavailable`).
5. **`arkavo_entitlements` with non-string entries, mixed case and malformed values.** Non-strings and malformed values are dropped; mixed case is lowercased and kept. Pinned in Task 4 (`TestTokenSource_MalformedEntitlementsIgnored`).

## File Map

| File | Responsibility |
|---|---|
| `service/internal/auth/cwt_verifier.go` (modify) | `VerifyCWTClaims`: verified claims as a map |
| `service/entityresolution/source/source.go` (create) | The source contract. Leaf package: sources implement it in their home packages, so there are no import cycles |
| `service/entityresolution/patreon/v2/source.go` (create) | `patreon-token` source |
| `service/entityresolution/patreon/v2/passthrough.go` (modify) | `membershipView`; the grant derivation goes |
| `service/entityresolution/arkavo/v2/agent_gate.go` (modify) | Exported `AgentDenial` and `LogAgentDenial` |
| `service/entityresolution/composite/v2/config.go` (create) | Config, decoding, validation |
| `service/entityresolution/composite/v2/capability.go` (create) | Which subjects a source sees, and which grants it may make |
| `service/entityresolution/composite/v2/token_claims.go` (create) | `token-claims` source (identity-core) |
| `service/entityresolution/composite/v2/device_class.go` (create) | `device-class` source (replaces `device_class_ceilings`) |
| `service/entityresolution/composite/v2/evidence.go` (create) | Seal and open `arkavo_evidence` |
| `service/entityresolution/composite/v2/composite.go` (create) | The resolver: both RPCs, source fan-out, union |
| `service/entityresolution/composite/v2/constraints.go` (create) | Agent gate, device caps |
| `service/entityresolution/composite/v2/register.go` (create) | Build verifiers, sources and checker from config |
| `service/entityresolution/v2/entity_resolution.go` (modify) | `sources` selects the composite; the `patreon` and `arkavo` cases go |
| `examples/config/opentdf-patreon-prod.yaml`, `opentdf-patreon-local-test.yaml`, `opentdf-arkavo-local-test.yaml` (modify) | Converted to `sources:` |
| `service/entityresolution/README.md`, `patreon/v2/README.md`, `arkavo/v2/README.md`, `docs/Configuring.md`, `docs/patreon-authnz-contract.md` (modify) | Describe the composite, not the modes |

## Plan Calls (decisions this plan makes)

The owner said "do hard cutovers, we are pre-release". What follows from it (recorded in spec §4 as my reading): no shadow; the `patreon` and `arkavo` modes are deleted; there is no membership derivation; upstream's `mode` values are untouched; `mode` and `sources` together is a startup error. The rest are my calls:

- **Evidence encoding.** One string claim: `arkavo_evidence` = `base64url(payload JSON) "." base64url(HMAC-SHA256(key, "arkavo-evidence-v1" || 0x00 || payload JSON))`. An opaque string survives `structpb` untouched, so the second call verifies exactly the bytes the first sealed. Keys: `seal_key` (current; seals and opens) plus `previous_seal_keys` (open only). Each is base64, at least 32 bytes decoded.
- **An invalid token on the token route** seals an evidence with no grants (outcome `_token: invalid`, expiry now + 60 s), rather than failing the RPC. That gives a deny, not a 503.
- **The agent gate runs before the sources** for a gated subject. Withholding everything before or after the union gives the same answer, and running it first skips the source work.
- **identity-core is inert in phase 1.** `arkavo-creator` isn't a definition in `examples/config/policy.patreon.yaml`, so its `publish` grant can't synthesize and changes no decision. It is configured to prove the partition.
- **The PEP allowlist** holds the exact string `ctxAuth.GetClientIDFromContext(ctx, true)` returns inside the ERS for the catalog node: on the AuthZEN route arks forwards the PEP's own service CWT upstream, so the platform sees the catalog node, not arks. Prod derives client IDs from `arkavo_account_id`, so the value comes from Task 1. A missing or conflicting client ID is not allowlisted, and every refusal logs the ID it saw, so a mismatch shows in one line.
- **A failed COSE key fetch at startup only warns,** as `NewCWTVerifier` does today; the keys refresh on first use. This avoids making a platform restart depend on identity being up. The cutover check in Rollout catches a wrong URL.

---

### Task 1: Pre-checks (read-only, prod). Blocks the cutover

**Files:** none changed. Record each answer in the Rollout table.

- [ ] **Step 1:** Read the deployed tdf-iroh-s3 config on iroh.arkavo.net. Record the authz `protocol` (expected: AuthZEN through arks).
- [ ] **Step 2:** Find the catalog node's client ID as the platform sees it: the `client_id` attribute on the platform's log lines for a catalog AuthZEN decision (`GET /catalog/<campaign>` with a viewer token). Confirm the platform derives a non-empty client ID from the catalog node's service CWT (prod reads `arkavo_account_id`). Record the exact string. It becomes `claims_chain_peps`. Do not take it from a licence decision: that route carries arks's own credential.
- [ ] **Step 3:** Confirm the viewer token's `aud` includes `https://platform.arkavo.net`. A recent KAS rewrap that succeeded through the platform proves it. Record the log line and time. Never paste tokens into chat or logs.
- [ ] **Step 4:** Confirm that standard-TDF rewraps reach this platform's KAS and ERS: arks `KAS_PROXY_MODE`, and the platform log for `/kas.AccessService/Rewrap`.
- [ ] **Step 5:** Confirm the deployed `allow_direct_entitlements: true`, and that `enforce_namespaced_entitlements` is unset or false.
- [ ] **Step 6:** If any answer differs from what's expected, stop and tell the owner.

### Task 2: Verified claims from the CWT verifier

**Files:**
- Modify: `service/internal/auth/cwt_verifier.go` (`VerifyCWTSubjectToken`)
- Test: `service/internal/auth/cwt_verifier_test.go`

**Interfaces:**
- Produces: `func (v *CWTVerifier) VerifyCWTClaims(ctx context.Context, token string) (map[string]any, error)`. It runs the same checks as `VerifyCWTSubjectToken` (signature against the cached key set, then `validateStandardClaims`) and returns the `decodeCWTClaims` map. That is the shape `DecodeClaimsFromToken` gives. `VerifyCWTSubjectToken` calls it, and keeps its signature and behaviour.

- [ ] **Step 1: Write the failing tests.** Build them like `TestCWTVerifier_CustomClaimsRoundTrip`:
  - `TestCWTVerifier_VerifyCWTClaims_ReturnsClaimsMap`: custom `arkavo_entitlements: ["https://patreon.arkavo.com/attr/campaign/value/13167240"]` → `m["iss"] == issuer`, `m["sub"]` set, and `m["arkavo_entitlements"]` a `[]any` holding that one string.
  - `TestCWTVerifier_VerifyCWTClaims_RejectsWrongAudience`: an error and a nil map.
  - `TestCWTVerifier_VerifyCWTClaims_RejectsBadSignature`: signed by a key outside the set → error.
- [ ] **Step 2:** Run `go test ./internal/auth/ -run VerifyCWTClaims -v`. Expected: FAIL (`VerifyCWTClaims` undefined).
- [ ] **Step 3:** Move the verification part of `VerifyCWTSubjectToken` into `VerifyCWTClaims`. `VerifyCWTSubjectToken` builds its `jwt.Token` and unsigned JWT from the returned map.
- [ ] **Step 4:** Run `go test ./internal/auth/ -v`. Expected: PASS, every existing `TestCWTVerifier_*` included.
- [ ] **Step 5: Commit** `feat(auth): return verified CWT claims as a map`.

### Task 3: The source contract

**Files:**
- Create: `service/entityresolution/source/source.go`
- Test: `service/entityresolution/source/source_test.go`

**Interfaces:**
- Produces (package `source`):
  ```go
  type Kind string    // KindPerson "person", KindAgent "agent", KindDevice "device"
  type Trust int      // TrustNone (claims discarded), TrustPEP (allowlisted PEP's unsealed claims), TrustVerified (verified token)
  type Subject struct { Claims map[string]any; Kind Kind; AccountID string; Trust Trust }
  type Query struct { Action string; Resources []string } // Resources: requested value FQNs; empty when the route carries none
  type Grant struct { FQN string; Actions []string; ExpiresAt time.Time } // zero ExpiresAt: the evidence expiry applies
  type Outcome string // Complete "complete", NotApplicable "not_applicable", Unavailable "unavailable", Invalid "invalid"
  type Resolution struct { Grants []Grant; Properties map[string]any; Outcome Outcome }
  type Source interface { Resolve(ctx context.Context, subject Subject, query Query) (Resolution, error) }
  type FQN struct { Namespace, Definition, Value string }
  func ParseFQN(s string) (FQN, bool)
  func ParseDefinition(s string) (namespace, definition string, ok bool)
  func (f FQN) DefinitionFQN() string // "https://<ns>/attr/<def>"
  func (f FQN) String() string        // "https://<ns>/attr/<def>/value/<value>"
  func KindOf(claims map[string]any) Kind
  ```
- `ParseFQN` is structural. It lowercases the input, then requires exactly `https://<ns>/attr/<def>/value/<value>`, with every part non-empty and no further `/`. `ParseDefinition` requires exactly `https://<ns>/attr/<def>`.
- `KindOf` returns `KindAgent` when `agentstatus.HasAgentMarker(claims)`, `KindDevice` when `arkavo_npe.type == "device"`, and `KindPerson` otherwise.

- [ ] **Step 1: Write the failing tests:**
  - `TestParseFQN`, a table:
    - `https://patreon.arkavo.com/attr/campaign/value/13167240` → `{patreon.arkavo.com, campaign, 13167240}`;
    - `HTTPS://Patreon.Arkavo.com/attr/Campaign/value/X1` → lowercased;
    - rejected: no value segment, an empty value, `http://`, `…/value/1/2`, and `…/attrs/…`;
    - `https://patreon.arkavo.com.evil/attr/campaign/value/1` parses, with namespace `patreon.arkavo.com.evil`.
  - `TestParseDefinition`: a definition parses; one with a `/value/…` suffix doesn't.
  - `TestKindOf`: `{}` → person; `arkavo_npe.type` `device` → device; `agent` → agent.
- [ ] **Step 2:** Run `go test ./entityresolution/source/ -v`. Expected: FAIL.
- [ ] **Step 3:** Implement.
- [ ] **Step 4:** Run it again. Expected: PASS.
- [ ] **Step 5: Commit** `feat(ers): source contract for composable entitlement resolution`.

### Task 4: Patreon token source

**Files:**
- Modify: `service/entityresolution/patreon/v2/passthrough.go`
- Create: `service/entityresolution/patreon/v2/source.go`
- Test: `service/entityresolution/patreon/v2/source_test.go`

**Interfaces:**
- Consumes: `source.*` (Task 3).
- Produces:
  ```go
  func membershipView(claim *arkavoPatreonClaim) *Membership // the Membership half of today's passthroughResolution: status, tier_slug, campaign_ids; no grants
  type SourceConfig struct {
      EntitlementsNamespace string `mapstructure:"entitlements_namespace"` // default patreon.arkavo.com
      InferUnknownAsFree    bool   `mapstructure:"infer_unknown_as_free"`
  }
  func NewTokenSource(cfg SourceConfig) source.Source
  ```
- `passthroughResolution` calls `membershipView` until Task 10 deletes it.
- `Resolve`:
  - **Grants:** every string in `arkavo_entitlements` that `ParseFQN`s into the configured namespace, with definition `campaign` (value all digits) or `campaign-tier` (value `^[0-9]+_[a-z0-9-]+$`), each with actions `["read"]`. It never reads `role`, and it derives nothing from memberships.
  - **`Properties`:** `membershipStruct(membershipView(claim)).AsMap()` when `parseArkavoPatreon` finds a claim. With no claim and `InferUnknownAsFree`, the free view (`tier_slug: free`, `status: former`). Otherwise nil.
  - **`Outcome`:** `Complete` when it returns grants or properties, else `NotApplicable`.

- [ ] **Step 1: Write the failing tests:**
  - `TestTokenSource_CreatorTiersFromEntitlements`. Claims: `arkavo_patreon: {role: "creator", campaign_id: "13167240", memberships: []}`, and `arkavo_entitlements` holding:
    - campaign `13167240`;
    - campaign-tier `13167240_supporter`, `13167240_free` and `13167240_tier-555`;
    - `https://arkavo.ai/attr/tdf/value/decrypt`;
    - `https://patreon.arkavo.com/attr/arkavo-creator/value/publish`.

    Expected grant FQNs: exactly the four Patreon ones.
  - `TestTokenSource_PatronGrantsComeOnlyFromEntitlements`: an active membership `7237273` with `tier_slugs: ["Supporter"]`.
    - `arkavo_entitlements` = campaign `7237273`, `7237273_supporter`, `7237273_tier-42` → exactly those three.
    - The same membership with no `arkavo_entitlements` → no grants, but `Properties["status"] == "active"`.
  - `TestTokenSource_MalformedEntitlementsIgnored`: `arkavo_entitlements` = `42`, `"HTTPS://PATREON.ARKAVO.COM/attr/campaign/value/7237273"`, `"https://patreon.arkavo.com/attr/campaign/value/abc"` and `"https://patreon.arkavo.com/attr/campaign-tier/value/7237273"` → exactly `https://patreon.arkavo.com/attr/campaign/value/7237273`.
  - `TestTokenSource_NoClaimInfersFree`: empty claims and `InferUnknownAsFree` → no grants, `Properties["status"] == "former"`, `Properties["tier_slug"] == "free"`.
  - `TestTokenSource_DeclinedMembershipView`: a `declined_patron` membership → `Properties["status"] == "declined"`, no grants.
- [ ] **Step 2:** Run `go test ./entityresolution/patreon/v2/ -run TokenSource -v`. Expected: FAIL.
- [ ] **Step 3:** Extract `membershipView` and implement `source.go`.
- [ ] **Step 4:** Run `go test ./entityresolution/patreon/v2/ -v`. Expected: PASS, existing tests included.
- [ ] **Step 5: Commit** `feat(patreon): token source for the composite ERS`.

### Task 5: Composite config, capabilities, identity-core and device-class sources, exported agent gate

**Files:**
- Modify: `service/entityresolution/arkavo/v2/agent_gate.go`
- Create: `service/entityresolution/composite/v2/config.go`, `capability.go`, `token_claims.go`, `device_class.go`
- Test: `service/entityresolution/arkavo/v2/agent_gate_test.go`, `service/entityresolution/composite/v2/config_test.go`, `capability_test.go`, `token_claims_test.go`, `device_class_test.go`

**Interfaces:**
- Produces (arkavo):
  - `func AgentDenial(ctx context.Context, checker agentstatus.Checker, claims map[string]any, ownerClaim string) (agentstatus.Subject, error)`. It parses the claims, builds the subject as `agentSubject` does, and returns nil for an ungated subject and `ReasonUnconfigured` for a nil checker. It recovers a checker panic as `checkStatus` does.
  - `func LogAgentDenial(ctx context.Context, log *logger.Logger, subject agentstatus.Subject, err error)`, which is today's `logAgentDenial` body.
  - The service's methods delegate to both until Task 10.
- Produces (composite, package `composite`). Config keys sit directly under `services.entityresolution`, as in spec §7:
  ```go
  type Config struct {
      Deadline    time.Duration     `mapstructure:"deadline"` // default 300ms
      Evidence    EvidenceConfig    `mapstructure:"evidence"`
      Sources     []SourceConfig    `mapstructure:"sources"`
      Constraints ConstraintsConfig `mapstructure:"constraints"`
  }
  type EvidenceConfig struct {
      Issuers          []IssuerConfig `mapstructure:"issuers"`
      SealKey          string         `mapstructure:"seal_key"`           // base64, ≥32 bytes decoded; redacted in LogValue
      PreviousSealKeys []string       `mapstructure:"previous_seal_keys"` // open only
      ClaimsChainPEPs  []string       `mapstructure:"claims_chain_peps"`
  }
  type IssuerConfig struct { Issuer string `mapstructure:"issuer"`; COSEKeysURL string `mapstructure:"cose_keys_url"`; Audience string `mapstructure:"audience"` }
  type SourceConfig struct {
      ID            string         `mapstructure:"id"`
      Type          string         `mapstructure:"type"` // "patreon-token" | "token-claims" | "device-class"
      Issuer        string         `mapstructure:"issuer"`
      Grants        []string       `mapstructure:"grants"`   // attribute definition FQNs
      Actions       []string       `mapstructure:"actions"`  // default ["read"]
      Subjects      []source.Kind  `mapstructure:"subjects"` // default all three kinds
      PEPAssertable bool           `mapstructure:"pep_assertable"`
      PropertiesKey string         `mapstructure:"properties_key"`
      Options       map[string]any `mapstructure:",remain"` // type-specific fields
  }
  type ConstraintsConfig struct {
      AgentStatus     agentstatus.Config  `mapstructure:"agent_status"`
      DeviceClassCaps map[string][]string `mapstructure:"device_class_caps"`
  }
  func DecodeConfig(in config.ServiceConfig) (cfg Config, present bool, err error) // present: in has "sources"; duration hook as arkavo's decodeConfig
  func (c Config) Validate() error

  type capability struct { issuer string; definitions map[string]bool; actions []string; subjects map[source.Kind]bool; pepAssertable bool }
  func newCapability(sc SourceConfig) capability
  func (c capability) admits(s source.Subject) bool // kind allowed, and: TrustVerified → claims iss == issuer; TrustPEP → pepAssertable && iss == issuer; TrustNone → true (claims are empty)
  func (c capability) allows(g source.Grant) bool   // ParseFQN ok, its DefinitionFQN owned, every action in c.actions

  func newTokenClaimsSource(claim string, definitions []string) source.Source // Options["claim"]: string entries in its own definitions, lowercased
  func newDeviceClassSource(classes map[string][]string) source.Source      // Options["classes"]: KindDevice only; grants classes[arkavo_npe.class], default class "unverified"
  ```

- [ ] **Step 1: Write the failing tests:**
  - `TestAgentDenial_PersonIsNeverGated`.
  - `TestAgentDenial_UnconfiguredWithholdsAgent`: agent claims as in `TestAgentGate_ThroughTheV2PDP`, nil checker → `*agentstatus.DenialError` with `Reason == agentstatus.ReasonUnconfigured`.
  - `TestValidate`, a table with one error per case:
    - no issuers;
    - an issuer without `cose_keys_url` or `audience`;
    - an empty `seal_key`;
    - a seal key under 32 bytes;
    - a previous key that isn't base64;
    - a source with an empty ID, a duplicate ID or an unknown type;
    - a grant that isn't a definition FQN;
    - a source issuer not among `evidence.issuers`;
    - **shared definition**: two sources list `https://patreon.arkavo.com/attr/campaign`, and the error names both IDs;
    - a `device-class` FQN outside that source's `grants`;
    - a `device_class_caps` entry that isn't a value FQN.

    Plus one valid config in the spec §7 shape → nil. Task 9 validates the example files themselves.
  - `TestDecodeConfig_AbsentIsNotPresent`: no `sources` → `present == false`.
  - `TestDecodeConfig_DurationString`: `deadline: "250ms"` → 250 ms.
  - `TestDecodeConfig_AgentStatusTimeout`: port the decode cases of `arkavo/v2/agent_status_config_test.go` to `constraints.agent_status`.
  - `TestCapability_Admits`, a table:
    - verified with a matching `iss` → true;
    - verified with another `iss` → false;
    - PEP when not `pepAssertable` → false;
    - PEP, assertable, with no `iss` → false;
    - a kind that isn't listed → false;
    - TrustNone → true.
  - `TestCapability_Allows`: an owned definition → true; another definition → false; unparseable → false; `write` when only `read` is allowed → false.
  - `TestTokenClaimsSource_SelectsOwnDefinitions`.
  - `TestDeviceClassSource`:
    - `managed` → the `managed` FQNs;
    - a missing class → the `unverified` FQNs;
    - a person subject → nothing.
- [ ] **Step 2:** Run `go test ./entityresolution/arkavo/v2/ ./entityresolution/composite/v2/ -v`. Expected: FAIL.
- [ ] **Step 3:** Implement.
- [ ] **Step 4:** Run it again. Expected: PASS, the existing arkavo tests included.
- [ ] **Step 5: Commit** `feat(ers): composite config, capabilities, token-claims and device-class sources`.

### Task 6: Sealed evidence

**Files:**
- Create: `service/entityresolution/composite/v2/evidence.go`
- Test: `service/entityresolution/composite/v2/evidence_test.go`

**Interfaces:**
- Produces:
  ```go
  const evidenceClaim = "arkavo_evidence"
  type evidence struct {
      V        int                       `json:"v"`   // 1
      Sub      string                    `json:"sub"`
      Exp      int64                     `json:"exp"` // unix seconds, never later than the token's exp
      Grants   []sealedGrant             `json:"grants"`
      Props    map[string]map[string]any `json:"props"`    // properties_key → properties
      Outcomes map[string]source.Outcome `json:"outcomes"` // source id → outcome; "_token" for the token itself
  }
  type sealedGrant struct { FQN string `json:"fqn"`; Actions []string `json:"actions"`; Source string `json:"source"`; Exp int64 `json:"exp,omitempty"` }
  func sealEvidence(key []byte, e evidence) (string, error)
  func openEvidence(keys [][]byte, sealed string, now time.Time) (evidence, error) // tries every key with hmac.Equal; rejects V != 1 and Exp <= now; drops grants whose Exp is set and <= now
  ```
  The encoding is in Plan Calls.

- [ ] **Step 1: Write the failing tests:**
  - `TestEvidence_RoundTrip`;
  - `TestEvidence_TamperedPayloadRejected`;
  - `TestEvidence_WrongKeyRejected`;
  - `TestEvidence_PreviousKeyStillOpens`;
  - `TestEvidence_ExpiredRejected`;
  - `TestEvidence_ExpiredGrantDropped`;
  - `TestEvidence_SurvivesStructpb`: the string goes through `structpb.NewStruct` and back through `AsMap`, then opens.
- [ ] **Step 2:** Run `go test ./entityresolution/composite/v2/ -run Evidence -v`. Expected: FAIL.
- [ ] **Step 3:** Implement.
- [ ] **Step 4:** Run it again. Expected: PASS.
- [ ] **Step 5: Commit** `feat(ers): seal composite evidence between the two ERS calls`.

### Task 7: Composite token route, with constraints

**Files:**
- Create: `service/entityresolution/composite/v2/composite.go`, `constraints.go`
- Test: `service/entityresolution/composite/v2/composite_token_test.go` and `constraints_test.go`, plus `helpers_test.go`. The helpers are a fake verifier, fake sources and `newTestService`, which sets `Tracer = noop.NewTracerProvider().Tracer("test")` as the patreon and arkavo tests do.

**Interfaces:**
- Consumes: Tasks 3-6, `arkavo.AgentDenial`, `arkavo.LogAgentDenial`, and `auth.DecodeCWTClaimsFromToken` (to read `iss` before choosing a verifier).
- Produces:
  ```go
  type claimsVerifier interface { VerifyCWTClaims(ctx context.Context, token string) (map[string]any, error) }
  type configuredSource struct { id, propsKey string; cap capability; src source.Source }
  type Service struct {
      entityresolutionV2.UnimplementedEntityResolutionServiceServer
      trace.Tracer
      // cfg, verifiers map[string]claimsVerifier (by issuer), sources []configuredSource,
      // sealKeys [][]byte (first seals), peps map[string]bool, agentStatus agentstatus.Checker,
      // caps map[string]map[string]bool, now func() time.Time, logger *logger.Logger
  }
  func New(cfg Config, verifiers map[string]claimsVerifier, sources []configuredSource, checker agentstatus.Checker, log *logger.Logger) (*Service, error)
  func (s *Service) CreateEntityChainsFromTokens(ctx context.Context, req *connect.Request[entityresolutionV2.CreateEntityChainsFromTokensRequest]) (*connect.Response[entityresolutionV2.CreateEntityChainsFromTokensResponse], error)
  func (s *Service) resolveToken(ctx context.Context, raw string, q source.Query) evidence
  func (s *Service) resolveSubject(ctx context.Context, subj source.Subject, q source.Query, exp time.Time) evidence
  func (s *Service) withheldAgent(ctx context.Context, subj source.Subject) bool // gated subject refused by AgentDenial(s.agentStatus, claims, "arkavo_account_id"); logs via LogAgentDenial
  func capGrants(caps map[string]map[string]bool, subj source.Subject, grants []sealedGrant) []sealedGrant // device subjects only; class from arkavo_npe.class, default "unverified"
  ```
- **Token handling:**
  - Decode the token unverified (CWT only) to read `iss`, pick that issuer's verifier, verify, and require `exp`.
  - Anything else, an unsigned JWT included, seals an evidence with no grants (see Plan Calls).
  - The subject is `TrustVerified`, with kind `KindOf(claims)` and `AccountID` from `arkavo_account_id`.
  - `Query.Resources` are the request's `Resource_AttributeValues` FQNs; `Action` is `read`.
- **`resolveSubject`:**
  1. If `withheldAgent`, return no grants and no props.
  2. Otherwise run each admitted source in its own goroutine, under `context.WithTimeout(cfg.Deadline)`. A source that errors, panics or misses the deadline is `Unavailable` and contributes nothing.
  3. Drop any grant the source's capability doesn't allow, with a `Warn` log naming the source ID.
  4. Union the rest by FQN: merge actions, and keep the first source as provenance.
  5. Apply `capGrants`.
  6. Put each source's props under its `PropertiesKey` when non-empty.
- **The returned chain** has one entity per token: an `Entity_Claims` subject entity `{arkavo_evidence: <sealed>}`, `EphemeralId` `composite-subject`.

- [ ] **Step 1: Write the failing tests.** Each opens the sealed claim from the returned chain to assert.
  - `TestTokenRoute_CreatorGetsOwnCampaignTiers`: real `patreon.NewTokenSource` (`properties_key: patreon`) plus identity-core, with the creator claims from Task 4. Expected: grants include `campaign/13167240`, `campaign-tier/13167240_supporter` and `13167240_free`, and `Props["patreon"]` is present.
  - `TestTokenRoute_SourceCannotGrantOutsideCapability`: a fake source owning `https://example.com/attr/a` returns `…/campaign/value/1` → absent.
  - `TestTokenRoute_SlowSourceIsUnavailable`: deadline 50 ms, a fake source sleeps 1 s. Expected: returns in under 500 ms, that source's outcome is `unavailable`, and the other source's grants are present.
  - `TestTokenRoute_SourceErrorAndPanicAreUnavailable`.
  - `TestTokenRoute_InvalidTokenSealsNoGrants`: the verifier errors → no RPC error, no grants, `Outcomes["_token"] == invalid`.
  - `TestTokenRoute_MissingExpIsInvalid`, `TestTokenRoute_UnknownIssuerIsInvalid` and `TestTokenRoute_UnsignedJWTIsInvalid`. The last uses a JOSE `alg=none` token carrying Patreon entitlements.
  - `TestTokenRoute_CBORNativeClaimValues`, ported from `patreon/v2/cwt_token_test.go`: the fake verifier returns `arkavo_patreon` with `time.Time` and `cbor.Tag` values. The evidence still seals, and grants are present.
  - `TestTokenRoute_EvidenceExpiryIsTokenExpiry`.
  - `TestTokenRoute_SourceOrderIsIrrelevant`.
  - `TestAgentWithheldWhenStatusUnset`.
  - `TestAgentAdmittedWhenEligible`.
  - `TestDeviceCaps_MissingClassIsNoCap` and `TestDeviceCaps_IntersectNeverAdds`.
- [ ] **Step 2:** Run `go test ./entityresolution/composite/v2/ -run 'TokenRoute|Agent|DeviceCaps' -v`. Expected: FAIL.
- [ ] **Step 3:** Implement.
- [ ] **Step 4:** Run `go test -race ./entityresolution/composite/v2/ -v`. Expected: PASS.
- [ ] **Step 5: Commit** `feat(ers): composite token route with constraints`.

### Task 8: Composite `ResolveEntities`, and the acceptance tests

**Files:**
- Modify: `service/entityresolution/composite/v2/composite.go`
- Test: `service/entityresolution/composite/v2/composite_resolve_test.go`, `decision_test.go`

**Interfaces:**
- Produces:
  - `func (s *Service) ResolveEntities(ctx context.Context, req *connect.Request[entityresolutionV2.ResolveEntitiesRequest]) (*connect.Response[entityresolutionV2.ResolveEntitiesResponse], error)`
  - `func callerClientID(ctx context.Context, peps map[string]bool) (id string, allowlisted bool)`, which gives `"none"` or `"conflict"` on `ErrNoMetadataFound` or `ErrConflictClientID`.
- Per entity:
  - A claims entity whose `arkavo_evidence` is a string → `openEvidence`. On failure, a representation with no grants and no props, and a `Warn` log. It is never treated as PEP-asserted.
  - A claims entity without one → `TrustPEP` when `callerClientID` is allowlisted. Otherwise `TrustNone` with empty claims, and a `Warn` `composite: unsealed claims chain from a caller not on claims_chain_peps` with `client_id`.
  - Any other entity type → `TrustNone` with empty claims.
- The representation:
  - `OriginalId`: the ephemeral ID, or `ent.EntityIDPrefix + index`;
  - `AdditionalProps`: one struct of `{propertiesKey: props}`, omitted when empty;
  - `DirectEntitlements`: the grants.

- [ ] **Step 1: Write the failing tests:**
  - `TestResolve_SealedEvidenceBecomesRepresentation`.
  - `TestResolve_ForgedSealGrantsNothing`: from an allowlisted client.
  - `TestResolve_PEPChainFromAllowlistedClient`:
    - ctx is `metadata.NewIncomingContext(ctx, metadata.Pairs(ctxAuth.ClientIDKey, "arks-test"))`;
    - claims: `{sub, iss, arkavo_patreon (creator, 13167240), arkavo_entitlements: [campaign 13167240, campaign-tier 13167240_supporter, arkavo-creator/value/publish]}`;
    - expected: grants are the two Patreon FQNs. `publish` is absent, because identity-core isn't `pep_assertable`.
  - `TestResolve_PEPChainFromOtherClientGrantsNothing`, with subtests: another client ID, no metadata, and two conflicting `client_id` values.
  - `TestCallerClientID`, a table:
    - an allowlisted ID → (`arks-test`, true);
    - another ID → (its value, false);
    - no metadata → (`none`, false);
    - two values → (`conflict`, false).
  - `TestResolve_PEPChainWithoutIssGrantsNothing`.
  - `TestResolve_NonClaimsEntityGetsFreeView`: a `UserName` entity → no grants, `patreon.status == "former"`.
  - `TestPatreonDecisions_ThroughTheV2PDP` (`decision_test.go`).
    - **Harness:** copied from `arkavo/v2/agent_gate_decision_test.go`, namely `inProcessERS`, `access.NewJustInTimePDP(ctx, logger.CreateTestLogger(), sdk, store, true, false)`, `filestore.NewStoreFromFile("../../../../examples/config/policy.patreon.yaml")` and `audit.ContextWithActorID`.
    - **Resource:** `[https://patreon.arkavo.com/attr/campaign/value/13167240, https://patreon.arkavo.com/attr/campaign-tier/value/13167240_supporter]`.
    - **Subtests:**
      - `licence and KAS: creator token` → `AllPermitted`;
      - `catalog: creator claims from the allowlisted PEP` → `AllPermitted`;
      - `catalog: same claims from another client` → denied;
      - `patron of 13167240, tier supporter, token route` → permitted;
      - `patron of 13167240, catalog route` → permitted;
      - `cross-campaign: patron of 7237273 only` → denied;
      - `declined and former patrons of 13167240` → denied.
  - `TestAgentGate_ThroughTheV2PDP`, ported from `arkavo/v2/agent_gate_decision_test.go`:
    - `policy.arkavo.yaml`, and a `token-claims` source owning `https://arkavo.ai/attr/tdf`;
    - its token is a test CWT accepted by the fake verifier, not an unsigned JWT;
    - the three subtests are unchanged: eligible → permitted, quarantined → denied, unreachable → denied.
- [ ] **Step 2:** Run `go test ./entityresolution/composite/v2/ -run 'Resolve|CallerClientID|ThroughTheV2PDP' -v`. Expected: FAIL.
- [ ] **Step 3:** Implement.
- [ ] **Step 4:** Run `go test -race ./entityresolution/composite/v2/ -v`. Expected: PASS.
- [ ] **Step 5: Commit** `feat(ers): composite ResolveEntities; creator permitted on every route`.

### Task 9: Registration and the converted configs

**Files:**
- Create: `service/entityresolution/composite/v2/register.go`
- Modify: `service/entityresolution/v2/entity_resolution.go` (`RegisterFunc`), `examples/config/opentdf-patreon-prod.yaml`, `opentdf-patreon-local-test.yaml`, `opentdf-arkavo-local-test.yaml`
- Test: `service/entityresolution/composite/v2/register_test.go`

**Interfaces:**
- Produces: `func Register(in config.ServiceConfig, log *logger.Logger) (*Service, error)`. It:
  1. calls `DecodeConfig`, then `Validate`;
  2. builds one `auth.NewCWTVerifier` per issuer (ES256, with that issuer's audience);
  3. builds the sources from `sourceFactories map[string]func(SourceConfig) (source.Source, error)`:
     - `patreon-token` decodes `Options` into `patreon.SourceConfig`;
     - `token-claims` reads `Options["claim"]`;
     - `device-class` reads `Options["classes"]`;
  4. builds `agentstatus.New` when `constraints.agent_status` is enabled.
- `RegisterFunc`:
  - When `DecodeConfig` reports `present`: a `mode` that is also set is fatal. Otherwise call `Register`, set `Tracer`, and return it. A `Register` error is fatal, as other config errors are.
  - Without `sources`, today's switch runs for the upstream modes.
- Configs:
  - `opentdf-patreon-prod.yaml`: replace `mode: patreon` and its keys with the spec §7 shape, which has:
    - `seal_key: ""`, with a comment that the deployment supplies it as a secret;
    - `claims_chain_peps` set to the Task 1 value;
    - a `patreon` source (`patreon-token`, `pep_assertable: true`, `properties_key: patreon`, `infer_unknown_as_free: true`);
    - an `identity-core` source (`token-claims`, `claim: arkavo_entitlements`, grants `https://patreon.arkavo.com/attr/arkavo-creator`);
    - `constraints.agent_status` unset, and `device_class_caps: {}`.
  - `opentdf-patreon-local-test.yaml`: the same, with its local issuer.
  - `opentdf-arkavo-local-test.yaml`:
    - a `token-claims` source owning `https://arkavo.ai/attr/tdf`;
    - a `device-class` source owning `https://arkavo.ai/attr/classification`, with its three classes;
    - its `agent_status` block moved under `constraints`.

- [ ] **Step 1: Write the failing tests:**
  - `TestRegister_BuildsComposite`;
  - `TestRegister_RejectsInvalidConfig` (shared definition);
  - `TestExampleConfigsValidate`: each of the three YAML files, with a 32-byte test `seal_key` set, gives nil from `DecodeConfig` and `Validate`, and `present == true`;
  - `TestRegisterFunc_ModeAndSourcesIsFatal`, in `v2` (assert on a `selectResolver(cfg) (useComposite bool, err error)` helper rather than `log.Fatalf`).

  Use an unreachable `cose_keys_url`: `NewCWTVerifier` only warns.
- [ ] **Step 2:** Run `go test ./entityresolution/composite/v2/ ./entityresolution/v2/ -run 'Register|Example' -v`. Expected: FAIL.
- [ ] **Step 3:** Implement.
- [ ] **Step 4:** Run `go test -race ./entityresolution/... ./internal/auth/... && go build ./...`. Expected: PASS, and a clean build.
- [ ] **Step 5: Commit** `feat(ers): register the composite resolver from sources`.

### Task 10: Delete the `patreon` and `arkavo` modes

**Files:**
- Modify: `service/entityresolution/v2/entity_resolution.go` (remove `PatreonMode`, `ArkavoMode` and their cases)
- Delete from `service/entityresolution/patreon/v2/`: everything except `types.go`, `source.go`, `parseArkavoPatreon`, `membershipView`, `membershipStruct`, `toIfaceSlice`, `slugify` and `normalizeStatus`. That means `EntityResolutionService`, `Config`, `JWTConfig`, `RegisterPatreonERS`, `NewERS`, both RPCs, `passthroughResolution` and the entitlement constants. `numericCampaignID` stays only if `source.go` uses it.
- Delete from `service/entityresolution/arkavo/v2/`: everything except `AgentDenial`, `LogAgentDenial`, `parseArkavoClaims` and what they call. That means `entity_resolution.go`, `config.go` and the JWT-path helpers in `claims.go` (`claimsFromToken`, `jwtPayloadClaim`, `exactStateVersion`).
- Tests: delete the tests of deleted code (`entity_resolution_test.go` and `cwt_token_test.go` in both packages, `agent_withheld_test.go`, the `passthroughResolution` cases of `passthrough_test.go`, and `agent_gate_decision_test.go`, which is ported in Task 8). Keep or adapt the tests of kept functions (`parseArkavoClaims` and state-version cases in `claims_test.go`, the `AgentDenial` cases in `agent_gate_test.go`).
- Docs:
  - `service/entityresolution/README.md` (the mode list);
  - `patreon/v2/README.md` and `arkavo/v2/README.md`: what each package now provides to the composite;
  - `docs/Configuring.md` (the `mode: arkavo` / `agent_status` section moves to `constraints.agent_status`);
  - `docs/patreon-authnz-contract.md` (`mode: patreon`).

- [ ] **Step 1:** Delete the code and tests listed above.
- [ ] **Step 2:** Run `go build ./... && go vet ./entityresolution/... && go test -race ./entityresolution/... ./internal/auth/... ./authorization/... ./internal/access/...`. Expected: PASS.
- [ ] **Step 3:** Run `git grep -n -E "PatreonMode|ArkavoMode|RegisterPatreonERS|RegisterArkavoERS|trust_materialized_claims|device_class_ceilings|mode: (patreon|arkavo)" -- ':!docs/superpowers'`. Expected: no matches.
- [ ] **Step 4:** Update the docs listed above.
- [ ] **Step 5: Commit** `refactor(ers)!: remove the patreon and arkavo modes`.

---

## Rollout (owner approves each prod step)

| Pre-check (Task 1) | Expected | Found |
|---|---|---|
| Catalog node authz protocol | AuthZEN via arks | |
| Catalog node client ID at the platform (catalog AuthZEN decision) | (exact string) | |
| Viewer token `aud` has `https://platform.arkavo.net` | yes | |
| Standard-TDF rewrap reaches this platform | yes | |
| `allow_direct_entitlements` / `enforce_namespaced_entitlements` | `true` / off | |

1. **arks first, verified live.** Deploy the companion arkavo-rs plan. Under today's `patreon` mode it changes nothing.
2. **Cut over.** Deploy this branch with the converted prod config, the real `seal_key` and the Task 1 `claims_chain_peps`. Then, within minutes:
   - the creator account on the iPhone lists, downloads and plays its own campaign's recording;
   - a patron device lists and plays theirs;
   - a standard-TDF KAS rewrap succeeds.

   Watch for `composite: unsealed claims chain from a caller not on claims_chain_peps`, `_token: invalid` and source `unavailable` logs. Any of them, or a failed check, means rollback: redeploy the previous platform build and config.

**Owner follow-ups, not code:**
- Add the forwarded `arkavo_entitlements` subject property to draft-arkavo-authzen-cwt-00.
- arkavo-ios ADR-0058 still says a creator's token lacks tier values.
