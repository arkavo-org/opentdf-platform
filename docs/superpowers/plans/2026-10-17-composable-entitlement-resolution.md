# Composable Entitlement Resolution Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Replace the single ERS `mode` with a composite resolver that runs every applicable entitlement source on every decision, so a creator is permitted for their own campaign's content on the licence, KAS rewrap and catalog routes.

**Architecture:** A new `composite` ERS verifies the viewer's CWT in `CreateEntityChainsFromTokens`, runs every source a capability admits, unions their grants, applies subtractive constraints, and seals the result into the chain as `arkavo_evidence` for `ResolveEntities`. Unsealed claims chains are accepted only from allowlisted PEPs and only into `pep_assertable` sources. A shadow wrapper lets the legacy `patreon` mode keep serving while the composite's grant sets are compared and logged.

**Tech Stack:** Go 1.25 (`service` module), connect-go, protobuf `structpb`, go-cose / fxamacker cbor (existing CWT verifier), testify.

**Spec:** `docs/superpowers/specs/2026-10-17-composable-entitlement-resolution-design.md`. Read it before starting; this plan argues from it.

**Companion plan (other repo, must ship first):** arkavo-rs `docs/superpowers/plans/2026-10-17-forward-patreon-entitlements.md` (arks forwards the filtered `arkavo_entitlements` in AuthZEN `pe_claims`).

**Not in this plan (spec says later):** live-source cache and single-flight (no live source in phase 1; it is a decorator around a `source.Source`, so adding it later changes no combiner code), value-prefix narrowing within a shared definition, per-audience minting, per-source signed envelopes, the authorization-service changes in spec §6, `enforce_namespaced_entitlements` (stays off).

## Global Constraints

- Issuer `https://identity.arkavo.net`; COSE key set `https://identity.arkavo.net/.well-known/cose-keys`; audience `https://platform.arkavo.net`; algorithm ES256.
- Patreon namespace `patreon.arkavo.com`; definitions `https://patreon.arkavo.com/attr/campaign` and `https://patreon.arkavo.com/attr/campaign-tier`. Campaign values are all digits; tier values are `<campaign digits>_<slug>` with the slug in `[a-z0-9-]+`.
- Every attribute value FQN the composite emits is lowercased (the PDP lowercases resource FQNs; see `directEntitlements` in `entityresolution/arkavo/v2/entity_resolution.go`).
- Default action `read`. Default source deadline 300 ms.
- One owner per attribute definition: two sources listing the same definition is a startup error.
- No source, constraint, PEP or classifier decision branches on `role` (spec §2 anti-goal). The shadow classifier may *read* `arkavo_patreon.campaign_id` to label a log line; it never changes an answer.
- Fail closed: a source error, panic, timeout or `unavailable` outcome contributes no grants and is never served stale. Constraints only remove grants.
- `agent_status` unset means every agent subject is withheld (today's `patreon` mode behaviour, so prod parity).
- `device_class_caps`: a class missing from the map means no cap; a cap intersects, never adds.
- Commit after each task. Do not push or deploy without the owner's go-ahead.
- Run Go commands from `service/`. Tests: `go test ./entityresolution/... ./internal/auth/...`. `golangci-lint` is not installed on the dev Mac; CI runs it (`.golangci.yaml`).

## Review Focus

1. **Catalog claims with no `iss`.** arks forwards `iss` only when the PEP supplied it. A PEP-asserted subject without `iss` must get no grants from any issuer-bound source, not an error. Pinned in Task 8 (`TestResolve_PEPChainWithoutIssGrantsNothing`).
2. **A forged `arkavo_evidence` from an allowlisted PEP.** It must be treated as invalid evidence (no grants), never downgraded to a PEP-asserted chain. Pinned in Task 8 (`TestResolve_ForgedSealGrantsNothing`).
3. **Two sources configured for one definition.** Startup must fail with both source IDs named, not silently union. Pinned in Task 5 (`TestValidate` case `shared definition`).
4. **A source exceeding the deadline.** The RPC still returns within about the deadline, that source is `unavailable` with no grants, other sources' grants stand. Pinned in Task 7 (`TestTokenRoute_SlowSourceIsUnavailable`).
5. **`arkavo_entitlements` with non-string entries, mixed case, and malformed values.** Non-strings and malformed values are dropped, mixed case is lowercased and kept. Pinned in Task 4 (`TestTokenSource_MalformedEntitlementsIgnored`).

## File Map

| File | Responsibility |
|---|---|
| `service/internal/auth/cwt_verifier.go` (modify) | `VerifyCWTClaims`: verified claims as a map |
| `service/entityresolution/source/source.go` (create) | The source contract: `Source`, `Subject`, `Query`, `Grant`, `Resolution`, `Outcome`, `ParseFQN`, `KindOf`. Leaf package; sources implement it in their home packages, so there are no import cycles |
| `service/entityresolution/patreon/v2/passthrough.go` (modify) | #96 id-shaped slug filter in the legacy derivation |
| `service/entityresolution/patreon/v2/source.go` (create) | `patreon-token` source |
| `service/entityresolution/arkavo/v2/agent_gate.go` (modify) | Exported `AgentDenial`, reused by the composite |
| `service/entityresolution/composite/v2/config.go` (create) | Config, decoding, validation |
| `service/entityresolution/composite/v2/capability.go` (create) | Which subjects a source sees, which grants it may make |
| `service/entityresolution/composite/v2/token_claims.go` (create) | `token-claims` source (identity-core) |
| `service/entityresolution/composite/v2/evidence.go` (create) | Seal and open `arkavo_evidence` |
| `service/entityresolution/composite/v2/composite.go` (create) | The resolver: both RPCs, source fan-out, union |
| `service/entityresolution/composite/v2/constraints.go` (create) | Agent gate, device caps |
| `service/entityresolution/composite/v2/shadow.go` (create) | Legacy serves, composite compared and logged |
| `service/entityresolution/composite/v2/register.go` (create) | Build verifiers, sources and checker from config |
| `service/entityresolution/v2/entity_resolution.go` (modify) | Select composite / shadow / legacy |
| `examples/config/opentdf-patreon-composite.yaml` (create) | Deployable-shape example, `serve: shadow` |

## Plan Calls (decisions this plan makes that the spec left open)

- **Config shape.** The composite lives under `services.entityresolution.composite` with `serve: shadow | on`. Spec §7's "presence of `sources` selects the composite" has no room for "legacy serves, composite compares", which migration step 3 needs. Absent `composite` = legacy only.
- **Evidence encoding.** One string claim, `arkavo_evidence` = `base64url(payload JSON) "." base64url(HMAC-SHA256(key, "arkavo-evidence-v1" || 0x00 || payload JSON))`. An opaque string survives `structpb` untouched, so the second call verifies exactly the bytes the first sealed. Keys: `seal_key` (current, seals and opens) plus `previous_seal_keys` (open only), each base64 and at least 32 bytes decoded.
- **Invalid token on the token route** seals an evidence with no grants (outcome `_token: invalid`, expiry now + 60 s) rather than failing the RPC: a deny, not a 503.
- **Agent gate runs before the sources** for a gated subject; withholding everything before or after the union gives the same answer and skips source work.
- **The #96 filter goes into `passthroughResolution` itself,** so it also fixes legacy `patreon` mode the moment this ships. The spec's "id-shaped slug" shadow class therefore never occurs and is not classified.
- **identity-core is inert in phase 1.** `arkavo-creator` is not a definition in `examples/config/policy.patreon.yaml`, so its `publish` grant cannot synthesize and changes no decision. It is configured to prove the partition, and its grants are an expected shadow class (`identity_core`), which the spec's list omits.
- **The PEP allowlist holds the exact string** `ctxAuth.GetClientIDFromContext(ctx, true)` returns for arks. Prod derives client IDs from `arkavo_account_id` (`server.auth.policy.client_id_claim`), so the value comes from Task 1, not from the spec's `client:arks-media` guess. A missing or conflicting client ID is not allowlisted.

---

### Task 1: Pre-checks (read-only, prod)

**Files:** none changed. Record each answer in this plan's Rollout section, in the table there.

- [ ] **Step 1:** Read the deployed platform config on platform.arkavo.net. Record `services.entityresolution.mode` (expected `patreon`), `allow_direct_entitlements` (expected `true`) and `enforce_namespaced_entitlements` (expected unset or `false`).
- [ ] **Step 2:** Read the deployed tdf-iroh-s3 config on iroh.arkavo.net. Record the authz `protocol` (expected AuthZEN through arks).
- [ ] **Step 3:** Find arks's client ID as the platform sees it: the `client_id` attribute on the platform's log lines for a FairPlay licence decision. Record the exact string. It becomes `claims_chain_peps`.
- [ ] **Step 4:** Confirm the viewer token's `aud` includes `https://platform.arkavo.net`: a recent KAS rewrap that succeeded through the platform proves it (the platform's authn already requires that audience). Record the evidence (log line and time). Do not paste tokens into chat or logs.
- [ ] **Step 5:** Confirm standard-TDF rewraps reach this platform's KAS and ERS: arks `KAS_PROXY_MODE` and the platform log for `/kas.AccessService/Rewrap`. Record it.
- [ ] **Step 6:** If any answer differs from the expectation, stop and tell the owner before Task 2.

### Task 2: Verified claims from the CWT verifier

**Files:**
- Modify: `service/internal/auth/cwt_verifier.go` (`VerifyCWTSubjectToken`, around lines 198-259)
- Test: `service/internal/auth/cwt_verifier_test.go`

**Interfaces:**
- Produces: `func (v *CWTVerifier) VerifyCWTClaims(ctx context.Context, token string) (map[string]any, error)`. Same checks as `VerifyCWTSubjectToken` (signature against the cached key set, then `validateStandardClaims`), and it returns the `decodeCWTClaims` map, the same shape `DecodeClaimsFromToken` gives. `VerifyCWTSubjectToken` calls it and keeps its signature and behaviour.

- [ ] **Step 1: Write the failing tests**, built like `TestCWTVerifier_CustomClaimsRoundTrip` (same `newP256` / `signCWT` / key-set server):
  - `TestCWTVerifier_VerifyCWTClaims_ReturnsClaimsMap`: a token with custom `arkavo_entitlements: ["https://patreon.arkavo.com/attr/campaign/value/13167240"]` gives a map where `m["iss"] == issuer`, `m["sub"]` is set, and `m["arkavo_entitlements"]` is a `[]any` holding that one string.
  - `TestCWTVerifier_VerifyCWTClaims_RejectsWrongAudience`: error, nil map.
  - `TestCWTVerifier_VerifyCWTClaims_RejectsBadSignature`: a token signed by a key not in the set errors.
- [ ] **Step 2:** Run `go test ./internal/auth/ -run VerifyCWTClaims -v`. Expected: FAIL, `VerifyCWTClaims` undefined.
- [ ] **Step 3:** Implement `VerifyCWTClaims` by moving the body of `VerifyCWTSubjectToken` up to `validateStandardClaims` into it; `VerifyCWTSubjectToken` then builds its `jwt.Token` and unsigned JWT from the returned map.
- [ ] **Step 4:** Run `go test ./internal/auth/ -v`. Expected: PASS, including every existing `TestCWTVerifier_*`.
- [ ] **Step 5: Commit** `feat(auth): return verified CWT claims as a map`.

### Task 3: The source contract

**Files:**
- Create: `service/entityresolution/source/source.go`
- Test: `service/entityresolution/source/source_test.go`

**Interfaces:**
- Produces (package `source`):
  ```go
  type Kind string    // KindPerson "person", KindAgent "agent", KindDevice "device"
  type Trust int      // TrustNone (claims discarded), TrustPEP (allowlisted PEP's unsealed claims), TrustVerified (verified token or sealed evidence)
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
- `ParseFQN` is structural: lowercase the input, then require exactly `https://<ns>/attr/<def>/value/<value>` with every part non-empty and no further `/`. `ParseDefinition` requires exactly `https://<ns>/attr/<def>`.
- `KindOf`: `KindAgent` when `agentstatus.HasAgentMarker(claims)`; `KindDevice` when `arkavo_npe.type == "device"`; else `KindPerson`.

- [ ] **Step 1: Write the failing tests:**
  - `TestParseFQN` table: `https://patreon.arkavo.com/attr/campaign/value/13167240` → `{patreon.arkavo.com, campaign, 13167240}`; `HTTPS://Patreon.Arkavo.com/attr/Campaign/value/X1` → lowercased; rejected: no value segment, empty value (`…/value/`), `http://` scheme, `…/value/1/2`, `https://patreon.arkavo.com/attrs/campaign/value/1`. `https://patreon.arkavo.com.evil/attr/campaign/value/1` parses with namespace `patreon.arkavo.com.evil`.
  - `TestParseDefinition`: `https://patreon.arkavo.com/attr/campaign` ok; with a `/value/…` suffix → not ok.
  - `TestKindOf`: `{}` → person; `{"arkavo_npe": {"type": "device"}}` → device; `{"arkavo_npe": {"type": "agent"}}` → agent.
- [ ] **Step 2:** Run `go test ./entityresolution/source/ -v`. Expected: FAIL (package missing).
- [ ] **Step 3:** Implement `source.go`.
- [ ] **Step 4:** Run the same command. Expected: PASS.
- [ ] **Step 5: Commit** `feat(ers): source contract for composable entitlement resolution`.

### Task 4: Patreon token source, and the #96 filter

**Files:**
- Modify: `service/entityresolution/patreon/v2/passthrough.go` (the tier-slug loop in `passthroughResolution`)
- Create: `service/entityresolution/patreon/v2/source.go`
- Test: `service/entityresolution/patreon/v2/passthrough_test.go`, `service/entityresolution/patreon/v2/source_test.go`

**Interfaces:**
- Consumes: `source.*` (Task 3).
- Produces:
  ```go
  type SourceConfig struct {
      EntitlementsNamespace      string `mapstructure:"entitlements_namespace"` // default patreon.arkavo.com
      LegacyMembershipDerivation bool   `mapstructure:"legacy_membership_derivation"`
      InferUnknownAsFree         bool   `mapstructure:"infer_unknown_as_free"`
  }
  func NewTokenSource(cfg SourceConfig) source.Source
  ```
- `Resolve` grants the union of: (a) when `LegacyMembershipDerivation` and `parseArkavoPatreon` finds a claim, `passthroughResolution(...).entitlements`; (b) every string in `arkavo_entitlements` that `ParseFQN`s into the configured namespace with definition `campaign` (value all digits) or `campaign-tier` (value `^[0-9]+_[a-z0-9-]+$`). Grants carry actions `["read"]`. It never reads `role`. `Properties` is `membershipStruct(mem).AsMap()` from (a); with no claim and `InferUnknownAsFree`, the free view (`tier_slug: free`, `status: former`); otherwise nil. `Outcome`: `Complete` when it returns grants or properties, else `NotApplicable`.
- The #96 filter: in `passthroughResolution`, after `slugify`, skip a slug that is `tier-` followed by one or more digits. It applies only to title slugs, never to `arkavo_entitlements`, where `_tier-<id>` is legitimate.

- [ ] **Step 1: Write the failing tests:**
  - `TestPassthrough_IDShapedTitleSlugIsDropped` (passthrough_test.go): active membership `123` with `tier_slugs: ["Tier 10234567", "tier-x1", "tiers-9"]` → entitlements contain `…/campaign-tier/value/123_tier-x1` and `…/123_tiers-9`, and do not contain `…/123_tier-10234567`.
  - `TestTokenSource_CreatorTiersFromEntitlements`: claims `arkavo_patreon: {role: "creator", campaign_id: "13167240", memberships: []}` and `arkavo_entitlements` = campaign `13167240`, campaign-tier `13167240_supporter`, `13167240_free`, `13167240_tier-555`, plus `https://arkavo.ai/attr/tdf/value/decrypt` and `https://patreon.arkavo.com/attr/arkavo-creator/value/publish` → grant FQNs are exactly the four Patreon ones.
  - `TestTokenSource_ActivePatronUnionsLegacyAndEntitlements`: active membership `7237273`, `tier_slugs: ["Supporter"]`, and `arkavo_entitlements` = campaign `7237273`, `7237273_supporter`, `7237273_tier-42` → grant FQN set is exactly those three.
  - `TestTokenSource_LegacyDerivationOff`: the same membership, no `arkavo_entitlements`, `LegacyMembershipDerivation: false` → no grants.
  - `TestTokenSource_MalformedEntitlementsIgnored`: `arkavo_entitlements: [42, "HTTPS://PATREON.ARKAVO.COM/attr/campaign/value/7237273", "https://patreon.arkavo.com/attr/campaign/value/abc", "https://patreon.arkavo.com/attr/campaign-tier/value/7237273"]` → grants exactly `https://patreon.arkavo.com/attr/campaign/value/7237273`.
  - `TestTokenSource_NoClaimInfersFree`: empty claims, `InferUnknownAsFree: true` → no grants, `Properties["status"] == "former"`, `Properties["tier_slug"] == "free"`.
- [ ] **Step 2:** Run `go test ./entityresolution/patreon/v2/ -run 'IDShaped|TokenSource' -v`. Expected: FAIL.
- [ ] **Step 3:** Add the filter to `passthroughResolution` and implement `source.go`.
- [ ] **Step 4:** Run `go test ./entityresolution/patreon/v2/ -v`. Expected: PASS, existing tests included.
- [ ] **Step 5: Commit** `feat(patreon): token source for the composite ERS; drop id-shaped title slugs (#96)`.

### Task 5: Composite config, capabilities, identity-core source, exported agent gate

**Files:**
- Modify: `service/entityresolution/arkavo/v2/agent_gate.go`
- Create: `service/entityresolution/composite/v2/config.go`, `capability.go`, `token_claims.go`
- Test: `service/entityresolution/arkavo/v2/agent_gate_test.go`, `service/entityresolution/composite/v2/config_test.go`, `capability_test.go`, `token_claims_test.go`

**Interfaces:**
- Produces (arkavo): `func AgentDenial(ctx context.Context, checker agentstatus.Checker, claims map[string]any, ownerClaim string) (agentstatus.Subject, error)`. It parses the claims, builds the subject as `agentSubject` does, and returns nil for an ungated subject, `ReasonUnconfigured` for a nil checker, and recovers a checker panic as `checkStatus` does. The method `agentDenial` delegates to it.
- Produces (composite, package `composite`):
  ```go
  type Config struct {
      Serve       string            `mapstructure:"serve"`    // "shadow" | "on"
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
      Type          string         `mapstructure:"type"` // "patreon-token" | "token-claims"
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
  func DecodeConfig(in config.ServiceConfig) (cfg Config, present bool, err error) // reads in["composite"]; duration hook as arkavo's decodeConfig
  func (c Config) Validate() error

  type capability struct { issuer string; definitions map[string]bool; actions []string; subjects map[source.Kind]bool; pepAssertable bool }
  func newCapability(sc SourceConfig) capability
  func (c capability) admits(s source.Subject) bool // kind allowed, and: TrustVerified → claims iss == issuer; TrustPEP → pepAssertable && iss == issuer; TrustNone → true (claims are empty)
  func (c capability) allows(g source.Grant) bool   // ParseFQN ok, its DefinitionFQN owned, every action in c.actions

  func newTokenClaimsSource(claim string, definitions []string) source.Source // Options["claim"]; selects string entries in its own definitions, lowercased
  ```

- [ ] **Step 1: Write the failing tests:**
  - `TestAgentDenial_PersonIsNeverGated` and `TestAgentDenial_UnconfiguredWithholdsAgent` (agent claims as in `TestAgentGate_ThroughTheV2PDP`, nil checker → `*agentstatus.DenialError` with `Reason == agentstatus.ReasonUnconfigured`).
  - `TestValidate` table, each case one error: `serve` not `shadow`/`on`; no issuers; an issuer without `cose_keys_url` or `audience`; empty `seal_key`; a seal key under 32 bytes; a previous key that isn't base64; a source with empty ID, a duplicate ID, or an unknown type; a grant that is not a definition FQN; a source issuer not among `evidence.issuers`; **shared definition** (two sources list `https://patreon.arkavo.com/attr/campaign`; the error names both IDs); a `device_class_caps` entry that is not a value FQN. Plus one valid config (the shape in Task 10's example) → nil.
  - `TestDecodeConfig_AbsentIsNotPresent`: a map without `composite` → `present == false`, no error. `TestDecodeConfig_DurationString`: `deadline: "250ms"` → 250 ms.
  - `TestCapability_Admits` table: verified with matching iss → true; verified with other iss → false; PEP with `pepAssertable` false → false; PEP with true and no `iss` → false; kind not listed → false; TrustNone → true.
  - `TestCapability_Allows`: owned definition → true; other definition → false; unparseable → false; action `write` when only `read` is allowed → false.
  - `TestTokenClaimsSource_SelectsOwnDefinitions`: claim `arkavo_entitlements` with a campaign FQN, `https://patreon.arkavo.com/attr/arkavo-creator/value/publish` and a non-string → grants exactly the `arkavo-creator` one when that is its definition.
- [ ] **Step 2:** Run `go test ./entityresolution/arkavo/v2/ ./entityresolution/composite/v2/ -v`. Expected: FAIL.
- [ ] **Step 3:** Implement.
- [ ] **Step 4:** Run the same command. Expected: PASS, existing arkavo tests included.
- [ ] **Step 5: Commit** `feat(ers): composite config, capabilities and token-claims source`.

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
  Encoding is in Plan Calls.

- [ ] **Step 1: Write the failing tests:** `TestEvidence_RoundTrip`; `TestEvidence_TamperedPayloadRejected` (change one byte of the payload part); `TestEvidence_WrongKeyRejected`; `TestEvidence_PreviousKeyStillOpens` (sealed with the old key, opened with `[new, old]`); `TestEvidence_ExpiredRejected`; `TestEvidence_ExpiredGrantDropped`; `TestEvidence_SurvivesStructpb` (put the string in `structpb.NewStruct`, read it back through `AsMap`, open it).
- [ ] **Step 2:** Run `go test ./entityresolution/composite/v2/ -run Evidence -v`. Expected: FAIL.
- [ ] **Step 3:** Implement.
- [ ] **Step 4:** Run the same command. Expected: PASS.
- [ ] **Step 5: Commit** `feat(ers): seal composite evidence between the two ERS calls`.

### Task 7: Composite token route, with constraints

**Files:**
- Create: `service/entityresolution/composite/v2/composite.go`, `constraints.go`
- Test: `service/entityresolution/composite/v2/composite_token_test.go`, `constraints_test.go`, `helpers_test.go` (fake verifier, fake sources, `newTestService`, which sets `Tracer = noop.NewTracerProvider().Tracer("test")` as the patreon and arkavo tests do)

**Interfaces:**
- Consumes: Tasks 3-6; `arkavo.AgentDenial`; `auth.DecodeCWTClaimsFromToken` (to read `iss` before choosing a verifier).
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
  func (s *Service) resolveToken(ctx context.Context, raw string, q source.Query) (evidence, map[string]any) // verified claims (nil when invalid) are returned for the shadow
  func (s *Service) resolveSubject(ctx context.Context, subj source.Subject, q source.Query, exp time.Time) evidence
  func (s *Service) withheldAgent(ctx context.Context, subj source.Subject) bool // gated subject denied by AgentDenial(s.agentStatus, claims, "arkavo_account_id"); logs the reason
  func capGrants(caps map[string]map[string]bool, subj source.Subject, grants []sealedGrant) []sealedGrant // device subjects only; class from arkavo_npe.class, default "unverified"
  ```
- Token handling: read `iss` from the unverified decode, pick that issuer's verifier, verify, and require `exp`. Any failure seals an evidence with no grants (Plan Calls). The subject is `TrustVerified`, `KindOf(claims)`, `AccountID` from `arkavo_account_id`. `Query.Resources` are the request's `Resource_AttributeValues` FQNs; `Action` is `read`.
- `resolveSubject`: if `withheldAgent`, return no grants and no props. Otherwise run each admitted source in its own goroutine under `context.WithTimeout(cfg.Deadline)`. A source that errors, panics or misses the deadline is `Unavailable` and contributes nothing. Drop and `Warn`-log grants its capability doesn't allow, with the source ID. Union by FQN (merge actions, keep the first source as provenance). Apply `capGrants`. Props go under each source's `PropertiesKey` when non-empty.
- The chain returned per token is one `Entity_Claims` subject entity `{arkavo_evidence: <sealed>}`, `EphemeralId` `composite-subject`, `Category` subject.

- [ ] **Step 1: Write the failing tests** (open the sealed claim from the returned chain to assert):
  - `TestTokenRoute_CreatorGetsOwnCampaignTiers`: real `patreon.NewTokenSource` (legacy derivation on, infer on, `properties_key: patreon`) plus identity-core; creator claims as in Task 4 → grants include `campaign/13167240`, `campaign-tier/13167240_supporter` and `13167240_free`; `Props["patreon"]` is present.
  - `TestTokenRoute_SourceCannotGrantOutsideCapability`: a fake source owning `https://example.com/attr/a` returns `…/campaign/value/1` → absent.
  - `TestTokenRoute_SlowSourceIsUnavailable`: deadline 50 ms, a fake source sleeps 1 s → returns in under 500 ms, its outcome is `unavailable`, the other source's grants are present.
  - `TestTokenRoute_SourceErrorAndPanicAreUnavailable`.
  - `TestTokenRoute_InvalidTokenSealsNoGrants`: the verifier errors → no RPC error, no grants, `Outcomes["_token"] == invalid`.
  - `TestTokenRoute_MissingExpIsInvalid` and `TestTokenRoute_UnknownIssuerIsInvalid`.
  - `TestTokenRoute_EvidenceExpiryIsTokenExpiry`.
  - `TestTokenRoute_SourceOrderIsIrrelevant`: the same two sources in both orders → equal grant sets.
  - `TestAgentWithheldWhenStatusUnset`: agent claims carrying entitlements a source would grant, nil checker → no grants.
  - `TestAgentAdmittedWhenEligible`: a checker that returns nil → grants present.
  - `TestDeviceCaps_MissingClassIsNoCap` and `TestDeviceCaps_IntersectNeverAdds`: the cap lists one FQN the person holds and one they don't → only the held one survives, the other is not added.
- [ ] **Step 2:** Run `go test ./entityresolution/composite/v2/ -run 'TokenRoute|Agent|DeviceCaps' -v`. Expected: FAIL.
- [ ] **Step 3:** Implement.
- [ ] **Step 4:** Run `go test -race ./entityresolution/composite/v2/ -v`. Expected: PASS.
- [ ] **Step 5: Commit** `feat(ers): composite token route with constraints`.

### Task 8: Composite `ResolveEntities`, and the creator acceptance test

**Files:**
- Modify: `service/entityresolution/composite/v2/composite.go`
- Test: `service/entityresolution/composite/v2/composite_resolve_test.go`, `decision_test.go`

**Interfaces:**
- Produces: `func (s *Service) ResolveEntities(ctx context.Context, req *connect.Request[entityresolutionV2.ResolveEntitiesRequest]) (*connect.Response[entityresolutionV2.ResolveEntitiesResponse], error)` and `func (s *Service) resolveEntity(ctx context.Context, e *entity.Entity) evidence` (also used by the shadow).
- Per entity:
  - A claims entity whose `arkavo_evidence` is a string → `openEvidence`. On failure: a representation with no grants and no props, `Warn` log. Never treated as PEP-asserted.
  - A claims entity without it → `TrustPEP` with its claims when `ctxAuth.GetClientIDFromContext(ctx, true)` succeeds and the ID is in `claims_chain_peps`; otherwise `TrustNone` with empty claims.
  - Any other entity type → `TrustNone` with empty claims.
  - The representation's `OriginalId` is the ephemeral ID, or `ent.EntityIDPrefix + index`. `AdditionalProps` is one struct of `{propertiesKey: props}`, omitted when empty. `DirectEntitlements` are the grants.

- [ ] **Step 1: Write the failing tests:**
  - `TestResolve_SealedEvidenceBecomesRepresentation`.
  - `TestResolve_ForgedSealGrantsNothing`: from an allowlisted client ID → no grants.
  - `TestResolve_PEPChainFromAllowlistedClient`: ctx `metadata.NewIncomingContext(ctx, metadata.Pairs(ctxAuth.ClientIDKey, "arks-test"))`; claims `{sub, iss, arkavo_patreon (creator, 13167240), arkavo_entitlements: [campaign 13167240, campaign-tier 13167240_supporter, arkavo-creator/value/publish]}` → grants are the two Patreon FQNs; `publish` is absent because identity-core isn't `pep_assertable`.
  - `TestResolve_PEPChainFromOtherClientGrantsNothing`: subtests for another client ID, no metadata, and two conflicting `client_id` values.
  - `TestResolve_PEPChainWithoutIssGrantsNothing`.
  - `TestResolve_NonClaimsEntityGetsFreeView`: a `UserName` entity → no grants, `patreon.status == "former"`.
  - `TestCreatorPermitted_ThroughTheV2PDP` (`decision_test.go`, harness copied from `arkavo/v2/agent_gate_decision_test.go`: `inProcessERS`, `access.NewJustInTimePDP(ctx, logger.CreateTestLogger(), sdk, store, true, false)`, `filestore.NewStoreFromFile("../../../../examples/config/policy.patreon.yaml")`, `audit.ContextWithActorID`). The resource is `[https://patreon.arkavo.com/attr/campaign/value/13167240, https://patreon.arkavo.com/attr/campaign-tier/value/13167240_supporter]`. Subtests:
    - `licence and KAS: creator token` → `AllPermitted`;
    - `catalog: creator claims from the allowlisted PEP` → `AllPermitted`;
    - `catalog: same claims from another client` → denied;
    - `cross-campaign: patron of 7237273 only` → denied;
    - `declined and former patrons of 13167240` (memberships only, no `arkavo_entitlements`) → denied;
    - `parity: active patron of 13167240 with tier supporter, token route` → permitted.
- [ ] **Step 2:** Run `go test ./entityresolution/composite/v2/ -run 'Resolve|ThroughTheV2PDP' -v`. Expected: FAIL.
- [ ] **Step 3:** Implement.
- [ ] **Step 4:** Run `go test -race ./entityresolution/composite/v2/ -v`. Expected: PASS.
- [ ] **Step 5: Commit** `feat(ers): composite ResolveEntities; creator permitted on every route`.

### Task 9: Shadow

**Files:**
- Create: `service/entityresolution/composite/v2/shadow.go`
- Test: `service/entityresolution/composite/v2/shadow_test.go`

**Interfaces:**
- Consumes: `entityresolutionv2connect.EntityResolutionServiceHandler` (the legacy `patreon` service), `(*Service).resolveToken`, `(*Service).resolveEntity`.
- Produces:
  ```go
  type Shadow struct { trace.Tracer /* legacy handler, composite *Service, logger */ }
  func NewShadow(legacy entityresolutionv2connect.EntityResolutionServiceHandler, composite *Service, log *logger.Logger) *Shadow
  // Both RPCs return the legacy response and error unchanged.
  func differences(legacy, composite []string) (onlyLegacy, onlyComposite []string) // lowercased set difference
  func classify(fqn, onlyIn string, claims map[string]any, tokenOutcome source.Outcome, owners map[string]string /* definition → source type */) string
  func callerClientID(ctx context.Context, peps map[string]bool) (id string, allowlisted bool) // "none" / "conflict" on ErrNoMetadataFound / ErrConflictClientID
  ```
- **Token route:** after legacy `CreateEntityChainsFromTokens`, the legacy grant set is legacy `ResolveEntities` on the returned chain's subject entities, called in-process. The composite set is `resolveToken`. Compare them.
- **Claims route:** compare legacy `ResolveEntities` with `resolveEntity` per entity, matched by `OriginalId`.
- Comparison runs synchronously, under the composite deadline and with `recover`. A composite failure logs class `composite_error`, and never changes the response.
- One `Info` line `ers shadow difference` per FQN, with `route` (`token` | `claims`), `class`, `fqn`, `only_in` and `sub`. On the claims route, also `client_id` (the value `GetClientIDFromContext(ctx, true)` returned inside the ERS, or `none` / `conflict`) and `pep_allowlisted`. Task 1 reads the client ID at the authn layer; this confirms the ERS sees the same string before the switch.
- Classes, first match wins:
  1. `token_invalid`: the token outcome is `invalid`.
  2. `creator_own_campaign`: only in the composite, definition `campaign` or `campaign-tier`, and the campaign ID equals `arkavo_patreon.campaign_id`.
  3. `tier_id_form`: only in the composite, a `campaign-tier` value matching `^[0-9]+_tier-[0-9]+$`.
  4. `identity_core`: only in the composite, a definition owned by a `token-claims` source.
  5. `unexpected`: anything else. This blocks the switch.

- [ ] **Step 1: Write the failing tests:** `TestShadow_ServesLegacyResponseUnchanged` (both RPCs, `proto.Equal` with a direct legacy call); `TestShadow_CompositePanicDoesNotAffectResponse`; `TestDifferences`; `TestClassify` table with one row per class; `TestCallerClientID` table for the `client_id` attribute: one allowlisted ID → (`arks-test`, true), another → (its value, false), no metadata → (`none`, false), two values → (`conflict`, false).
- [ ] **Step 2:** Run `go test ./entityresolution/composite/v2/ -run 'Shadow|Differences|Classify' -v`. Expected: FAIL.
- [ ] **Step 3:** Implement.
- [ ] **Step 4:** Run the same command. Expected: PASS.
- [ ] **Step 5: Commit** `feat(ers): shadow the composite against legacy patreon mode`.

### Task 10: Registration and example config

**Files:**
- Create: `service/entityresolution/composite/v2/register.go`, `examples/config/opentdf-patreon-composite.yaml`
- Modify: `service/entityresolution/v2/entity_resolution.go` (`RegisterFunc`)
- Test: `service/entityresolution/composite/v2/register_test.go`

**Interfaces:**
- Produces: `func Register(in config.ServiceConfig, log *logger.Logger, legacy entityresolutionv2connect.EntityResolutionServiceHandler) (entityresolutionv2connect.EntityResolutionServiceHandler, error)`. It `DecodeConfig`s and `Validate`s; builds one `auth.NewCWTVerifier` per issuer (ES256, with that issuer's audience); builds sources from `sourceFactories map[string]func(SourceConfig) (source.Source, error)` (`patreon-token` decodes `Options` into `patreon.SourceConfig`; `token-claims` reads `Options["claim"]`); builds `agentstatus.New` when `constraints.agent_status` is enabled. It returns `*Service` for `serve: on`, and `NewShadow(legacy, svc, log)` for `serve: shadow`, which needs a non-nil legacy.
- `RegisterFunc`: decode `composite` first.
  - Absent: today's switch, unchanged.
  - `serve: on`: don't build a legacy handler.
  - `serve: shadow`: require `mode: patreon` (fatal otherwise), build it as today, and pass it in.
  - Set `Tracer` on what's returned; a `Register` error is fatal, as other config errors are.
- The example is `opentdf-patreon-prod.yaml` plus a `composite:` block in the spec §7 shape and these Plan Calls:
  - `serve: shadow`;
  - `seal_key: ""` with a comment that the deployment supplies it as a secret;
  - `claims_chain_peps` set to the Task 1 value;
  - sources `patreon` (`patreon-token`, `pep_assertable: true`, `properties_key: patreon`, `legacy_membership_derivation: true`, `infer_unknown_as_free: true`) and `identity-core` (`token-claims`, `claim: arkavo_entitlements`, grants `https://patreon.arkavo.com/attr/arkavo-creator`);
  - `constraints.agent_status` unset, and `device_class_caps: {}`.

- [ ] **Step 1: Write the failing tests:**
  - `TestRegister_ServeOnReturnsComposite`;
  - `TestRegister_ShadowNeedsLegacy`;
  - `TestRegister_RejectsInvalidConfig` (shared definition);
  - `TestExampleConfigValidates`: load the example YAML, take `services.entityresolution`, set a 32-byte test `seal_key`, then `DecodeConfig` and `Validate` → nil.
  - Use an unreachable `cose_keys_url`: `NewCWTVerifier` only warns.
- [ ] **Step 2:** Run `go test ./entityresolution/composite/v2/ -run 'Register|Example' -v`. Expected: FAIL.
- [ ] **Step 3:** Implement `register.go`, the `RegisterFunc` change and the example.
- [ ] **Step 4:** Run `go test -race ./entityresolution/... ./internal/auth/... && go build ./...`. Expected: PASS and a clean build.
- [ ] **Step 5: Commit** `feat(ers): register the composite resolver (serve: shadow | on)`.

---

## Rollout (owner approves each prod step)

| Pre-check (Task 1) | Expected | Found |
|---|---|---|
| Platform ERS `mode` | `patreon` | |
| `allow_direct_entitlements` / `enforce_namespaced_entitlements` | `true` / off | |
| Catalog node authz protocol | AuthZEN via arks | |
| arks client ID at the platform | (exact string) | |
| Viewer token `aud` has `https://platform.arkavo.net` | yes | |
| Standard-TDF rewrap reaches this platform | yes | |

1. **arks first.** Deploy the companion arkavo-rs plan. It's inert under `patreon` mode, which never reads `arkavo_entitlements`.
2. **Shadow.** Deploy this branch with `composite.serve: shadow`, the real `seal_key` and the Task 1 `claims_chain_peps`. Exercise every route: a creator Play, a patron Play, a KAS rewrap, and the catalog index for the creator and for a patron. Read the `ers shadow difference` lines. Only `creator_own_campaign`, `tier_id_form` and `identity_core` may appear; any `unexpected`, `token_invalid` or `composite_error` blocks step 3.
3. **Switch all three routes together:** `serve: on`. Verify that the creator account on the iPhone lists, downloads and plays its own campaign's recording, and that a patron still plays theirs. Rollback is `serve: shadow`.
4. **Later:** remove `mode`, and `legacy_membership_derivation` once telemetry shows no token relies on memberships alone (spec §8 step 5).

**Owner follow-ups, not code:**
- Add the forwarded `arkavo_entitlements` subject property to draft-arkavo-authzen-cwt-00.
- arkavo-ios ADR-0058 still says a creator's token lacks tier values.
