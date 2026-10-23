# Device Rules in Policy Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Devices in a decision narrow the person's grants by rules the policy file declares (`device_rules`). A device's class and app count only from a verified DeviceCheck token bound to the person. This replaces #61's `device_class_caps`.

**Architecture:**
- **New package `service/internal/chaindevice`** holds:
  - the device marker (the composite writes it, the PDP reads it);
  - the rule set and its single evaluator `Rules.Keeps`, which both decision routes call.
- **The file store** parses and validates `device_rules` into a `*chaindevice.Rules`, and exposes it as an optional store capability.
- **The composite ERS:**
  - verifies device tokens that arrive in a claims entity;
  - binds each device to the chain's subjects by `iss` and `arkavo_account_id`;
  - splits a DeviceCheck token used as the subject into a person plus a sealed device.

**Tech Stack:** Go; Connect RPC; protobuf `structpb`; `go-cose`/CBOR CWTs; YAML file store; testify.

**Spec:** `docs/superpowers/specs/2026-10-23-device-rules-in-policy-design.md`

**Branch:** `fix/chain-device-constraints` (PR #61). Commits go on this branch.

## Global Constraints

- After every task:
  - `golangci-lint run <changed packages>` reports 0 issues;
  - `go test` passes for the changed packages;
  - `~/go/bin/gofumpt -w` has been run on the changed Go files.
- Commits use Conventional Commits with `git commit -s`. End every message with:
  ```
  Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>
  Claude-Session: https://claude.ai/code/session_01BVcbNv49aHGvjcShJmioeo
  ```
- `gh` writes always pass `--repo arkavo-org/opentdf-platform`, or the repo they target.
- Leave the untracked files `lib/ocrypto/ec_key_pair.swift`, `sdk/nanotdf.swift` and `message.txt` alone.
- Reserved names:
  - marker key `arkavo_device` (`chaindevice.PropKey`);
  - device-token claim `arkavo_device_token` (`chaindevice.TokenClaim`);
  - device classes `attested`, `managed`, `unverified`;
  - app environments `production`, `development`.
- Policy FQN matching is case-insensitive:
  - a value FQN matches exactly;
  - a definition FQN matches every `<def>/value/<v>`;
  - a hierarchy value never covers the values below it.
- Fail toward fewer grants. These all read as class `unverified`, unbound, with no app:
  - a malformed marker;
  - an unverified token;
  - a PEP-claims device.
- An unbound device makes `Keeps` false for every FQN.
- `examples/config/policy.patreon.yaml` gets no `device_rules` in this change.

## Review Focus

1. **One person, two devices, one of them unbound.** The whole decision denies, on both routes. Task 4 pins it with `TestBind_OneUnboundDeviceDeniesAll`; Task 6 checks it end to end.
2. **A DeviceCheck token whose `aud` is a plain string `arkavo:devicecheck`, with no platform audience, used as the subject.** After the split, the person's claims have no `aud`. They must still resolve as a person, not a device or an agent. Task 5 covers it in `TestSplit_StringAudience`.
3. **A cap whose class is misspelled (`atested`).** It would never apply, which fails open, so it must fail the policy load. Task 2: `TestDeviceRules_UnknownClassFailsLoad`.
4. **A definition FQN that is a prefix of another definition** (`…/attr/campaign` vs `…/attr/campaign-tier`). The campaign rule must not match tier values. Task 1: `TestMatch_DefinitionIsNotAPrefix`.
5. **Old sealed evidence after the deploy:** a v1 payload with no `iss`, `account_id` or `device`. It opens with no device, so a subject that was minted before the deploy and travels with a device token never binds, and that decision denies until the token is re-minted. Task 4 pins this in `TestBind_EvidenceWithoutIdentityNeverBinds`.

---

### Task 1: `chaindevice` package: marker, rules, evaluator

**Files:**
- Create: `service/internal/chaindevice/device.go` (marker), `service/internal/chaindevice/rules.go` (rules, matching, `Keeps`, `AppIDHash`)
- Test: `service/internal/chaindevice/device_test.go`, `service/internal/chaindevice/rules_test.go`

**Interfaces:**
- Produces:
  ```go
  const (
      PropKey    = "arkavo_device"
      TokenClaim = "arkavo_device_token"
      KindDevice = "device"
      ClassAttested, ClassManaged, ClassUnverified = "attested", "managed", "unverified"
      EnvProduction, EnvDevelopment = "production", "development"
  )
  var Classes = []string{ClassAttested, ClassManaged, ClassUnverified}
  type Device struct {
      Class     string
      Verified  bool
      Bound     bool
      AppIDHash string // lowercase hex SHA-256 of <TeamID>.<BundleID>; "" = no app
      AppEnv    string // "" = unknown
  }
  func (d Device) Props() map[string]any       // {"kind","class","verified","bound","app_id_hash","app_env"}
  func FromRepresentation(rep *entityresolutionV2.EntityRepresentation) (Device, bool)
  type Requirement struct {
      Grants        []string // lowercased value or definition FQNs
      DeviceClasses []string
      AppIDHashes   []string // nil = any app
      AppEnvs       []string // nil = any env
  }
  type Cap struct {
      DeviceClass string
      Keeps       []string // lowercased value or definition FQNs
  }
  type Rules struct {
      Requirements []Requirement
      Caps         []Cap
  }
  func (r *Rules) Keeps(devices []Device, fqn string) bool // nil r allowed
  func (r *Rules) Narrows(devices []Device) bool          // true when Keeps could drop anything
  func Matches(pattern, fqn string) bool
  func AppIDHash(appID string) string
  ```

- [ ] **Step 1: Write failing tests**

  In `device_test.go`:
  - `TestDevice_RoundTrip`: `FromRepresentation` of a rep whose `AdditionalProps[0][PropKey]` is `Device{Class:"attested",Verified:true,Bound:true,AppIDHash:"ab",AppEnv:"production"}.Props()` returns that device, `true`.
  - `TestDevice_Malformed`: these each return `Device{Class:"unverified"}, true`:
    - a non-struct value under `PropKey`;
    - `kind` missing;
    - `bound` not a bool;
    - `verified` not a bool.

    `kind` missing means the value is a device-shaped struct without `kind`, under `PropKey`.
  - `TestDevice_UnverifiedNeverBound`: props with `verified:false, bound:true, class:"attested"` read as `Device{Class:"unverified"}`.
  - `TestDevice_Absent`: a rep with no `PropKey` returns `false`.

  In `rules_test.go`:
  - `TestMatch_ValueAndDefinition`: `Matches(publish, publish)`, `Matches(campaignDef, campaignDef+"/value/13167240")` and the uppercase variants are all true.
  - `TestMatch_DefinitionIsNotAPrefix`: `Matches("https://patreon.arkavo.com/attr/campaign", "https://patreon.arkavo.com/attr/campaign-tier/value/x")` is false.
  - `TestMatch_ValueDoesNotCoverOthers`: `Matches(defFQN+"/value/vip", defFQN+"/value/paid")` is false.
  - `TestAppIDHash`:
    - `AppIDHash("M8GS7ZT95Y.com.arkavo.Arkavo") == "543398d88f303adedb67445ee9edbf1e1733a73d92bf6992cfbf228d60763cf8"`
    - `AppIDHash("M8GS7ZT95Y.com.arkavo.ArkavoCreator") == "ea2defc9e7bf14b832b0fb5e4ada8f0af0e114dca9fc7741cda17d875cf1bc01"`
  - `TestKeeps_PublishRule`, table-driven. The rule is publish requires attested, both app hashes, and `production`. Rows (devices → `Keeps(devices, publish)`):

    | Devices | Result |
    |---|---|
    | none | false |
    | attested, bound, listed app, production | true |
    | managed, otherwise same | false |
    | attested, `development` | false |
    | attested, `AppIDHash: ""` | false |
    | attested, unlisted hash | false |
    | managed and attested-production, both bound | true (any one device meets it) |

    In every row, `Keeps(devices, campaignValue)` (not required) is true unless a device is unbound.
  - `TestKeeps_Caps`: the cap `managed → [campaignDef, tierDef]`.
    - A managed device keeps `campaignValue` and `tierValue` and drops `decryptValue`.
    - An attested device (no cap) keeps all three.
    - Two caps intersect: `managed → [campaignDef]` and `attested → [tierDef]`, with both devices present, keep nothing.
  - `TestKeeps_UnboundDeniesAll`: with `(*Rules)(nil)` and with an empty `&Rules{}`, a device with `Bound:false` makes `Keeps` false for any FQN. With no devices, `Keeps` is true.
  - `TestNarrows`:
    - nil rules and no devices → false;
    - any requirement → true;
    - a device present → true.

- [ ] **Step 2: Run them; they fail to compile**

  Run: `go test ./service/internal/chaindevice/...`
  Expected: build failure (undefined).

- [ ] **Step 3: Implement**
  - `Matches` lowercases both sides; then it's equality, or `strings.HasPrefix(fqn, pattern+"/value/")`.
  - `FromRepresentation` reads the first `AdditionalProps` struct carrying `PropKey`. Every malformed shape gives `Device{Class: ClassUnverified}`, and `Verified=false` forces the same.
  - `Keeps`:
    1. any unbound device → false;
    2. every requirement whose `Grants` match `fqn` needs at least one device meeting class, app and env;
    3. every device whose class has a cap must have `fqn` matched by its `Keeps`.

    A nil `r` runs step 1 only.
  - `AppIDHash` is `hex.EncodeToString(sha256.Sum256([]byte(appID)))`.
  - The package doc comment states the contract: the composite writes the marker, the PDP reads it only from a representation, and a device narrows but never grants.

- [ ] **Step 4: Run tests; they pass**

  Run: `go test ./service/internal/chaindevice/... && golangci-lint run ./service/internal/chaindevice/...`
  Expected: `ok`, 0 issues.

- [ ] **Step 5: Commit**: `feat(authz): chaindevice package for device markers and policy device rules`

---

### Task 2: File store loads and validates `device_rules`

**Files:**
- Modify: `service/policy/filestore/schema.go` (add the `DeviceRules` field and its types)
- Modify: `service/policy/filestore/store.go`:
  - `builder.build()` calls a new `buildDeviceRules()` after `buildAttributes`;
  - `Store` gains a `deviceRules` field and a `DeviceRules()` method.
- Create: `service/policy/filestore/device_rules.go`, which holds `buildDeviceRules`.
- Test: `service/policy/filestore/device_rules_test.go`

**Interfaces:**
- Consumes: `chaindevice.Rules`, `Requirement`, `Cap`, `AppIDHash`, `Classes`, `EnvProduction`, `EnvDevelopment` (Task 1).
- Produces:
  ```go
  // schema.go
  DeviceRules *DeviceRulesDef `yaml:"device_rules" json:"device_rules"`
  type DeviceRulesDef struct {
      Requirements []DeviceRequirementDef `yaml:"requirements" json:"requirements"`
      Caps         []DeviceCapDef         `yaml:"caps" json:"caps"`
  }
  type DeviceRequirementDef struct {
      Grants        []string `yaml:"grants" json:"grants"`
      DeviceClasses []string `yaml:"device_classes" json:"device_classes"`
      Apps          []string `yaml:"apps" json:"apps"`
      AppEnvs       []string `yaml:"app_envs" json:"app_envs"`
  }
  type DeviceCapDef struct {
      DeviceClass string   `yaml:"device_class" json:"device_class"`
      Keeps       []string `yaml:"keeps" json:"keeps"`
  }
  // store.go
  func (s *Store) DeviceRules() *chaindevice.Rules // nil when the file declares none
  ```

- [ ] **Step 1: Write failing tests.** Build each test's schema inline: one namespace `patreon.arkavo.com` with these attributes:
  - `arkavo-creator` (anyOf, value `publish`);
  - `campaign` (anyOf, no values);
  - `campaign-tier` (anyOf, no values);
  - `classification` (hierarchy, values `public`, `vip`).

  Tests:
  - `TestDeviceRules_Loads`: the spec's §3 YAML block loads, with both app IDs and `app_envs: [production]`.
    - `DeviceRules().Requirements[0].AppIDHashes` equals the two hashes pinned in Task 1.
    - `Grants` are lowercased.
    - `Caps[0].Keeps` holds both definition FQNs.
  - `TestDeviceRules_NoneDeclared`: a schema without `device_rules` gives `DeviceRules() == nil`.
  - `TestDeviceRules_RejectsAtLoad`, table-driven. Each row fails `NewStore`, and the error names the offending entry:
    - FQN doesn't parse (`https://x/attrs/y`);
    - undeclared definition (`…/attr/nope`);
    - undeclared value under a definition with declared values (`…/arkavo-creator/value/pubish`);
    - hierarchy attribute (`…/classification/value/vip` in grants, or `…/classification` in keeps);
    - empty `device_classes`;
    - unknown class `atested`, in a requirement and separately in a cap (`TestDeviceRules_UnknownClassFailsLoad` is this row);
    - two caps for `managed`;
    - app `com.arkavo.Arkavo` with no Team ID;
    - app `M8GS7ZT95Y.` with an empty bundle;
    - app env `prod`;
    - `apps: []` (present but empty);
    - `app_envs: []`.
  - `TestDeviceRules_SyntheticValueAccepted`: `…/campaign/value/13167240` in grants loads, because `campaign` declares no values.

- [ ] **Step 2: Run; they fail.** Run `go test ./service/policy/filestore/ -run TestDeviceRules`. Expected: build failure.

- [ ] **Step 3: Implement `buildDeviceRules`.**
  - Check against `b.attributesByFQN` and `b.valuesByFQN`.
  - A Team ID is exactly 10 characters from `[A-Z0-9]`, then `.`, then a non-empty bundle.
  - Distinguish a missing list from an empty one by `nil` versus `len == 0` (yaml.v3 decodes `[]` to an empty non-nil slice).
  - Error prefix: `filestore: device_rules: `.

- [ ] **Step 4: Run.** `go test ./service/policy/filestore/... && golangci-lint run ./service/policy/filestore/...`. Expected: pass, 0 issues.

- [ ] **Step 5: Commit**: `feat(policy): file store declares device_rules`

---

### Task 3: PDP applies rules to devices on both routes

**Files:**
- Modify: `service/internal/access/v2/policy_store.go`: add the `DeviceRuleSource` interface.
- Modify: `service/internal/access/v2/just_in_time_pdp.go`:
  - the `JustInTimePDP` struct gets a `deviceRules` field, detected next to `SubjectMappingMatcher` (~line 84);
  - `resolvedChain`, `resolveEntitiesFromEntityChain` and `narrowEntityEntitlements` change.
- Modify: `service/internal/access/v2/pdp.go`:
  - `getDecision`'s signature changes;
  - the narrowing block (~line 555) changes;
  - the exported `GetDecision` passes `nil, nil`.
- Test: `service/internal/access/v2/pdp_test.go` (new suite methods), `service/internal/access/v2/just_in_time_pdp_device_test.go` (new)
- Modify: `service/entityresolution/composite/v2/decision_test.go`. Delete `TestChainDevices_ThroughTheV2PDP`, which depended on `device_class_caps` caps; Task 6 replaces it. Keep `TestChainDevices_NonClaimsEnvironmentNeverReachesTheERS`.

**Interfaces:**
- Consumes: `chaindevice.Device`, `FromRepresentation`, `(*Rules).Keeps`, `(*Rules).Narrows` (Task 1).
- Produces:
  ```go
  type DeviceRuleSource interface{ DeviceRules() *chaindevice.Rules }
  type resolvedChain struct {
      subjects []*entityresolutionV2.EntityRepresentation
      devices  []chaindevice.Device
  }
  func (p *PolicyDecisionPoint) getDecision(ctx, rep, action, resources, rules *chaindevice.Rules, devices []chaindevice.Device) (*Decision, map[string][]*policy.Action, error)
  func narrowEntityEntitlements(entitlements []*authzV2.EntityEntitlements, rules *chaindevice.Rules, devices []chaindevice.Device)
  ```
- Partitioning, in `resolveEntitiesFromEntityChain`:
  - a subject representation is a subject, and its marker, if any, is also a device;
  - an environment representation with a marker is a device;
  - other environment representations are skipped.

- [ ] **Step 1: Write failing tests.**
  - In `pdp_test.go`, `Test_GetDecision_DeviceRules` (suite method). It uses a rep with direct entitlements `publish` and `campaign` and the suite's direct-entitlements PDP. Rule: publish requires attested.
    - No devices: publish denied, campaign permitted.
    - Attested bound device: both permitted.
    - Unbound device: both denied.
    - `rules == nil` with no devices: both permitted.
  - In `just_in_time_pdp_device_test.go`, `TestResolveChain_PartitionsDevices`. Use a stub `EntityResolutionV2` client returning fixed reps:
    - subject rep with no marker → 1 subject, 0 devices;
    - subject rep with a bound marker → 1 subject, 1 device;
    - env rep with a marker → 1 device;
    - env rep without a marker → skipped.
  - `TestNarrowEntityEntitlements_Rules`: the same publish rule applied to an `EntityEntitlements` map drops `publish` and keeps `campaign` when there are no devices.

- [ ] **Step 2: Run; they fail to compile.** `go test ./service/internal/access/v2/ -run 'DeviceRules|PartitionsDevices|NarrowEntityEntitlements'`.

- [ ] **Step 3: Implement.**
  - `getDecision` narrows only when `rules.Narrows(devices)`, and logs `devices_count` and the remaining FQNs at debug.
  - `GetDecision` and `GetEntitlements` in the JIT PDP pass `p.deviceRules`.
  - Remove every `entityconstraint` import from `access/v2`.

- [ ] **Step 4: Run.** `go test ./service/internal/access/v2/... ./service/entityresolution/composite/... && golangci-lint run ./service/internal/access/v2/...`. Expected: pass, 0 issues. The composite still emits `arkavo_constraint`, which the PDP now ignores, so the composite tests still pass.

- [ ] **Step 5: Commit**: `feat(authz): PDP narrows by policy device rules`

---

### Task 4: Composite verifies device tokens in a chain and binds them

**Files:**
- Modify: `service/entityresolution/composite/v2/evidence.go`: `evidence` gains three fields.
- Modify: `service/entityresolution/composite/v2/composite.go`:
  - `resolveSubject` fills `Iss` and `AccountID`;
  - `resolveEntity` gains a device-token branch and returns `*chaindevice.Device` instead of `class string`;
  - `ResolveEntities` binds in a second pass;
  - `representation` takes `*chaindevice.Device` and writes `chaindevice.PropKey`.
- Create: `service/entityresolution/composite/v2/device.go`, holding `deviceFromClaims`, `deviceTokenEntity` and `bindDevices`.
- Modify: `service/entityresolution/composite/v2/config.go`: reserve `chaindevice.PropKey` and `chaindevice.TokenClaim` as `properties_key` values, replacing the `entityconstraint.PropKey` check at ~line 271.
- Test: `service/entityresolution/composite/v2/device_test.go` (new). In `composite_resolve_test.go`, replace `TestResolve_DeviceCarriesItsConstraint` with the tests below. Extend `config_test.go` for both reserved keys.

**Interfaces:**
- Consumes: `chaindevice.Device`, `PropKey`, `TokenClaim`, `KindDevice`, the class constants (Task 1); `source.KindOf`; `s.verifyToken`.
- Produces:
  ```go
  // evidence.go: all omitempty, version stays 1
  Iss       string        `json:"iss,omitempty"`
  AccountID string        `json:"account_id,omitempty"`
  Device    *sealedDevice `json:"device,omitempty"`
  type sealedDevice struct {
      Class     string `json:"class"`
      AppIDHash string `json:"app_id_hash,omitempty"`
      AppEnv    string `json:"app_env,omitempty"`
  }
  // device.go
  func deviceFromClaims(claims map[string]any, verified bool) chaindevice.Device // class/app from arkavo_npe when verified; else Class unverified
  func bindDevices(entries []resolvedEntry)                                      // sets Device.Bound
  type resolvedEntry struct {
      id       string
      category entity.Entity_Category
      ev       evidence
      device   *chaindevice.Device
      iss      string
      account  string
  }
  ```
- Device token claims, read from the verified token's `arkavo_npe`:
  - `class` (missing → `unverified`; a value outside `chaindevice.Classes` → `unverified`);
  - `app_id_hash`, lowercased;
  - `app_env`, which must be `production` or `development`, else `""`.
- Binding rule: a device is bound iff all of these hold:
  - it is `Verified`;
  - the request has at least one non-environment entry;
  - every such entry has a non-empty `iss` and `account` equal to the device's.

  A subject entry whose sealed evidence has a `Device` gets that device with `Verified: true, Bound: true`.

- [ ] **Step 1: Write failing tests** in `device_test.go`. Use `fakeVerifier{}`, `signCWT`, `pepConfig()`, `claimsEntity`, `callerContext`, `resolveAs`, and `environmentEntity` (move it from `decision_test.go` into `helpers_test.go`). The device token claims are:
  - `iss: testIssuer`, `sub: <uuid>`, `exp`, `aud: []any{"arkavo:devicecheck", "https://platform.arkavo.net"}`, `arkavo_account_id: creatorAccount`;
  - `arkavo_npe: {type: device, class: attested, device_id: d1, app_id_hash: <iOS hash>, app_env: production}`.

  Tests:
  - `TestDeviceToken_VerifiedAndBound`:
    - person `claimsEntity("e0", catalogCreatorClaims())`, plus environment entity `{arkavo_device_token: <signed>}`;
    - the env rep's marker reads as `Device{attested, Verified, Bound, iOS hash, production}`;
    - the env rep has no direct entitlements.
  - `TestDeviceToken_AccountMismatchUnbound`: the device token's `arkavo_account_id` differs, so `Bound == false`.
  - `TestDeviceToken_FromAnyCaller`: a caller not on `claims_chain_peps` still gets a `Verified` device. Its person is anonymous, so the device is unbound.
  - `TestDeviceToken_InvalidIsUnverified`:
    - `fakeVerifier{err: …}`;
    - an expired token;
    - a token whose claims aren't a device's (no `arkavo_npe`, `aud: "x"`).

    Each reads as `Device{Class:"unverified"}`, with no entitlements.
  - `TestDeviceToken_UnknownClassIsUnverified`: `class: "gold"` reads as `unverified` (`Verified` stays true).
  - `TestPEPClaimsDevice_Unbound`: an env claims entity with `deviceClaims` from an allowlisted PEP has a marker with `Verified: false`, `Bound: false`.
  - `TestBind_OneUnboundDeviceDeniesAll`: person plus a bound device token plus a mismatched device token. One marker is bound and one isn't. Task 6 checks the decision.
  - `TestBind_EvidenceWithoutIdentityNeverBinds`:
    - a sealed subject whose evidence was sealed without `Iss` and `AccountID` (build it with `sealEvidence` directly), plus a valid device token;
    - the device is unbound.
  - `TestResolveSubject_RecordsIssAndAccount`: the token-route evidence for `creatorClaims` has `Iss == testIssuer` and `AccountID == creatorAccount`.
  - `TestSealedEvidence_RoundTripsIdentityAndDevice`: `openEvidence(sealEvidence(ev))` keeps `Iss`, `AccountID` and `Device`.
  - Config: `properties_key: arkavo_device` and `properties_key: arkavo_device_token` each fail `Validate`.

- [ ] **Step 2: Run; they fail.** `go test ./service/entityresolution/composite/... -run 'DeviceToken|PEPClaimsDevice|Bind_|RecordsIssAndAccount|RoundTripsIdentity|Reserved'`.

- [ ] **Step 3: Implement.**
  - `resolveEntity` order:
    1. sealed evidence (unchanged);
    2. `claims[chaindevice.TokenClaim]` is a string: run `s.verifyToken` and build the device with `deviceFromClaims`; the evidence is empty (no grants);
    3. allowlisted PEP claims, as today: a `KindDevice` subject gets `deviceFromClaims(claims, false)`;
    4. anonymous.
  - `ResolveEntities` builds `[]resolvedEntry`, calls `bindDevices`, then builds representations.
  - Keep the `capGrants`/`deviceConstraint` code until Task 5. Only `representation`'s caller changes.

- [ ] **Step 4: Run.** `go test ./service/entityresolution/... ./service/internal/... && golangci-lint run ./service/entityresolution/composite/...`. Expected: pass, 0 issues.

- [ ] **Step 5: Commit**: `feat(ers): composite verifies and binds device tokens in a chain`

---

### Task 5: Split a DeviceCheck subject; remove `device_class_caps` and the `device-class` source

**Files:**
- Modify: `service/entityresolution/composite/v2/composite.go`:
  - `resolveToken` splits;
  - remove the `caps` field from `Service` and `New`;
  - remove the `capGrants` call in `resolveSubject`.
- Modify: `service/entityresolution/composite/v2/device.go`: add `personClaims`.
- Modify: `service/entityresolution/composite/v2/constraints.go`: delete `capGrants` and `deviceConstraint`; keep `withheldAgent`.
- Delete: `service/entityresolution/composite/v2/device_class.go` and `device_class_test.go`.
- Modify: `service/entityresolution/composite/v2/register.go`: remove the `typeDeviceClass` case.
- Modify: `service/entityresolution/composite/v2/config.go`:
  - `Validate` refuses a non-empty `Constraints.DeviceClassCaps` and a source with `type: device-class`;
  - keep the `DeviceClassCaps` field, documented as "removed; present only so Validate can refuse it";
  - remove `optionClasses` and the classes option handling.
- Modify: `service/entityresolution/v2/entity_resolution.go:48`: the `device_class_ceilings` message becomes "device rules moved to device_rules in the policy file".
- Modify tests that use caps or the device-class source:
  - `constraints_test.go`: delete `TestDeviceCaps_*`, `device` and `sealed` if they're unused;
  - `composite_resolve_test.go`: delete `TestResolveSubject_KindComesFromClaims`, or rewrite it to assert a device subject's kind without the device-class source;
  - `composite_token_test.go`: delete `TestResolveSubject_TrustNoneNeverGetsDeviceClassGrants`;
  - `register_test.go`, `config_test.go`: update.
- Test: `service/entityresolution/composite/v2/split_test.go` (new)

**Interfaces:**
- Consumes: `deviceFromClaims`, `sealedDevice`, `resolvedEntry` (Task 4).
- Produces: `func personClaims(claims map[string]any) map[string]any`. It returns a copy without `arkavo_npe` and `cnf`, with `arkavo:devicecheck` removed from `aud`, and with `aud` deleted when nothing remains. A string `aud` equal to it is deleted.

- [ ] **Step 1: Write failing tests** in `split_test.go`. The fixture is a DeviceCheck token carrying `creatorClaims` plus `aud: ["arkavo:devicecheck", "https://platform.arkavo.net"]`, `cnf: {…}` and `arkavo_npe {device, attested, iOS hash, production}`.
  - `TestSplit_PersonResolvesAsPerson`:
    - `tokenEvidence` grants include `publishValue` and `creatorCampaign`;
    - `ev.Device` is `{attested, iOS hash, production}`;
    - `ev.AccountID == creatorAccount`.
  - `TestSplit_StringAudience`: with `aud: "arkavo:devicecheck"` the same holds, and `personClaims` has no `aud`.
  - `TestSplit_RepresentationCarriesBoundDevice`: `openEntity` / `resolveAs` of the token-route subject gives a rep whose marker reads `Verified, Bound`, and the rep keeps its direct entitlements.
  - `TestSplit_AgentMarkerNotSplit`: a token with `arkavo_swarm` is an agent, gets no `Device`, and is gated as today.
  - `TestPersonClaims_DoesNotMutate`: the input map is unchanged.
  - In `config_test.go`, `TestValidate_RefusesRemovedDeviceSettings`: `constraints.device_class_caps: {managed: [...]}` and a source `type: device-class` each fail. The error contains `device_rules`.

- [ ] **Step 2: Run; they fail.** `go test ./service/entityresolution/composite/... -run 'Split|PersonClaims|RefusesRemoved'`.

- [ ] **Step 3: Implement.** In `resolveToken`, after `verifyToken`:
  - if `source.KindOf(claims) == source.KindDevice`, then:
    - `dev := deviceFromClaims(claims, true)`;
    - `claims = personClaims(claims)`;
    - resolve as now;
    - set `ev.Device = &sealedDevice{dev.Class, dev.AppIDHash, dev.AppEnv}`.

  `representation` writes the marker for `ev.Device` with `Verified: true, Bound: true`. Apply this through `resolvedEntry` in `ResolveEntities`.

- [ ] **Step 4: Run.** `go test ./service/entityresolution/... && golangci-lint run ./service/entityresolution/...`. Expected: pass, 0 issues.

- [ ] **Step 5: Commit**: `feat(ers)!: a DeviceCheck subject is a person plus its device; device_class_caps and device-class source removed`

---

### Task 6: End-to-end decisions through the v2 PDP

**Files:**
- Create: `service/entityresolution/composite/v2/testdata/policy.device-rules.yaml`. Copy `examples/config/policy.patreon.yaml` and add:
  - the attribute `patreon.arkavo.com/arkavo-creator` (anyOf, value `publish`);
  - the spec §3 `device_rules`, with both apps and `app_envs: [production]`, and the cap `managed → [campaign def, campaign-tier def]`.
- Modify: `service/entityresolution/composite/v2/decision_test.go`: add tests. Remove the `deviceClaims` helper if it's unused.

**Interfaces:**
- Consumes: `pdpFor`, `permitted`, `tokenIdentifier`, `chainIdentifier`, `environmentEntity`, `signCWT`, and the Task 4 and 5 fixtures.

- [ ] **Step 1: Write the tests.**
  - `TestDeviceRules_ThroughTheV2PDP`, catalog chain route, publish resource. Rows:

    | Chain | Decision |
    |---|---|
    | person alone | deny |
    | person + attested, iOS, production device token | permit |
    | the same with the Creator hash | permit |
    | person + managed device | deny |
    | attested, `development` | deny |
    | attested, no app | deny |
    | attested, unlisted app | deny |
    | person + PEP-claims device saying attested with a listed app | deny |
    | person + device token for another account | deny |
    | person + one bound attested device + one unbound device | deny |
    | device token alone | error, "no subject entities" |
  - `TestDeviceRules_CapThroughTheV2PDP`: person + managed device:
    - campaign and tier content permitted;
    - a `content-type` value the person holds denied.
  - `TestDeviceRules_TokenRouteSplit`: `tokenIdentifier(<DeviceCheck token>)`:
    - publish is permitted when the token is attested, iOS, production;
    - denied when the token is `managed`.
  - `TestDeviceRules_RoutesAgree`: take every subject-mapped FQN (the `status` and `entitlement` values) the person holds with no device. `GetEntitlements` reads subject mappings only (#62), so only those are comparable.
    - Person + managed device: the cap keeps only `campaign` and `campaign-tier`, so each of those FQNs is absent from `GetEntitlements` and denied by `GetDecision`.
    - Person + attested device (no cap, no requirement on them): each is present in `GetEntitlements` and permitted by `GetDecision`.
  - `TestDeviceRules_NoRulesDecidesAsBefore`: with `patreonPolicy`, which has no rules, person alone and person + attested device both decide as `TestPatreonDecisions_ThroughTheV2PDP` expects.

- [ ] **Step 2: Run.** `go test ./service/entityresolution/composite/... -run 'DeviceRules'`. Expected: pass. A failure here means an earlier task diverged from the spec: fix that task's code, not the test.

- [ ] **Step 3: Commit**: `test(authz): device rules end to end through the v2 PDP`

---

### Task 7: Remove `entityconstraint`; docs and example configs

**Files:**
- Delete: `service/internal/entityconstraint/` (both files).
- Modify `docs/Configuring.md`:
  - remove the `constraints.device_class_caps` row (~591), the `device-class` type and `classes` rows (~579, ~587), and `device_class_caps: {}` (~618);
  - fix the `device_class_ceilings` migration row (~632);
  - rewrite "Composite resolver: devices in a chain" (~641) to cover:
    - the `arkavo_device_token` claims entity;
    - binding on `iss` and `arkavo_account_id`;
    - an unbound device denies;
    - the DeviceCheck subject split;
    - `device_rules` with the spec's YAML;
    - the spec's rollout order.
- Modify: `service/entityresolution/README.md:41,78`, dropping device-class caps.
- Modify example configs:
  - `examples/config/opentdf-patreon-prod.yaml:103` and `opentdf-patreon-local-test.yaml:79`: remove `device_class_caps: {}`;
  - `examples/config/opentdf-arkavo-local-test.yaml`: remove the `device-class` source and `device_class_caps`;
  - `examples/config/policy.arkavo.yaml`: in the header and the classification comment, drop "a device-class source owns classification". Classification is then granted by no source; note that this waits on #63, per the spec's Open question.

- [ ] **Step 1: Verify nothing still references the removed names.**
  ```bash
  grep -rn 'entityconstraint\|device_class_caps\|deviceClassSource\|typeDeviceClass' --include='*.go' service
  grep -rn 'device_class_caps\|type: device-class' examples docs/Configuring.md service/entityresolution/README.md
  ```
  Expected: the first finds no output. The second finds only the `Validate` refusal message and the Configuring.md migration note.

- [ ] **Step 2: Check that every example config still loads.** Run `go test ./service/entityresolution/... ./service/policy/filestore/...`, plus any example-config load test (search `opentdf-arkavo-local-test.yaml` in `*_test.go`). Expected: pass.

- [ ] **Step 3: Run the full gate.**
  ```bash
  ~/go/bin/gofumpt -w $(git diff --name-only main -- '*.go')
  golangci-lint run ./service/...
  go test ./...
  ```
  Expected:
  - lint: 0 new issues (the existing sloglint findings in `evaluate.go` are untouched);
  - tests: only the known Docker or live-platform failures (Keycloak integration, `service/integration`, `rttests`). Any other failure blocks.

- [ ] **Step 4: Commit**: `docs(authz): device rules in policy; drop entityconstraint`

---

### Task 8: Publish and update downstream

These are outward-facing writes. The user has authorised pushing this branch, creating GitHub issues, and commenting. Pass `--repo` on every write.

- [ ] **Step 1:** `git push origin fix/chain-device-constraints`. Expected: CI starts on #61.
- [ ] **Step 2:** Comment on #61 (`--repo arkavo-org/opentdf-platform`):
  - what changed since the last review: rules moved to policy, signed device tokens, binding, the split, and the removed settings;
  - the PR now "Closes #60";
  - link the spec and #63.
- [ ] **Step 3:** Comment on these, each saying what the PEP or spec must now send (from the spec's Downstream section):
  - specifications#9 (`arkavo-org/specifications`);
  - the tdf-iroh-s3#35 thread;
  - arkavo-rs#96 (`arkavo-org/arkavo-rs`): superseded, so forward `{arkavo_device_token: <CWT>}` as an environment claims entity.
- [ ] **Step 4:** Wait for CI on #61. Report its result and any new review comments to the user. Fix findings on this branch before merging (memory: follow-ups before merge).
