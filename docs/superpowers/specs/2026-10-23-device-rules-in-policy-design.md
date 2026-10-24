# Device rules in policy (rework of #61 for #60)

## Why

Bug #60: device NPEs in a person's chain never affected decisions. PR #61 made them reach the resolver and narrow the person's grants. But it took the rules from the composite ERS config (`constraints.device_class_caps`), and it trusted the device class the PEP sent.

The owner decided otherwise (#60, 2026-10-22):

> Devices narrow a grant based on policy. The policy declares what a grant requires of an accompanying device (attestation, class), or which grants a device class is capped to. The fix should read those rules from policy, not from `constraints.device_class_caps` in the ERS config. Devices narrow the person's grants; they never act as co-subjects.

The first rule it needs: **publishing requires an attested device running a production Arkavo app** (tdf-iroh-s3#35, #59; owner, 2026-10-23). A modified device, OS or app must not publish: it would let scripted clients upload content that violates the terms.

What App Attest can and cannot give that rule:

- It blocks a modified or re-signed app: the attested key is bound to `SHA256(<TeamID>.<BundleID>)` (`rpIdHash`), and a re-signed app has another Team ID.
- It blocks simulators, emulators and direct API scripts: they have no Secure Enclave key.
- It reports the environment through the aaguid (`appattest` or `appattestdevelop`). On macOS a locally signed developer build reports `appattest` (authnz-rs fixture finding), so "production" there means "signed by the Arkavo team", not "from the store".
- It does not detect a jailbroken device or a modified OS: a hooked genuine app can still sign. Narrowing that is outside this design (see Downstream).

## Goals

- Policy declares device rules of two kinds:
  - **requirement:** a grant needs an accompanying device of one of some classes;
  - **cap:** a device of class C, when present, limits the person to some grants.
  A requirement can also name the apps and app environments the device must be running.
- The ERS reports what a device *is* (kind, class, app, app environment) and nothing about what it allows.
- A device's class and app count only if the platform verified authnz-rs's signature on the device token itself. A class a PEP asserts is not trusted.
- Every device belongs to a person in the same decision. A device alone gets nothing.
- Devices never become co-subjects.
- `GetDecision` and `GetEntitlements` agree.

## Non-goals

- Agents in a chain, and organizations as owners. An agent environment entity is still skipped; the agent gate is unchanged. That design is #63 (owner → agent → device).
- Device rules in the policy database. Production runs `mode: core,entityresolution,-policy,-kas` with `policy_file`; only the file store carries rules. A DB-backed store has none.
- Upstreaming. OpenTDF policy has no device concept; this is a fork extension.

## Anti-goals

- A rule that silently allows. A malformed rule fails policy load, not open.
- PEP-supplied rules or classes. Only the policy file declares rules, and only a signed device token declares a class.

## What #61 keeps

- The JIT PDP sends the chain's subjects and its claims environment entities to the ERS; other environment entities are skipped before it. (OpenTDF's `Entity` has no token type: email, user name, claims or client ID. A device token travels inside a claims entity; see §1.)
- Representations are partitioned alike on both routes: subjects; environment entities resolved as devices; the rest skipped.
- `source.KindOf`: `arkavo_npe.type: device` or an `aud` naming `arkavo:devicecheck`. The agent marker still wins.
- Narrowing runs in `pdp.getDecision` after direct grants are merged, and on `GetEntitlements` output.

## What changes

### 1. The device proves its class with a signed token

authnz-rs mints the DeviceCheck token: a CWT with aud `arkavo:devicecheck` (plus the platform audience) and `arkavo_npe {type: device, class, device_id}`. `class` is `attested` while the last App Attest assertion is under 15 minutes old, else `managed`. The token lasts an hour, so authnz-rs also mints `arkavo_npe.attestation_expiry` (the assertion plus 15 minutes), and the composite reads `attested` only before it: past it, or without one, the device is `managed`, in a chain and in sealed evidence alike.

authnz-rs gains two `arkavo_npe` members (Downstream):

- `app_id_hash`: the attested `rpIdHash`, lowercase hex, as `DeviceBinding.app_id` already stores it;
- `app_env`: `production` for aaguid `appattest`, `development` for `appattestdevelop`, recorded in the binding at attestation.

A token without them has no app, which fails any requirement that names apps or app environments.

- **In a chain.** The PEP forwards an environment claims entity whose only claim is `arkavo_device_token`: the raw DeviceCheck CWT. `arkavo_device_token` is reserved (a `properties_key` may not use it, as `arkavo_device` below). The composite verifies it with the issuer's verifier (`verifyToken`), from any caller: the signature, not the caller, is what it trusts, as with sealed evidence. A verified token that `KindOf` judges a device gives the device's class, app and app environment. One that doesn't verify, has expired, or isn't a device token is a device of class `unverified` with no app. A device token entity is never resolved by the sources and holds no grants. (A PEP-claims device is still resolved as a subject is, as today; the PDP never reads an environment representation's grants, and its marker is unbound.)
- **Claims from a PEP.** A device sent as plain claims (`TrustPEP`) is still a device, but its class reads as `unverified` and it has no app, whatever the claims say. It never satisfies a requirement for `attested` or `managed`, or one that names apps.
- **Binding, in the composite.** `ResolveEntities` receives one chain per request, with each entity's category, so the composite binds there and the PDP never needs identities. A device is bound only if it is a verified token, and its `iss` and `arkavo_account_id` equal those of every subject entity in the request. A subject's `iss` and `arkavo_account_id` come from its PEP claims, or from its sealed evidence, which gains both fields. `arkavo_account_id`, not `sub`: authnz-rs mints different `sub` forms per token type (a UUID on auth and DeviceCheck tokens, `arkavo:<id>` on OIDC access tokens), while `arkavo_account_id` is the one account UUID on all of them and is already the composite's stable ID (`claimAccountID`). A subject or device with either missing never binds, and an anonymous subject never binds.
- **An unbound device denies.** The marker carries `bound: false`, and the PDP then keeps no grant for any subject of the chain, on both routes: ignoring the device would drop a cap and widen grants. A PEP-claims device is never bound, so it denies too once it rides with a person. *(Builder's call: binding needs a signature to mean anything.)*
- **Lone device.** A chain with a device and no subject is denied (#61's "no subject entities" error already does this).
- **A DeviceCheck token as the subject** (KAS rewrap from iOS, arkavo-rs#72). The token carries the person's claims and the device's. On the token route the composite splits it:
  - the person: the same claims with `arkavo_npe`, `cnf` and the `arkavo:devicecheck` audience removed, so `KindOf` judges a person and the sources resolve it as any person token;
  - the device: kind, class, app and app environment from the token's `arkavo_npe`, sealed into the person's evidence (new `device` member), bound by construction.
  
  The chain stays one sealed subject entity. Its representation carries the device marker, and the PDP reads a marker on a subject representation as that subject's own bound device. Device rules then apply as in a chain. This replaces the composite's own handling of device subjects, so `device_class_caps` goes entirely.
- **The `device-class` source goes.** After the split no token route subject is a device, so a source that grants by device class never fires; and devices never grant (owner, #60). A config with a source of `type: device-class` fails startup, as one with `device_class_caps` does, with a message pointing to `device_rules`. The arkavo-plane example (`opentdf-arkavo-local-test.yaml`, `policy.arkavo.yaml`) grants `classification` by device class today; it loses that source. See Open question.

### 2. The ERS reports identity only

The composite's device marker (`arkavo_constraint` in `AdditionalProps`) is renamed `arkavo_device` and becomes `{kind: "device", class, verified, bound, app_id_hash, app_env}`. `capped` and `allow` go, as do `deviceConstraint()`, `capGrants()` and `device_class_caps`.

`entityconstraint` is renamed to `chaindevice`: it parses that value from a representation. A device that isn't verified, or whose value is malformed, reads as class `unverified`, unbound, with no app, which fails toward fewer grants under any rule set.

The PDP flattens every `AdditionalProps` key into subject-mapping selectors, so on a split subject the marker is selector input. That is harmless: the key is reserved and only the composite writes it.

### 3. Policy declares the rules

New top-level section in the policy file:

```yaml
device_rules:
  requirements:
    - grants:
        - https://patreon.arkavo.com/attr/arkavo-creator/value/publish
      device_classes: [attested]
      apps:                                  # optional; <TeamID>.<BundleID>
        - M8GS7ZT95Y.com.arkavo.Arkavo        # iOS
        - M8GS7ZT95Y.com.arkavo.ArkavoCreator # macOS
      app_envs: [production]                 # optional
  caps:
    - device_class: managed
      keeps:
        - https://patreon.arkavo.com/attr/campaign          # a definition FQN covers every value, synthetic ones included
        - https://patreon.arkavo.com/attr/campaign-tier
```

- **Matching.** An entry in `grants` or `keeps` is a value FQN (matches that value) or a definition FQN (matches every value under it). Campaign and tier values are synthetic, so definition matching is needed. Case-insensitive, exact otherwise; a hierarchy value does not cover the values below it.
- **Requirement semantics.** A grant matched by a requirement is kept only if the decision has at least one device that meets all of it: its class is in `device_classes`; if `apps` is set, its `app_id_hash` equals `SHA256` of one of them (the policy names apps readably, the loader hashes them, the token carries the hash); if `app_envs` is set, its `app_env` is one of them. A decision with no device drops it, on every route: the token route, and tdf-iroh-s3's direct `GetDecisionMultiResource` claims mode, deny a required grant until they send a device (owner, 2026-10-23).
- **Cap semantics.** For each device whose class has a cap, the person keeps only grants its `keeps` matches. Several devices intersect. A class with no cap entry narrows nothing.
- **Order.** Requirements and caps both apply; a grant survives only if it passes both.
- **Validation at load.** Any failure fails the policy load:
  - every FQN must parse;
  - every FQN must name an attribute definition the policy file declares, and a value FQN under a definition with declared values must name one of them (synthetic values, under definitions with none declared, are accepted). A typo in a requirement would otherwise never match and fail open. *(Builder's call, from the builder check.)*
  - no rule may name an attribute whose rule is `hierarchy`. `GetDecision` narrows before hierarchy evaluation and `GetEntitlements` after comprehensive expansion, so a hierarchy rule would let a higher value bypass a requirement and make the two routes disagree. Lift this only with a design for hierarchy expansion. *(Builder's call, from the builder check.)*
  - `device_classes` must be non-empty; a class may have at most one cap entry.
  - each `apps` entry must have the form `<TeamID>.<BundleID>` (a 10-character Team ID, a dot, a non-empty bundle ID); `app_envs` entries must be `production` or `development`; neither list may be present but empty.

### 4. The PDP applies them

- An optional store capability `DeviceRuleSource { DeviceRules() DeviceRules }`, detected the way `SubjectMappingMatcher` is. The file store implements it; any other store has no rules.
- `resolvedChain.constraints` becomes `devices []chaindevice.Device`.
- `getDecision` and `GetEntitlements` narrow with `(rules, devices)` in place of `[]Constraint`.
- With no rules, devices change nothing, so the current policy file decides as today. Binding and lone-device denials apply with or without rules.

### 5. Config and docs

- Remove `constraints.device_class_caps` from the composite and `Configuring.md`. Pre-release hard cutover (owner, 2026-10-17): a config still setting it fails startup with a message pointing to `device_rules`.
- `Configuring.md`: "devices in a chain" describes `device_rules`, signed device tokens and binding.

## Downstream

- **authnz-rs (arkavo-org/authnz-rs#114).** Mint `arkavo_npe.app_id_hash` and `arkavo_npe.app_env` in the DeviceCheck token; store the environment in `DeviceBinding` at attestation. Bindings made before that have no environment: they mint no `app_env` and fail an `app_envs` requirement until the device attests again.
- **Narrowing the jailbreak gap (not this design; per-upload assertion: arkavo-org/specifications#10, risk metric: authnz-rs#114).**
  - Tie the App Attest assertion to the upload: the client's assertion signs a hash of the content being published, so a hooked device must drive the real app once per upload instead of replaying a token from a script (authnz-rs, arks, tdf-iroh-s3, specifications).
  - Use Apple's App Attest receipt risk metric in authnz-rs to spot device farms.
  - Terms are still enforced by moderation and account reputation; attestation raises the cost of abuse, it doesn't end it.
- **arkavo-rs (arks).** Forward the DeviceCheck CWT as an environment claims entity `{arkavo_device_token: <CWT>}` in the chain, not `{type, class}` claims. #96 (class-only forwarding) is superseded; rework or close it.
- **tdf-iroh-s3 (#35).** Send the signed device token, not `context.device.class`. Update the comment.
- **specifications#9.** The device entity is the signed token; class claims from the PEP carry no weight.

## Rollout

YAML decoding is lenient, so a binary without this change silently ignores `device_rules`. A requirement like publish-needs-attested would then fail open. Order:

1. Deploy arks forwarding the device token (`{arkavo_device_token: <CWT>}`) **instead of** the device's claims. **Hard precondition for step 3.** arks `main` forwards a device today as `{sub, iss, aud, kid}` (`device_to_value`); a DeviceCheck `aud` makes `KindOf` judge it a device, which this change reads as a PEP-claims device, unbound, so the whole decision denies. Safe before the platform: the current platform skips every environment entity.
2. Deploy authnz-rs minting `app_id_hash` and `app_env`.
3. Deploy the platform binary.
4. Add `device_rules` to the policy file. `policy.patreon.yaml` doesn't declare `patreon.arkavo.com/attr/arkavo-creator` today (only the ERS config's source grants name it), so the publish rule fails load validation until the attribute and its `publish` value are declared in the same change.
5. tdf-iroh-s3 sends the device token. Until then its devices read as `unverified` and its direct claims route has none, so step 4 must not add the publish requirement before steps 2 and 5 ship, or publishing is denied.

Deploying the binary alone changes these things, before any rule is written:

- A DeviceCheck token at KAS rewrap is now a person plus a device. With no rules and no `device_class_caps`, that person keeps their own grants: wider than a capped device subject got, but no wider than the same person's other tokens.
- A config naming `device_class_caps` or a `device-class` source fails startup, so it must be removed in the same deploy.
- A chain whose device is sent as plain PEP claims is denied (unbound). arks `main` sends exactly that today (`{sub, iss, aud, kid}`), hence step 1.

## Tests

- Test-only policy file. `examples/config/policy.patreon.yaml` (the production example) gets no rules in this change.
- The owner's rule, end to end through the v2 PDP: publish with person alone → deny; person + verified attested device, listed app, production → permit; person + verified managed device → deny; verified attested device with an unlisted app, no app, or `development` → deny; person + PEP-claims device saying `attested` with a listed app → deny.
- Binding: person + device token for another `sub` → deny.
- Lone device → deny.
- DeviceCheck token as the subject: resolves to the person, narrowed by the token's class.
- Cap: person + managed device keeps campaign and tier values (definition match), loses others.
- No rules: every chain decides as before.
- Both routes agree.
- App hashing: `M8GS7ZT95Y.com.arkavo.ArkavoCreator` hashes to the `rpIdHash` in authnz-rs's App Attest fixture.
- Load validation failures; a config with `device_class_caps` fails startup.

## Open question (owner)

- **Device class granting classification on the arkavo plane.** `opentdf-arkavo-local-test.yaml` grants `https://arkavo.ai/attr/classification` (a `hierarchy` attribute) by device class: attested → restricted, managed → confidential, unverified → internal. Under "devices narrow, never grant" that source goes. The narrowing equivalent, "restricted requires an attested device", names a hierarchy attribute, which §3's validation forbids. Proposed: drop the source from the example now and design hierarchy-aware device rules with #63.

## Left to the builder

- Names (`device_rules`, `requirements`, `caps`, `keeps`) may change if the loader suggests better ones.
- Where the rule evaluation lives (`internal/access/v2` or `chaindevice`).
- Log fields for narrowed grants and binding failures.
