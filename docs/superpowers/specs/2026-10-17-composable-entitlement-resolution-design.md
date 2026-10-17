# Composable entitlement resolution for platform.arkavo.net

**Date:** 2026-10-17
**Status:** Design, for review. Nothing in it is built yet.
**Scope:** the arkavo-org/opentdf-platform fork that serves platform.arkavo.net, with the follow-on changes it needs in arkavo-rs (`arks`), tdf-iroh-s3 and authnz-rs.
**Inputs:** the product owner's direction, independent proposals from three peer models (codex, grok, kimi) given the same brief, and a reading of the code at the revisions below.

| Repository | Revision read |
|---|---|
| opentdf-platform fork | `origin/main` `425af373` |
| arkavo-rs | `origin/main` `82821d0` |
| tdf-iroh-s3 | `origin/main` `15d9c28` |
| authnz-rs | PR #100 (`f6dda42`), deployed 2026-10-17 |

## 1. Why this exists

A decision about whether a viewer may decrypt or play a recording runs through the platform's entity resolution service (ERS). The ERS turns the viewer's token into entitlements, and the decision engine compares them with the TDF's policy.

Today the ERS is configured with exactly one `mode`: `keycloak`, `claims`, `multi-strategy`, `patreon` or `arkavo` (`service/entityresolution/v2/entity_resolution.go`, `NewRegistration`). Each mode understands one kind of evidence. Prod appears to run `patreon` (the prod config draft is `examples/config/opentdf-patreon-prod.yaml`).

On 2026-10-17 that broke a real case. A creator's token correctly carried:
- `https://patreon.arkavo.com/attr/campaign/value/13167240`;
- every `https://patreon.arkavo.com/attr/campaign-tier/value/13167240_*` value, put in `arkavo_entitlements` by authnz-rs #100 because the account owns that campaign.

The FairPlay licence for the creator's own recording was still denied, and so was the catalog node's evaluated decision. The cause is in `patreon` mode (`service/entityresolution/patreon/v2/passthrough.go`):
- it derives entitlements only from `arkavo_patreon.memberships`;
- for a creator it only records the owned campaign ID in a flattened view, and grants nothing for it;
- it never reads `arkavo_entitlements`.

`arkavo` mode would read that array, but it would drop the Patreon behaviours `patreon` mode provides. Stripe purchases are next on the backlog and on-chain entitlements later. Each would otherwise become another mode, and a deployment could still run only one.

**The owner's direction:** no single mode. Every applicable resolution behaviour should be usable together, for many kinds of source. The priority is the **shape**: Stripe and blockchain must drop in later without rework. That ranks above a quick creator fix, but the shape must also fix the creator case.

## 2. Goals, non-goals, anti-goals

**Goals**
1. Every decision considers every applicable source of entitlement and combines their grants.
2. Adding a source (Stripe, blockchain, or something not yet named) is new code behind one interface plus a config entry. It needs no change to the combiner, to other sources, or to existing TDF policies.
3. A source can only grant within the attribute space it is authorised for, so a bug in one source cannot unlock another source's content.
4. Sources whose evidence travels in the token and sources looked up at decision time use the same interface.
5. Fix the creator case: a token carrying the owned campaign's entitlements is permitted for that campaign's content, on both the licence route and the catalog route.
6. Keep every current patron permitted, and keep the `.patreon.*` subject-mapping behaviour, through the migration.

**Non-goals (for this design)**
- Designing the Stripe integration or the blockchain integration. Neither has been researched. Only their plug-in points are sketched (§9).
- Changing how Arkavo Creator writes TDF policies today.
- Replacing OpenTDF's decision engine.

**Anti-goals: things that would make this a failure even if it technically works**
- A new "mode" by another name, or routing that picks one source per request. Upstream `multi-strategy` does exactly that: `service/entityresolution/multi-strategy/service.go` selects a strategy and returns the first success.
- Any source failure that turns into access. That includes a live lookup failing open, or serving stale grants after an error.
- Precedence rules where one source silently shadows another's grants.
- Representing each source as its own entity. The decision engine ANDs entity representations (§6), so a union would become an intersection.
- Unbounded passthrough of every FQN in a token.

## 3. Constraints

- **Policy semantics are fixed:** OR within an attribute definition (`anyOf`), AND across definitions (`service/internal/access/v2/evaluate.go`). Patreon content needs `campaign/<cid>` AND one of its listed `campaign-tier/<cid>_<slug>` values.
- **Synthetic values:** dynamic values such as campaign IDs and tier slugs need `allow_direct_entitlements: true`. The PDP then synthesises the value under an existing definition (`service/internal/access/v2/helpers.go`, `getResourceDecisionableAttributes`).
- **One representation per subject:** `JustInTimePDP.GetDecision` (`service/internal/access/v2/just_in_time_pdp.go`) requires every entity representation it evaluates to be permitted. Environment entities are skipped (`skipEnvironmentEntities`).
- **Two routes reach the platform:**
  - *Licence:* arks calls `GetDecision` with the viewer's CWT as `entityIdentifier.token.jwt` (`arkavo-rs src/modules/license/pdp.rs`).
  - *Catalog:* tdf-iroh-s3's `GET /catalog/<campaign>` calls either `GetDecisionMultiResource` with a claims chain, or AuthZEN through arks (`tdf-iroh-s3 src/authz.rs`; AuthZEN is the default).
- **Tokens:** CWT, ES256, issuer `https://identity.arkavo.net`, one-hour lifetime. Patreon data is materialised at mint and cached for 5 minutes.
- **Revocation baseline:** the token's lifetime. *My call, pending the Stripe research*, agreed in conversation as the default; sources that need faster revocation are looked up live.

## 4. Decided by the owner

- No single mode. All applicable behaviours run together, for many source types. Stripe is next and blockchain later; neither is researched.
- Stripe sketch: we define item IDs in Stripe, purchases reach our platform, the purchase becomes an entitlement in the CWT, and at Play the token is matched against the item ID in the TDF's policy and allowed. If tokens grow large, entitlements may need to be scoped or looked up remotely.
- The shape comes before the quick creator fix.
- "Creator" means the account owns a Patreon campaign, as Patreon reports it (authnz-rs #100). It does not mean a role a client asserted.

## 5. The design

### 5.1 One composite resolver

Add a composite ERS, registered when `services.entityresolution.sources` is present. `mode` keeps working unchanged until migration ends (§8).

For each subject entity in a request, the composite does four things:
1. **Establish verified evidence** (§5.3).
2. **Run every source that applies** to this subject and evidence. Sources run concurrently, under one deadline.
3. **Check each source's grants against that source's capability** (§5.2), and drop anything outside it. Dropped grants are logged with the source ID.
4. **Union** the surviving grants, deduplicated by (FQN, action) with provenance kept. Then **apply constraints** (§5.5), which can only remove. Produce **one** `EntityRepresentation`: `DirectEntitlements` holds the union, and `AdditionalProps` holds each source's properties under that source's own key (for example `.patreon`).

The order of sources has no effect. Two sources may grant the same FQN only if both are authorised for it. The result is idempotent.

### 5.2 Source capabilities (trust model, phase 1)

Each source is configured with a capability:

- **issuer:** whose signed evidence it may read, e.g. `https://identity.arkavo.net`;
- **grants:** the attribute definitions it may grant values in, optionally narrowed to a value prefix;
- **actions:** default `read`;
- **subjects:** person, agent, device.

FQNs are parsed structurally (namespace, definition, value), never matched as raw string prefixes.

**My call: one owner per attribute definition,** following kimi's partition:
- the `patreon` source owns `https://patreon.arkavo.com/attr/campaign` and `…/campaign-tier`;
- the `identity-core` source owns only the definitions it is listed for, such as `…/arkavo-creator` (the publish entitlement, which shares the `patreon.arkavo.com` namespace);
- `identity-core` never grants `campaign` or `campaign-tier`, even though the same `arkavo_entitlements` array carries them.

So a namespace is not the unit of ownership; a definition is.

When a future definition must be shared, for example a purchase and a membership both unlocking one `anyOf` definition, each source gets a disjoint **value prefix** within it.

**What phase 1 does not isolate.** All token-carried evidence today is signed by one issuer, authnz-rs. A compromised authnz-rs can mint anything its sources are authorised to read. Capabilities stop one source's *logic* from granting another's namespace. They do not stop a compromised signer.

Isolation from the signer needs per-source signed evidence, or authenticated live sources (§10). That's for the owner to decide later; this design leaves room for it.

### 5.3 Verified evidence

Two inputs exist today:

- **Token entities**, on the licence route. `DecodeClaimsFromToken` (`service/internal/auth/cwt_verifier.go`) decodes and explicitly does **not** verify. It relies on an upstream check that, on this route, covers arks's service credential, not the viewer token inside `entityIdentifier`.

  **My call:** the composite verifies every entity token itself against the configured issuer's COSE key set. That covers signature, issuer, expiry, and the audience `https://platform.arkavo.net`. Only verified claims reach sources. The platform already has a CWT verifier in the same file.

- **Claims chains**, on the catalog route through `GetDecisionMultiResource`: the claims were verified by the calling node (tdf-iroh-s3 `catalog_api.rs`, `build_chain`), not by the platform.

  **My call:** accept claims chains only from allowlisted PEP client IDs, and feed them only to sources marked `pep_assertable`. The `arkavo_trusted` marker is never proof on its own. The preferred end state is for PEPs to pass the original token, so §5.3's first rule covers them too.

### 5.4 The source interface

```
Resolve(ctx, subject, query) -> (Resolution, error)

subject    = verified claims, subject kind (person | agent | device), stable account ID
query      = action, requested resources or attribute definitions (when the route supplies them), deadline
Resolution = grants[{fqn, actions, expires_at}], properties (map), outcome
outcome    = complete | not_applicable | unavailable | invalid
```

- **Token-carried sources** do no I/O. They read verified claims and return grants that expire with the token. Examples: `patreon` (memberships plus the Patreon entries of `arkavo_entitlements`) and `identity-core`.
- **Live sources** call a configured, authenticated endpoint, never a URL taken from the token. They pass the stable account ID and the requested items.
  - **Cache:** keyed by (source, account, query, evidence version), with single-flight and a bounded size. The TTL is the smallest of the source's lease, the token's remaining life and the configured maximum.
  - **Failure:** fails closed. If a live source relevant to the request is `unavailable`, that request gets no ALLOW from it, and stale results are never served after an error. Sources not relevant to the requested definitions are not called.
- **Requested scope:** `CreateEntityChainsFromTokensRequest` already carries the requested `resources` (`entity_resolution.proto`, marked experimental), and the PDP passes them on the token route. Sources may use them to answer only for the definitions in play. `ResolveEntitiesRequest` doesn't carry them (§6).

### 5.5 Constraints (subtractive, applied after the union)

- **Agent gate:** a subject carrying the agent marker is checked live against authnz-rs agent status (`service/entityresolution/arkavo/v2/agent_gate.go`, `service/internal/agentstatus`). If it is withheld or unavailable, the subject gets no grants. *Open question:* the timeout (§11.1).
- **Device ceilings:** a device class caps what the subject may hold; it never adds. Today `arkavo` mode's `directEntitlements` *appends* ceiling FQNs as grants (`service/entityresolution/arkavo/v2/entity_resolution.go`), so the composite must not copy that.
  - **Phase 1:** applies when the device token is itself the subject.
  - **Phase 2:** applies when a device token comes with a person in the catalog chain. This needs an authorization change (§6), because environment entities are skipped.

### 5.6 Token size

1. **Now:** keep the flat `arkavo_entitlements` array, and have authnz-rs mint it per audience, so the platform audience gets only platform-relevant FQNs.
2. **When a defined byte cap is reached:** scope by namespace, or replace part of the array with an `entitlements_ref` (account, snapshot version, digest), resolved by a live source of the same name. Never truncate silently. A digest proves consistency, not current non-revocation.

## 6. What fits the existing APIs, and what doesn't

**Fits the ERS as it is (no proto change):**
- the composite as a new registration in `NewRegistration`;
- `DirectEntitlement{attribute_value_fqn, actions}`;
- `AdditionalProps` for subject mappings;
- token verification;
- token-carried and subject-wide live sources;
- the agent gate as "no grants".

**Needs an authorization change (phase 2, not needed for the creator fix):**
- **Resource scope in `ResolveEntities`.** It doesn't carry action or resources. Either add them, or route claims chains through a decision-scoped resolution call.
- **True person-plus-device constraints.** Environment entities are skipped in `JustInTimePDP`, and constraints must apply after subject mappings and direct grants are merged, not only to direct grants.
- **Per-resource `UNAVAILABLE`,** so a live-source outage can be told apart from a deny. Today an ERS error becomes "could not decide", which arks maps to 503.

**Also turn on:** `enforce_namespaced_entitlements: true` (`service/authorization/v2/config.go`), as the Patreon README already recommends.

## 7. Config sketch (illustrative, not deployable)

Based on kimi's sketch, the most conservative of the three.

```yaml
services:
  authorization:
    policy_file: /etc/opentdf/policy.patreon.yaml
    allow_direct_entitlements: true
    enforce_namespaced_entitlements: true

  entityresolution:
    # presence of `sources` selects the composite; `mode` remains only until migration ends
    deadline: 300ms
    evidence:
      issuers:
        - issuer: https://identity.arkavo.net
          cose_keys_url: https://identity.arkavo.net/.well-known/cose-keys
          audience: https://platform.arkavo.net
      verify_entity_tokens: true
      claims_chain_peps: [client:catalog-node]      # allowlisted PEP client IDs

    sources:
      - id: patreon
        type: patreon-token
        issuer: https://identity.arkavo.net
        claims: [arkavo_patreon, arkavo_entitlements]
        grants:
          - https://patreon.arkavo.com/attr/campaign
          - https://patreon.arkavo.com/attr/campaign-tier
        legacy_membership_derivation: true          # today's passthroughResolution, for parity
        properties_key: patreon                     # keeps .patreon.* subject mappings
        infer_unknown_as_free: true
        pep_assertable: true

      - id: identity-core
        type: token-claims
        issuer: https://identity.arkavo.net
        claim: arkavo_entitlements
        grants:
          - https://patreon.arkavo.com/attr/arkavo-creator   # the publish entitlement
        pep_assertable: false

      # later, shape only:
      # - id: stripe
      #   type: live-http            # or token-claims, once researched
      #   grants: [https://<offer-or-item definition>]   # see §11.2
      #   timeout: 250ms
      #   fail: closed

    constraints:
      agent_status:
        url: https://identity.arkavo.net
        timeout: <open question §11.1>
        on_failure: withhold
      device_class_ceilings:
        unverified: []      # ceilings intersect, never add
```

## 8. Migration, and how the creator case gets fixed

The creator case fails on **two routes**. The composite alone fixes only one of them.

| Decision | Route | What it needs |
|---|---|---|
| FairPlay licence (Play) | arks → `GetDecision`, token entity (`pdp.rs`) | The composite with the `patreon` source reading the Patreon entries of `arkavo_entitlements` |
| Catalog `entitled` | tdf-iroh-s3 → AuthZEN (the default) → arks `translate.rs` → platform | The composite, **and** a change to arks `pe_claims` (`src/modules/authzen/translate.rs`), which forwards only `sub`, `iss`, `email` and a sanitised `arkavo_patreon`, and drops `arkavo_entitlements`. Its own comment flags this |

Arks's AuthZEN translation is PEP-supplied and unsigned. So the fix is either to carry the viewer token through to the platform, which the composite then verifies (preferred), or to forward `arkavo_entitlements` only for allowlisted PEPs and only to `pep_assertable` sources. Otherwise switch the catalog node to `protocol = "opentdf-v2"` (`tdf-iroh-s3 src/config.rs`), whose claims chain already forwards `arkavo_entitlements`.

**Steps:**
1. **Pre-checks, read-only:**
   - Confirm prod's ERS `mode` and the catalog node's `protocol`.
   - Confirm that arks verifies the viewer CWT before calling `GetDecision`, and that the identity token's audience includes the platform.
2. **Build the composite** behind `sources:`, with `patreon`, `identity-core` and the agent gate. Run parity tests against today's `patreon` mode:
   - patrons: active, declined and former;
   - free followers (`infer_unknown_as_free`);
   - creators;
   - a cross-campaign deny, for example a tier of campaign A never satisfies campaign B;
   - expired or forged tokens;
   - agents;
   - a claims chain from a PEP not on the allowlist.
3. **Shadow in prod:** evaluate both and log the differences on licence and catalog traffic. Expected difference: creators only.
4. **Switch the licence route.** The creator's Play now works.
5. **Fix the catalog route** (arks `pe_claims`, or the node's protocol), then switch it. Creator rows unlock.
6. **Retire `mode`.** Later, retire `legacy_membership_derivation` once telemetry shows that no tokens rely on memberships alone. authnz-rs's `campaign_entitlements` becomes the single Patreon derivation. Keep the `.patreon` properties for as long as subject mappings use them.

## 9. How Stripe and blockchain plug in (interface level only)

**Stripe** (owner's sketch, not researched):
- **Ingestion:** a verified webhook ingester (in authnz-rs or a small service) records purchases against Arkavo accounts, keyed by the Stripe item IDs we define.
- **Token-carried:** authnz-rs mints the purchase as an FQN into the token. The `stripe` source owns its grant space.
- **Live:** when refunds must take effect within the hour, or tokens get too large, a `stripe` live source queries the purchase ledger for the requested items. Both variants return the same `Resolution`.

**Blockchain:**
- A live source maps a verified account-to-wallet binding plus `(chain, contract, token ID)` to grants, inside the source.
- Only finalised ownership counts. Results expire by block or lease, and indexer uncertainty means no grant.
- A signed, short-lived attestation can later make it token-carried without changing the composite.

**The policy question to settle before the first Stripe-gated TDF** (§11.2): the decision engine ANDs separate definitions. A TDF tagged with a Patreon tier *and* a new Stripe item definition would require *both*. For "membership or purchase", both need to be values in one `anyOf` definition: under `campaign-tier`, a new shared `offer` definition, or something else.

## 10. Later (out of phase 1)

- **Per-source evidence envelopes:** versioned and source-scoped, optionally signed by the source, replacing the flat array. They would isolate sources from a compromised authnz-rs signer.
- **The authorization changes in §6.**
- **Freshness ceilings in authnz-rs:** `owner_fallback` reuses stored ownership and tiers after a Patreon failure. Set a maximum evidence age, so repeated mints cannot keep stale ownership alive indefinitely. Also account for the 5-minute materialisation cache on top of the token's hour.

## 11. Open questions

1. **Agent-status timeout and lease.** The peers proposed different numbers: a 5 s lease ceiling (codex, citing `service/internal/agentstatus/client.go`), a 250 ms timeout (grok) and a 3 s timeout (kimi). The builder should measure, and pick a timeout that fits the Play budget below. **Builder's call.**
2. **The shared item and offer model for "membership or purchase"** (§9). **The owner's call**, before Stripe ships, as part of the Stripe research.
3. **The Play latency budget.** The peers suggested about 300 ms for the whole resolution, with token-only sources local. arks's own HTTP timeout to the platform is 10 s. **Builder:** measure and set it.
4. **Whether phase 1 needs device ceilings with a person in the catalog chain,** or whether subject-device ceilings suffice. **Owner**, when there's a product requirement.

## 12. What's left to the builder

- Package layout for the composite and its sources.
- How the existing `patreon` and `arkavo` resolvers are refactored into sources. Prefer reusing `passthroughResolution` and `directEntitlements`, minus the ceiling append.
- Logging and metrics: grants dropped by capability, source outcomes, shadow differences.
- Test layout, including the parity matrix in §8 step 2.
- Exact config field names. The sketch in §7 is illustrative.
