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
| authnz-rs | PR #100, merged as `a07cae2` and deployed 2026-10-17 |

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
5. Fix the creator case: a creator is entitled to every tier of every campaign they own, on every route (licence, KAS rewrap and catalog). Their token carries those entitlements, and every route treats them exactly like a patron's.
6. Keep every current patron permitted, and keep the `.patreon.*` subject-mapping behaviour, across the cutover.

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
- Branching on `role`, or on any notion of "creator", in a PEP or a source. The catalog node, arks and the platform can't tell a creator from a viewer, and must not need to. A creator's access arrives as entitlements in the token, in the same shape as a patron's.

## 3. Constraints

- **Policy semantics are fixed:** OR within an attribute definition (`anyOf`), AND across definitions (`service/internal/access/v2/evaluate.go`). Patreon content needs `campaign/<cid>` AND one of its listed `campaign-tier/<cid>_<slug>` values.
- **Synthetic values:** dynamic values such as campaign IDs and tier slugs need `allow_direct_entitlements: true`. The PDP then synthesises the value under an existing definition (`service/internal/access/v2/helpers.go`, `getResourceDecisionableAttributes`).
- **One representation per subject:** `JustInTimePDP.GetDecision` (`service/internal/access/v2/just_in_time_pdp.go`) requires every entity representation it evaluates to be permitted. Environment entities are skipped (`skipEnvironmentEntities`).
- **Three routes reach the same ERS:**
  - *Licence:* arks calls `GetDecision` with the viewer's CWT as `entityIdentifier.token.jwt` (`arkavo-rs src/modules/license/pdp.rs`).
  - *Catalog:* tdf-iroh-s3's `GET /catalog/<campaign>` calls either `GetDecisionMultiResource` with a claims chain, or AuthZEN through arks (`tdf-iroh-s3 src/authz.rs`; AuthZEN is the default).
  - *KAS rewrap:* `service/kas/access/accessPdp.go` calls `GetDecisionMultiResource` with the request's bearer as the token entity. Standard TDF rewraps reach the platform through arks's Connect proxy (`/kas.AccessService/*`). It is the one route where the bearer *is* the subject token, so it's the only one where an agent's proof of possession is checked (`ipcReauthRoutes`, `service/internal/auth/authn.go`). **In scope:** it is tested and cut over with the other routes (§8).
- **The token route makes two ERS calls:** `JustInTimePDP` calls `CreateEntityChainsFromTokens` with the token and the requested resources, then `ResolveEntities` on the claims chain that comes back (`just_in_time_pdp.go`). The token, and the resources, exist only in the first call. The `EntityRepresentation` is built in the second. Both calls arrive with the calling service's client ID (`IPCMetadataClientInterceptor`, `authn.go`), so on the licence route the second call looks like `arks-media` sending a claims chain of its own.
- **Tokens:** CWT, ES256, issuer `https://identity.arkavo.net`, one-hour lifetime. Patreon data is materialised at mint and cached for 5 minutes.
- **Revocation baseline:** the token's lifetime. *My call, pending the Stripe research*, agreed in conversation as the default; sources that need faster revocation are looked up live.

## 4. Decided by the owner

- No single mode. All applicable behaviours run together, for many source types. Stripe is next and blockchain later; neither is researched.
- Stripe sketch: we define item IDs in Stripe, purchases reach our platform, the purchase becomes an entitlement in the CWT, and at Play the token is matched against the item ID in the TDF's policy and allowed. If tokens grow large, entitlements may need to be scoped or looked up remotely.
- The shape comes before the quick creator fix.
- "Creator" means the account owns a Patreon campaign, as Patreon reports it (authnz-rs #100). It does not mean a role a client asserted.
- "A Creator should have all their campaigns entitled." The catalog can't tell a viewer from a creator, so a creator's own content must get the same answer on the catalog route as at Play. The fix belongs in what reaches the platform, not in creator-specific handling anywhere.
  - *My call, following from that:* the catalog route is part of phase 1, not deferred.
- "Do hard cutovers, we are pre-release" (2026-10-17). No shadow period and no legacy compatibility path.
  - *My reading of it:* the `patreon` and `arkavo` modes are deleted in the same change that adds the composite; the platform stops deriving Patreon grants from `arkavo_patreon` memberships and reads them only from `arkavo_entitlements`; upstream's own `mode` values are left alone; `mode` and `sources` together is a startup error.
  - authnz-rs reads the owned campaign from Patreon's `/identity` `campaign` relationship, which is to-one (`find_campaign_id`, `src/patreon.rs`). The composite takes whatever set of grants the token carries, so it doesn't depend on that count.

## 5. The design

### 5.1 One composite resolver

Add a composite ERS, registered when `services.entityresolution.sources` is present. The `patreon` and `arkavo` modes are deleted in the same change (§4, §8). Upstream's own `mode` values stay, and setting `mode` together with `sources` is a startup error.

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

There are two kinds of input, and the token route spans two calls (§3).

**Token entities** (licence and KAS rewrap routes). `DecodeClaimsFromToken` (`service/internal/auth/cwt_verifier.go`) decodes and explicitly does **not** verify. It relies on an upstream check. On the licence route that check covers arks's service credential, not the viewer token inside `entityIdentifier`.

**My call: sources run in the first call, and their result is sealed for the second.**
- In `CreateEntityChainsFromTokens`, the composite verifies the entity token against the configured issuer's COSE key set: signature, issuer, expiry, and the audience `https://platform.arkavo.net`. The platform already has a CWT verifier in the same file. Then it runs the sources, which receive the requested resources this call carries (§5.4), and the constraints.
- It writes the result into the returned chain's claims as an `arkavo_evidence` object: the unioned grants, per-source properties, outcomes, subject and expiry. This is sealed with an HMAC under a key only the ERS holds, configured as `evidence.seal_key`.
- In `ResolveEntities`, a claims entity with a valid, unexpired seal becomes its `EntityRepresentation` directly, without re-running sources.

This replaces the `arkavo_trusted` boolean (`arkavo/v2/entity_resolution.go`), which any caller can forge. It needs no proto change. The rejected alternatives:
- allowlisting `arks-media` would let arks assert arbitrary chains;
- carrying the raw token into the second call would put the bearer in claims and verify it twice.

**Claims chains without a seal.** These come from PEPs that verified the token themselves: the catalog route, as `opentdf-v2` claims chains or AuthZEN through arks, which then calls the platform as `arks-media`.
- **My call:** accept them only from allowlisted PEP client IDs (`claims_chain_peps`), and feed them only to sources marked `pep_assertable`.
- A sealed chain is never treated as PEP-asserted, and an unsealed one never as verified.

### 5.4 The source interface

```
Resolve(ctx, subject, query) -> (Resolution, error)

subject    = verified claims, subject kind (person | agent | device), stable account ID
query      = action, requested resources or attribute definitions (when the route supplies them), deadline
Resolution = grants[{fqn, actions, expires_at}], properties (map), outcome
outcome    = complete | not_applicable | unavailable | invalid
```

- **Token-carried sources** do no I/O. They read verified claims and return grants that expire with the token. Examples: `patreon` (the Patreon entries of `arkavo_entitlements`, plus the `.patreon` membership view read from `arkavo_patreon`), `identity-core` and `device-class`.
- **Live sources** call a configured, authenticated endpoint, never a URL taken from the token. They pass the stable account ID and the requested items.
  - **Cache:** keyed by (source, account, query, evidence version), with single-flight and a bounded size. The TTL is the smallest of the source's lease, the token's remaining life and the configured maximum.
  - **Failure:** fails closed. If a live source relevant to the request is `unavailable`, that request gets no ALLOW from it, and stale results are never served after an error. Sources not relevant to the requested definitions are not called.
- **Requested scope:** `CreateEntityChainsFromTokensRequest` already carries the requested `resources` (`entity_resolution.proto`, marked experimental), and the PDP passes them on the token route. Because sources run in that call (§5.3), they can use the resources to answer only for the definitions in play. Unsealed claims chains reach only `ResolveEntities`, which carries no resources (§6), so sources answer subject-wide there.

### 5.5 Constraints (subtractive, applied after the union)

- **Agent gate:** a subject carrying the agent marker is checked live against authnz-rs agent status (`service/entityresolution/arkavo/v2/agent_gate.go`, `service/internal/agentstatus`). If it is withheld or unavailable, the subject gets no grants. *Open question:* the timeout (§11.1).
- **Device caps:** a device class may cap what the subject holds; a constraint never adds. Today `arkavo` mode's `directEntitlements` *appends* `device_class_ceilings` FQNs as grants (`service/entityresolution/arkavo/v2/entity_resolution.go`). That is a grant, not a cap.
  - *My call, needed to retire `arkavo` mode:* it becomes a `device-class` **source**. For a device subject it grants the FQNs configured for its `arkavo_npe.class` (default `unverified`), only within the definitions it owns, like any other source. Every configured FQN must fall within those definitions, or startup fails.
  - **Naming:** the composite uses a new key, `device_class_caps`, so no existing `device_class_ceilings` config silently inverts. A class missing from the map means **no cap**.
  - **Phase 1:** configures no caps. Device-subject tokens keep the person's grants, as today. authnz-rs mints only the `attested` and `managed` classes (`src/device_check.rs`), and device tokens carry the full user claims.
  - **Later:** what each class should be capped to is the owner's decision (§11.4). Caps on a device that comes with a person in the catalog chain need an authorization change (§6), because environment entities are skipped.

### 5.6 Token size

1. **Phase 1:** keep the flat `arkavo_entitlements` array as it is. No authnz-rs or client change.
2. **Later, not part of this build:**
   - **Per-audience minting:** the viewer token is one CWT with `aud = ["arkavo", <platform>]`, and arks requires both (`arkavo-rs src/modules/license/person_token.rs`). So per-audience minting means a second token, or claims that depend on the audience. Either way it changes authnz-rs and the client apps.
   - **Beyond a defined byte cap:** scope by namespace, or replace part of the array with an `entitlements_ref` (account, snapshot version, digest), resolved by a live source of the same name. Never truncate silently. A digest proves consistency, not current non-revocation.

## 6. What fits the existing APIs, and what doesn't

**Fits the ERS as it is (no proto change):**
- the composite as a new registration in `NewRegistration`;
- `DirectEntitlement{attribute_value_fqn, actions}`;
- `AdditionalProps` for subject mappings;
- token verification and the sealed evidence that carries it to `ResolveEntities` (§5.3);
- token-carried and live sources;
- the agent gate as "no grants".

**Needs an authorization change (phase 2, not needed for the creator fix):**
- **Resource scope in `ResolveEntities`.** It doesn't carry action or resources. Either add them, or route claims chains through a decision-scoped resolution call.
- **True person-plus-device constraints.** Environment entities are skipped in `JustInTimePDP`, and constraints must apply after subject mappings and direct grants are merged, not only to direct grants.
- **Per-resource `UNAVAILABLE`,** so a live-source outage can be told apart from a deny. Today an ERS error becomes "could not decide", which arks maps to 503.

**Leave `enforce_namespaced_entitlements` off in phase 1.**
- **Why:** in strict mode the PDP skips every subject mapping that has no namespace (`service/internal/access/v2/pdp.go`), logging it only at trace level. The policy-file loader builds subject mappings without a `Namespace` (`service/policy/filestore/store.go`). Turning it on would silently drop the `.patreon.status` and benefit mappings, against Goal 6.
- **What covers it instead:** the composite's capability check does the namespace isolation for direct grants.
- **To enable it later:** the loader must first set namespaces on policy-file mappings.

## 7. Config sketch (illustrative, not deployable)

Based on kimi's sketch, the most conservative of the three.

```yaml
services:
  authorization:
    policy_file: /etc/opentdf/policy.patreon.yaml
    allow_direct_entitlements: true
    # enforce_namespaced_entitlements stays off in phase 1 (§6)

  entityresolution:
    # presence of `sources` selects the composite; setting `mode` as well is a startup error
    deadline: 300ms
    evidence:
      issuers:
        - issuer: https://identity.arkavo.net
          cose_keys_url: https://identity.arkavo.net/.well-known/cose-keys
          audience: https://platform.arkavo.net
      verify_entity_tokens: true
      seal_key: ${ERS_EVIDENCE_SEAL_KEY}            # HMAC key for arkavo_evidence (§5.3)
      claims_chain_peps: [<arks's client ID, from the pre-check>]   # PEPs whose unsealed chains are accepted

    sources:
      - id: patreon
        type: patreon-token
        issuer: https://identity.arkavo.net
        claims: [arkavo_patreon, arkavo_entitlements]
        grants:
          - https://patreon.arkavo.com/attr/campaign
          - https://patreon.arkavo.com/attr/campaign-tier
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

      # local agent testing (opentdf-arkavo-local-test.yaml), not prod:
      # - id: device-class
      #   type: device-class
      #   issuer: https://identity.arkavo.net
      #   grants: [https://arkavo.ai/attr/classification]
      #   classes:
      #     unverified: [https://arkavo.ai/attr/classification/value/internal]
      #     managed:    [https://arkavo.ai/attr/classification/value/confidential]
      #     attested:   [https://arkavo.ai/attr/classification/value/restricted]

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
      device_class_caps: {}   # phase 1: no caps; a missing class means no cap; caps intersect, never add (§5.5)
```

## 8. Cutover, and how the creator case gets fixed

The creator case fails on every route. The composite alone fixes the token routes, but not the catalog.

| Decision | Route | What it needs |
|---|---|---|
| FairPlay licence (Play) | arks → `GetDecision`, token entity (`pdp.rs`) | The composite, with the `patreon` source reading the Patreon entries of `arkavo_entitlements` |
| KAS rewrap (standard TDF) | arks Connect proxy → platform KAS → `GetDecisionMultiResource`, bearer as the token entity (`accessPdp.go`) | The same as the licence |
| Catalog `entitled` | tdf-iroh-s3 → AuthZEN (the default) → arks `translate.rs` → platform as `arks-media` | The composite, **and** a catalog-route change, because arks's `pe_claims` (`src/modules/authzen/translate.rs`) forwards only `sub`, `iss`, `email` and a sanitised `arkavo_patreon`, and drops `arkavo_entitlements`. Its own comment flags this |

**The catalog-route change (phase 1, per the owner's decision in §4).** *My call on the mechanism:* arks's `pe_claims` also forwards `arkavo_entitlements`, sanitised the way `sanitize_patreon` already treats `arkavo_patreon`:
- it keeps only FQNs in the definitions the `patreon` source owns (`campaign`, `campaign-tier`), at most a fixed count;
- it forwards them for every viewer, with no role check;
- the composite then accepts them only from `arks-media`, and only into `pep_assertable` sources (§5.3).

This keeps the AuthZEN facade, its device and environment entities, and the rule that CWTs are never sent as `EntityIdentifier.token` (arkavo-rs `docs/platform-proxy.md`; draft-arkavo-authzen-cwt-00). It does add a subject property to that draft. The trust is the same arks already extends to `arkavo_patreon` from the catalog node, which verifies the CWT before asking. With the membership derivation gone (step 2 below), patrons on the catalog route depend on this change too, so arks must be live before the platform cuts over.

Rejected alternatives:
- **tdf-iroh-s3 `ConnectAuthzClient` in `entity_mode = token`** (`src/authz.rs`) needs no arks change, and its comment that CWTs fail the ERS parse is stale. But it drops the device entities. Also, tdf-iroh-s3 checks the person token's issuer, not its audience (`src/auth.rs`), so the composite's audience check could reject tokens the catalog accepts today.
- **`protocol = "opentdf-v2"`** is labelled rollback-only in tdf-iroh-s3 (`src/config.rs`).

**Steps (hard cutover, §4):**
1. **Pre-checks, read-only.** They block the cutover, since no shadow period will catch a mistake:
   - the catalog node's `protocol`;
   - arks's client ID as the platform sees it, which becomes `claims_chain_peps`;
   - that the identity token's audience includes the platform;
   - that standard TDF rewraps reach this platform's KAS and ERS. The prod config draft says `-kas`, while arks's `KAS_PROXY_MODE` forwards `/kas.AccessService/Rewrap` to a co-located platform.
2. **Build the composite** with `patreon`, `identity-core`, `device-class` and the agent gate, and **delete the `patreon` and `arkavo` modes** in the same change. Their reusable parts (claim parsing, the `.patreon` view, the agent gate) move behind the sources.
   - **One Patreon derivation.** The platform no longer derives grants from memberships. authnz-rs has put every active membership's campaign and tier values in `arkavo_entitlements` since #95, so that array is the single source. The #96 id-shaped slug filter is moot on the platform; it stays in authnz-rs, where titles are slugified.
   - **Tests:**
     - patrons: active, declined and former;
     - free followers (`infer_unknown_as_free`);
     - creators;
     - a cross-campaign deny, for example a tier of campaign A never satisfies campaign B;
     - expired, forged, unsigned (`alg=none`) and untrusted-issuer tokens;
     - a forged or expired `arkavo_evidence` seal;
     - agents;
     - an unsealed claims chain from a PEP not on the allowlist;
     - what the deleted modes' tests covered: CBOR-native claim values, and the agent gate through the v2 PDP.
3. **Deploy arks** (the catalog-route change) and confirm it is live. Under today's `patreon` mode it changes nothing.
4. **Cut over the platform:** deploy with `sources:` configured. All three routes switch at once, so there is no window where Play works and the creator's rows stay Locked. Verify a creator's Play, download and catalog listing, a patron's Play and catalog listing, and a KAS rewrap. Rollback is redeploying the previous build and config.

**Not carried over:** the platform's RAR endpoint (`service/authorization/v2/rar.go`) hands the ERS an unsigned-JWT bridge for a CWT subject token. The composite accepts only verified CWTs, so RAR would get no grants. No config enables RAR; if it is enabled later, it must hand the ERS the original CWT.

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
4. **What each device class should be capped to,** if anything. Phase 1 configures no caps, and device tokens keep the person's grants. **The owner's call**, when there's a product requirement.
5. **Settled: the catalog route.** The owner decided that a creator gets the same answer on every route, with no creator-specific handling (§4). The mechanism, arks forwarding the filtered `arkavo_entitlements` (which adds a subject property to draft-arkavo-authzen-cwt-00), is my call (§8).

## 12. What's left to the builder

- Package layout for the composite and its sources.
- How the existing `patreon` and `arkavo` resolvers are refactored into sources. Prefer reusing `passthroughResolution` (plus the #96 filter) and `directEntitlements` (minus the ceiling append).
- The `arkavo_evidence` encoding, the HMAC construction and key rotation for `seal_key`, and its expiry, which is no later than the token's.
- Logging and metrics: grants dropped by capability, source outcomes, unsealed chains refused because the caller isn't allowlisted.
- Test layout, including the test list in §8 step 2.
- Exact config field names. The sketch in §7 is illustrative.
