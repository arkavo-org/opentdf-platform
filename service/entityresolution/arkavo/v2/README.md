# Arkavo Entity Resolution Provider (v2)

An Arkavo-backed Entity Resolution Service (ERS) for distributed identity and
authorization within the Arkavo ecosystem. It accepts both JOSE (JWT) and COSE
(CWT) tokens carrying materialized `arkavo_entitlements` claims, verified by
a trusted authnz-rs issuer, and translates those claims directly into platform
entitlements. Pairs with
[`examples/config/policy.arkavo.yaml`](../../../../examples/config/policy.arkavo.yaml).

## What it does

When a subject's claims carry the `arkavo_entitlements` claim (in JWT or CWT
form), the provider emits **direct entitlements** per claim assertion — in the
entitlements namespace with dynamic attribute values:

```
https://arkavo.ai/attr/classification/value/<classification>
https://arkavo.ai/attr/action/value/<action>
https://arkavo.ai/attr/mesh/value/<mesh_role>
```

Attribute *values* are dynamic (resolved as synthetic values when
`allow_direct_entitlements` is on), so onboarding agents requires zero policy
changes. The provider also surfaces a flattened `.arkavo.*` view for legacy
subject mappings derived from the same claim.

It also supports Non-Person Entities (NPE) — service accounts and agents — by
resolving their client IDs and applying device class ceilings (e.g., an
`unverified` agent can only access `internal` data).

## Configuration

```yaml
services:
  entityresolution:
    mode: arkavo

    # SECURITY: the materialized arkavo_entitlements claim is authoritative.
    # Off by default; enable only when every decision caller reaches the ERS
    # through a trusted channel (the platform's verified-token path, or a
    # role:standard PEP that verified the subject token). Pin the materializer
    # with trusted_issuer.
    trust_materialized_claims: true
    trusted_issuer: http://127.0.0.1:8081

    # Platform actions (read, create, update, delete) that direct entitlements
    # may grant. `decrypt` is NOT an action — it appears only as an attribute
    # value under the `tdf` attribute.
    direct_entitlement_actions: [read]

    # Device class ceilings: non-person entities (NPE) with a device_class
    # attribute value are capped to the corresponding classification level.
    # A device can only access data at its ceiling or lower.
    device_class_ceilings:
      unverified: ["https://arkavo.ai/attr/classification/value/internal"]
      managed:    ["https://arkavo.ai/attr/classification/value/confidential"]
      attested:   ["https://arkavo.ai/attr/classification/value/restricted"]

    # JWT claim overrides (defaults shown). These control which claim names
    # carry the entitlements, client ID, and user ID.
    client_id_claim: arkavo_account_id
```

The authorization service must also set `allow_direct_entitlements: true`
(and typically `enforce_namespaced_entitlements: true`) for the dynamic
values to be honored.

## Trust Model

Arkavo entitlements are signed upstream at authnz-rs and verified by the
platform's token validation layer before reaching the ERS. The provider uses
a two-path resolution model with different trust semantics on each path,
unified by the `arkavo_trusted` marker and the `trust_materialized_claims`
master switch.

### The `arkavo_trusted` Marker

When `CreateEntityChainsFromTokens` processes a token, it checks the issuer
against `trusted_issuer` (if `trust_materialized_claims` is on). If the check
passes, it stamps `arkavo_trusted: true` onto the SUBJECT entity's claims,
along with `arkavo_entitlements` and the raw `arkavo_npe` data. This marker
carries the issuer decision forward into the claims-entity path.

### Two-Path Resolution

**Token path** (`CreateEntityChainsFromTokens`):
- Token signature is verified by platform authn middleware (before reaching ERS)
- If `trust_materialized_claims` is on: issuer comparison against `trusted_issuer` is enforced here
- If check passes: `arkavo_trusted: true` marker is set
- If check fails or `trust_materialized_claims` is off: no marker, no entitlements

**Claims-entity path** (`ResolveEntities`):
- Caller supplies an Entity_Claims payload (may have originated elsewhere)
- The issuer comparison is NOT redone on this path — only the `arkavo_trusted` marker is checked
- If `trust_materialized_claims` is on AND `claims["arkavo_trusted"] == true`: direct entitlements are emitted
- If either condition is false: no entitlements

Critically: a caller who can construct or forward a claims entity with a forged
`arkavo_trusted: true` marker will bypass the `trusted_issuer` pin on the
claims-entity path. The operator's protection on that path is **the PEP
boundary** — `ResolveEntities` must be reachable only through a trusted
decision layer. The `trust_materialized_claims` flag is the master switch
that gates entitlements on both paths, but only the token path can enforce
the issuer pin; the marker is what carries that decision to the second pass.

When `trust_materialized_claims: false`, entitlements are disabled on both paths
entirely — no marker check avoids this setting.

### Entity Resolution Flow

1. **Token arrives at ERS**: JWT (JOSE) or CWT (COSE), signature already verified
   by the platform's authn middleware.
2. **Issuer check (token path only)**: If `trust_materialized_claims` is on,
   verify that the token's `iss` claim matches `trusted_issuer` (or skip if
   `trusted_issuer` is empty).
3. **Marker and claims storage**: If the issuer check passes, set
   `arkavo_trusted: true` and store `arkavo_entitlements` and `arkavo_npe` in
   the SUBJECT entity's claims.
4. **Entity synthesis**: Create a SUBJECT entity carrying the claims, and an
   ENVIRONMENT entity if the token includes an `arkavo_npe` block.
5. **Claims-entity resolution**: On the second pass, `ResolveEntities` checks
   `trust_materialized_claims && claims["arkavo_trusted"] == true` to decide
   whether to emit direct entitlements.
6. **Direct entitlements emission**: Convert `arkavo_entitlements` into platform
   attribute FQNs (e.g., `https://arkavo.ai/attr/classification/value/restricted`).
7. **Device ceiling**: If the subject is a device NPE (non-person entity), apply
   the ceiling for its device class.

Subject mappings are not used — all authorization flows through direct
entitlements and the policy snapshot vocabulary.

## Testing

```bash
cd service && go test ./entityresolution/arkavo/...
```

No outbound Arkavo or authnz-rs calls — tests exercise claims passthrough
directly with mocked JWT/CWT payloads.
