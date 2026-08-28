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
platform's token validation layer before reaching the ERS. The ERS trusts
only tokens from the `trusted_issuer` pin — all other issuers are rejected.

### Entity Resolution Flow

1. **Token arrives at ERS**: JWT (JOSE) or CWT (COSE), signature already verified
   by the platform's authn middleware.
2. **Issuer check**: If `trust_materialized_claims` is on, verify that the token
   comes from the `trusted_issuer`.
3. **Claims extraction**: Extract `arkavo_entitlements`, `arkavo_account_id`
   (client ID), and other claims.
4. **Entity synthesis**: Create a SUBJECT entity carrying the entitlements claim
   and a marker indicating it was trust-gated (PEP boundary).
5. **Direct entitlements emission**: Convert each entitlement into a platform
   attribute reference (e.g., `arkavo.ai/classification/restricted`).
6. **Device ceiling**: If the subject is an NPE (non-person entity), apply the
   ceiling for its device class.

Subject mappings are not used — all authorization flows through direct
entitlements and the policy snapshot vocabulary.

## Testing

```bash
cd service && go test ./entityresolution/arkavo/...
```

No outbound Arkavo or authnz-rs calls — tests exercise claims passthrough
directly with mocked JWT/CWT payloads.
