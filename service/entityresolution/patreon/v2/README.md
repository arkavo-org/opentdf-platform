# Patreon Entity Resolution Provider (v2)

A Patreon-backed Entity Resolution Service (ERS) for the multi-creator SaaS
model. It makes **no Patreon API calls**: identity.arkavo.net materializes
every consumer's memberships into the `arkavo_patreon` CWT claim at token
mint (using the consumer's own OAuth token, which sees every campaign they
back), and this provider translates that trusted claim into entitlements.
Pairs with
[`examples/config/policy.patreon.yaml`](../../../../examples/config/policy.patreon.yaml).

## What it does

When a subject's claims carry the materialized `arkavo_patreon` claim, the
provider emits **campaign-qualified direct entitlements** per ACTIVE
membership — in the creator's own tier vocabulary, with no per-creator
config:

```
https://patreon.arkavo.com/attr/campaign/value/<campaign_id>
https://patreon.arkavo.com/attr/campaign-tier/value/<campaign_id>_<tier_slug>
```

Attribute *values* are dynamic (resolved as synthetic values when
`allow_direct_entitlements` is on), so onboarding a creator requires zero
policy changes. Declined/former memberships grant nothing, and tiers are
campaign-qualified so a tier at one creator never satisfies another's gate.

It also surfaces a flattened `.patreon.*` view (`status`, `tier_slug`,
`campaign_ids`) for coarse legacy subject mappings, derived from the same
claim.

## Configuration

```yaml
services:
  entityresolution:
    mode: patreon

    # SECURITY: the materialized arkavo_patreon claim is authoritative.
    # Off by default; enable only when every decision caller reaches the ERS
    # through a trusted channel (the platform's verified-token path, or a
    # role:standard PEP that verified the subject token — e.g. the catalog
    # node). Pin the materializer with trusted_issuer.
    trust_materialized_claims: true
    trusted_issuer: https://identity.arkavo.net

    # Namespace for emitted entitlement FQNs (default patreon.arkavo.com).
    entitlements_namespace: patreon.arkavo.com

    # A subject with no usable Patreon claim resolves as a free follower
    # instead of NotFound, so non-Patreon traffic still flows through subject
    # mappings.
    infer_unknown_as_free: true

    # JWT claim overrides (defaults shown).
    jwt:
      patreon_user_id_claim: patreon_user_id
      username_claim: preferred_username
      client_id_claim: azp
```

The authorization service must also set `allow_direct_entitlements: true`
(and typically `enforce_namespaced_entitlements: true`) for the dynamic
campaign-tier values to be honored.

## Resolution

Only a **claims** entity carrying `arkavo_patreon` resolves to a membership.
Other entity types (username/email/client id) have no Patreon source — live
lookups were removed — so they resolve as not-found (→ free when
`infer_unknown_as_free`). `CreateEntityChainsFromTokens` parses each JWT
(signature verified upstream by the platform authn layer), emits an
`ENVIRONMENT` entity for the `azp` client id, and a trust-gated `SUBJECT`
entity carrying the `patreon` block plus the preserved claim for the decision
flow's second pass.

## Testing

```bash
cd service && go test ./entityresolution/patreon/...
```

No outbound Patreon calls — tests exercise the claims-passthrough directly.
