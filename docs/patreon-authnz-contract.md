# Patreon entitlements: where they come from

identity.arkavo.net (authnz-rs) derives every Patreon grant once and puts
the result in the `arkavo_entitlements` claim at mint:

- per active membership, `campaign/value/<cid>` and the tier values
  `campaign-tier/value/<cid>_<slug>` and `campaign-tier/value/<cid>_tier-<tier id>`;
- for a campaign owner, their own campaign and every tier of it.

The platform decides from that list alone. The composite entity resolver's
Patreon source ([`service/entityresolution/patreon/v2`](../service/entityresolution/patreon/v2/README.md))
keeps each well-formed `campaign` and `campaign-tier` value and never
re-derives grants from `arkavo_patreon`. That claim only feeds the `.patreon`
properties that subject mappings read. `TestArkavoEntitlementsDecide_ThroughTheV2PDP`
in `service/entityresolution/composite/v2` pins this behaviour through the v2
decision engine.

The claim shapes are defined in authnz-rs, in `.claude/rules/patreon.md`.
This file used to propose a `ResolveFanMemberships` RPC. It was never built:
claims are materialized at mint, and identity's `GET /entities/arkavo:<uuid>`
serves the same claims to service resolvers.
