# Patreon token source (v2)

This package is no longer an entity resolver of its own. It provides the
composite entity resolver's `patreon-token` source
([`../../composite/v2`](../../composite/v2)): `NewTokenSource(SourceConfig)`
returns a `source.Source` that reads Patreon grants and the `.patreon`
membership view from a verified authnz-rs token. It makes no Patreon API
calls and does no I/O. Pairs with
[`examples/config/policy.patreon.yaml`](../../../../examples/config/policy.patreon.yaml).

## What it grants

Grants come only from the token's `arkavo_entitlements` claim, which
identity.arkavo.net fills at mint. The source keeps each entry that is a
well-formed value of the two Patreon definitions in its namespace, and drops
everything else:

```
https://patreon.arkavo.com/attr/campaign/value/<campaign digits>
https://patreon.arkavo.com/attr/campaign-tier/value/<campaign digits>_<slug>
```

The slug is `[a-z0-9-]+`, so the first `_` splits a tier value
unambiguously. Tiers are campaign-qualified, in each creator's own tier
vocabulary, so a tier at one creator never satisfies another's gate. Every
grant carries the action `read`. The composite still drops any grant outside
the definitions the source is configured to own.

Attribute *values* are dynamic (resolved as synthetic values when
`allow_direct_entitlements` is on), so onboarding a creator needs no policy
change; only the definitions must exist.

## What it surfaces

The `arkavo_patreon` claim (the consumer's memberships, materialized by
identity.arkavo.net) feeds only the flattened `.patreon` view: `status`,
`tier_slug`, `campaign_ids` and the rest of `Membership`, for coarse subject
mappings. It grants nothing. Only active memberships with a numeric campaign
id count towards `status: active` and `campaign_ids`; a creator's own
`campaign_id` is listed too. The composite puts the view under the source's
`properties_key`.

A subject with no `arkavo_patreon` claim gets no view, or, with
`infer_unknown_as_free`, the free view (`tier_slug: free`,
`status: former`). The outcome is `complete` when there is a grant or a
view, and `not_applicable` otherwise.

## Configuration

One entry under the composite's `sources`
([`docs/Configuring.md`](../../../../docs/Configuring.md#composite-resolver)):

```yaml
services:
  entityresolution:
    sources:
      - id: patreon
        type: patreon-token
        issuer: https://identity.arkavo.net
        grants:
          - https://patreon.arkavo.com/attr/campaign
          - https://patreon.arkavo.com/attr/campaign-tier
        properties_key: patreon      # keeps .patreon.* subject mappings
        pep_assertable: true         # also reads the catalog node's claims chains
        # Options read by this source:
        entitlements_namespace: patreon.arkavo.com   # the default
        infer_unknown_as_free: true
```

Any other option key is a startup error. The authorization service must set
`allow_direct_entitlements: true` for the dynamic values to be honoured.

## Agents

The source does not judge agents. The composite's agent gate
(`constraints.agent_status`, see
[`../../arkavo/v2/README.md`](../../arkavo/v2/README.md#agent-status)) runs
before any source, and withholds every agent subject while it is unset.

## Testing

```bash
cd service && go test ./entityresolution/patreon/...
```
