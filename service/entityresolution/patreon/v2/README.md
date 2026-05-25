# Patreon Entity Resolution Provider (v2)

A Patreon-backed Entity Resolution Service (ERS) that resolves a subject's
Patreon membership state and surfaces it as policy claims under the
`.patreon.*` selector tree. Pairs with
[`examples/config/policy.patreon.yaml`](../../../../examples/config/policy.patreon.yaml).

## What it does

For each `ResolveEntities` request entry, the provider looks the subject up in
Patreon (by user id, email, JWT claim, or forwarded user OAuth token) and
returns a representation that includes:

```jsonc
{
  "patreon": {
    "user_id": "12345",
    "email": "fan@example.com",
    "full_name": "Fan One",
    "status": "active",            // active | declined | former
    "tier_slug": "patron",         // slugified tier name; "free" if none
    "tier_amount_cents": 500,
    "campaign_ids": ["arkavo"],
    "benefits": ["early-access", "exclusive-content"]
  }
}
```

Subject mappings in `policy.patreon.yaml` key off these fields - e.g.
`.patreon.tier_slug == "patron"` grants the
`https://patreon.arkavo.com/attr/tier/value/patron` attribute value.

## Configuration

```yaml
services:
  entityresolution:
    mode: patreon
    # One of these must be set:
    creator_access_token: ${PATREON_CREATOR_ACCESS_TOKEN}
    # ...or for client_credentials refresh:
    # client_id: ${PATREON_CLIENT_ID}
    # client_secret: ${PATREON_CLIENT_SECRET}

    # Restrict member lookups to specific campaign ids (leave empty to
    # auto-list campaigns this token has access to).
    campaign_ids:
      - "12345678"

    # Return a synthetic free-tier membership when a subject is not a backer
    # (instead of returning NotFound). Useful so unauthenticated/non-Patreon
    # traffic still flows through the subject mapping engine.
    infer_unknown_as_free: true

    # JWT claim overrides (defaults shown).
    jwt:
      patreon_user_id_claim: patreon_user_id
      patreon_access_token_claim: patreon_access_token
      username_claim: preferred_username
      client_id_claim: azp
```

## Resolution strategy

`ResolveEntities` chooses a lookup path per entity type:

| Entity type      | Lookup                                                |
|------------------|-------------------------------------------------------|
| `UserName`       | Patreon user id (campaign member search)              |
| `EmailAddress`   | Patreon email (campaign member search)                |
| `ClientId`       | Treated as Patreon user id                            |
| `Claims` (JWT)   | In priority: `patreon_access_token` -> `patreon_user_id` -> `email` -> `preferred_username` |

`CreateEntityChainsFromTokens` parses each JWT (signature-unverified, like the
other ERS modes), emits an `ENVIRONMENT` entity for the `azp` client id, and
a `SUBJECT` entity whose claims are the `patreon` block above.

## Testing

```bash
cd service && go test ./entityresolution/patreon/...
```

Tests use an in-memory `MembershipAPI` stub plus an `httptest` server to
exercise pagination and JSON:API parsing. No outbound Patreon calls are made.
