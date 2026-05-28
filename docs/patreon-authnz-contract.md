# Patreon Entitlement Source — `authnz-rs` ↔ opentdf-platform Contract

Status: **proposal**, target implementation `arkavo-org/authnz-rs`.

This document defines the boundary between `authnz-rs` (Arkavo's identity
gateway) and the opentdf-platform Patreon Entity Resolution Service (ERS).
It exists so the Rust-side implementation can move forward without the Go
ERS having to know how OAuth, credential storage, or refresh are handled.

The current opentdf-platform branch (`claude/attribute-authority-tagging-3gTrI`)
ships:

- `examples/config/policy.patreon.yaml` — namespace, attributes, and subject
  mappings that consume the claim shape defined below.
- `service/entityresolution/patreon/v2/` — a single-creator ERS mode that
  reads a static creator token from config. **It will be refactored** to
  call `authnz-rs` over RPC instead, once the contract below is implemented.

## Architectural split

| Concern                                                | Owner            |
|--------------------------------------------------------|------------------|
| Patreon OAuth code exchange and CSRF state             | `authnz-rs`      |
| Encrypted refresh + access token storage (KMS-backed)  | `authnz-rs`      |
| Per-creator token refresh worker (lazy + scheduled)    | `authnz-rs`      |
| ConnectCreator / ListConnections / RevokeConnection    | `authnz-rs`      |
| Patreon v2 API client (member search, identity)        | `authnz-rs`      |
| `patreon.arkavo.com` namespace + attributes            | opentdf-platform |
| Subject mappings keyed off `.patreon.connections[].*`  | opentdf-platform |
| ERS mode emitting the claim block from RPC results     | opentdf-platform |

Credentials never enter opentdf-platform. The ERS holds only resolved
membership data, transiently, for the duration of one
`ResolveEntities` / `CreateEntityChainsFromTokens` call.

## The one RPC the ERS needs

```proto
service PatreonEntitlements {
  // ResolveFanMemberships returns this fan's membership state across every
  // connected creator. The ERS calls it once per inbound entity-resolution
  // request; latency budget is < 200ms p99 so authnz-rs must cache
  // aggressively (per-creator memberships have a natural TTL since the
  // Patreon webhook lifecycle is creator-scoped).
  rpc ResolveFanMemberships(ResolveFanMembershipsRequest)
      returns (ResolveFanMembershipsResponse);
}

message ResolveFanMembershipsRequest {
  // Exactly one of these identifies the fan. The ERS supplies whatever the
  // inbound entity carried.
  oneof identifier {
    string patreon_user_id = 1;
    string email           = 2;
    // Forwarded backer OAuth token (when the JWT carried one) — authnz-rs
    // uses /identity directly instead of campaign member search.
    string user_access_token = 3;
  }

  // Optional - restrict to a subset of connected creators. Empty = all.
  repeated string creator_ids = 4;
}

message ResolveFanMembershipsResponse {
  repeated Membership connections = 1;
}

message Membership {
  string   creator_id        = 1;  // Arkavo's creator id
  string   campaign_id       = 2;
  string   patreon_user_id   = 3;
  string   email             = 4;
  string   full_name         = 5;
  string   status            = 6;  // active | declined | former
  string   tier_slug         = 7;  // free | <slugified tier title>
  uint32   tier_amount_cents = 8;
  repeated string benefits   = 9;  // slugified
  google.protobuf.Timestamp pledge_start    = 10;
  google.protobuf.Timestamp last_charge_at  = 11;
}
```

The claim shape the ERS emits onto subject entities is a direct projection
of `ResolveFanMembershipsResponse.connections` into a structpb under the
key `patreon.connections`:

```jsonc
{
  "patreon": {
    "connections": [
      {
        "creator_id": "alice", "campaign_id": "12345",
        "tier_slug": "patron", "status": "active",
        "benefits": ["early-access", "discord"]
      },
      {
        "creator_id": "bob", "campaign_id": "67890",
        "tier_slug": "supporter", "status": "active",
        "benefits": ["early-access"]
      }
    ]
  }
}
```

Subject mappings in `policy.patreon.yaml` then key off selectors like
`.patreon.connections[].creator_id` and `.patreon.connections[].tier_slug`.

### Required `Membership` value invariants

| Field        | Invariant                                                 |
|--------------|-----------------------------------------------------------|
| `status`     | Lowercased: `active`, `declined`, or `former`. Maps from Patreon's `patron_status` (`active_patron` → `active`, etc.). |
| `tier_slug`  | Lowercased, kebab-cased title of the *highest-amount* currently entitled tier. `"free"` when no tier is held. |
| `benefits`   | Lowercased, kebab-cased benefit titles, deduplicated, sorted. |
| `creator_id` | Stable Arkavo creator id (NOT Patreon's). Used as the FQN segment for the `campaign` attribute value. |

These invariants match what the ERS already produces; the Rust side must
preserve them so the existing subject mappings keep working.

## Service-to-service authentication

The ERS calls `authnz-rs` from inside the cluster. Three viable options:

1. **mTLS** with a private CA — preferred for production. authnz-rs verifies
   the ERS's client cert SAN.
2. **OIDC service token** — opentdf-platform's existing AccessTokenVerifier
   issues a service-scoped token; authnz-rs validates it. Matches how the
   rest of the platform authenticates internal calls.
3. **Shared static bearer** — only acceptable for dev. Pass via
   `PATREON_AUTHNZ_BEARER` env var.

The ERS-side config (when this lands) will look like:

```yaml
services:
  entityresolution:
    mode: patreon
    patreon:
      authnz_url: https://authnz.arkavo.internal
      auth:
        mode: mtls              # or "service_token" | "bearer"
        client_cert: /etc/tls/ers.crt
        client_key:  /etc/tls/ers.key
        ca:          /etc/tls/ca.crt
      # Optional: synthesize a "free" membership when authnz-rs returns
      # an empty list, so non-backers still flow through subject mappings.
      infer_unknown_as_free: true
      # Timeout for the resolve RPC. ERS treats timeouts as
      # ErrPatreonUnavailable (not NotFound) so KAS does not deny on a
      # transient outage.
      timeout: 750ms
```

## Connect / Admin surface on authnz-rs

Independent of the ERS contract, `authnz-rs` must expose the operator API
for creators. Suggested shape (REST or RPC, authnz-rs's choice):

| Method | Path / RPC                                  | Purpose                                                   |
|--------|---------------------------------------------|-----------------------------------------------------------|
| `GET`  | `/v1/patreon/oauth/start?creator_id=…`      | Redirect creator to Patreon's authorize endpoint.         |
| `GET`  | `/v1/patreon/oauth/callback`                | Code exchange + identity lookup; persists the connection. |
| `POST` | `/v1/patreon/connections`                   | Admin path: `{creator_id, refresh_token}` — for creators who completed OAuth out-of-band or for backfill. |
| `GET`  | `/v1/patreon/connections`                   | Inventory (no token material; metadata only).             |
| `DEL`  | `/v1/patreon/connections/{creator_id}`      | Revoke at Patreon, then mark `revoked_at`.                |

CSRF: a `state` nonce keyed to `creator_id` with a short TTL, stored
server-side. Required Patreon scopes: `identity`, `identity[email]`,
`campaigns`, `campaigns.members`, `campaigns.members[email]`. Webhook
ingest (`members:pledge:create|update|delete`) is the path that keeps
authnz-rs's cache fresh between RPC calls.

## Suggested storage shape (reference, not required)

These columns are what the discarded Go scaffolding modelled; the Rust
side is free to evolve them. Recorded here so the schema choices aren't
lost:

```sql
CREATE TABLE patreon_creator_connections (
    id                       UUID PRIMARY KEY,
    creator_id               TEXT UNIQUE NOT NULL,
    patreon_user_id          TEXT NOT NULL,
    campaign_id              TEXT NOT NULL,
    scopes                   TEXT[] NOT NULL DEFAULT '{}',
    access_token_ciphertext  BYTEA NOT NULL,
    access_token_expires_at  TIMESTAMPTZ NOT NULL,
    refresh_token_ciphertext BYTEA,
    key_id                   TEXT NOT NULL, -- KMS key version stamp
    connected_at             TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at               TIMESTAMPTZ NOT NULL DEFAULT now(),
    last_refreshed_at        TIMESTAMPTZ,
    revoked_at               TIMESTAMPTZ,
    metadata                 JSONB NOT NULL DEFAULT '{}'::jsonb
);

-- Partial indexes that matter:
-- (creator_id) WHERE revoked_at IS NULL  -- ERS lookups
-- (access_token_expires_at) WHERE revoked_at IS NULL  -- refresh worker
```

Refresh tokens are AES-256-GCM-encrypted under a KMS-managed key. `key_id`
identifies the key version so rotation is lazy.

## Migration plan (Go-side)

When `authnz-rs` is ready:

1. Add a `patreon.authnz_url` and auth block to the platform config.
2. Replace `service/entityresolution/patreon/v2/client.go`'s direct Patreon
   API code with an `authnz-rs` RPC client (same `MembershipAPI` interface
   the ERS already depends on).
3. Refactor `ResolveEntities` / `CreateEntityChainsFromTokens` to call
   `ResolveFanMemberships` once per request and emit
   `.patreon.connections[]` (multi-creator) instead of the current
   single-membership `.patreon.*` shape.
4. Update `policy.patreon.yaml` subject mappings:
   - `.patreon.tier_slug` → `.patreon.connections[].tier_slug` (subject
     mappings already use the `IN` operator over arrays).
   - Add per-creator `campaign` value mappings keyed off
     `.patreon.connections[].creator_id`.
5. Delete the static `creator_access_token` / `campaign_ids` config
   fields from the ERS — they become a property of each connection in
   authnz-rs.

The policy YAML in this branch already uses array-flavored selectors
(`.patreon.benefits[]`, `.patreon.campaign_ids[]`), so step 4 is a
search-and-replace, not a redesign.

## Open questions

- Where does the **Arkavo creator id** live as a stable identifier? authnz-rs
  needs a non-Patreon canonical id to use in `creator_id`. If creators
  live in opentdf's user store, the OAuth start endpoint takes their id
  from the caller's session; otherwise authnz-rs owns its own creator
  registry.
- **Cache invalidation across services**. Patreon webhooks land at
  authnz-rs; the ERS does not subscribe. A `last_modified` field on
  `Membership` plus a short opentdf-side cache (e.g. 30s) is probably
  sufficient — confirm before we wire caching.
- **Scope for future sources** (Stripe, Substack). If they end up here
  too, the RPC should generalize: `ResolveFanEntitlements` returning
  source-tagged blocks (`patreon.connections[]`, `stripe.subscriptions[]`,
  …). Doing it Patreon-only now is fine; the proto leaves room.
