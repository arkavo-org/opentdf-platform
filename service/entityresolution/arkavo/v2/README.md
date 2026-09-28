# Arkavo Entity Resolution Provider (v2)

An Arkavo-backed Entity Resolution Service (ERS) for distributed identity and
authorization within the Arkavo ecosystem. It accepts both JOSE (JWT) and COSE
(CWT) tokens, already signature-verified upstream by the platform's authn
middleware, and — when the token's issuer is trusted (see Trust Model below)
— translates their materialized `arkavo_entitlements` claim directly into
platform entitlements. Pairs with
[`examples/config/policy.arkavo.yaml`](../../../../examples/config/policy.arkavo.yaml).

## What it does

When a subject's claims carry the `arkavo_entitlements` claim (in JWT or CWT
form) and the issuer is trusted, the provider emits **direct entitlements**
per claim assertion (lowercased and deduplicated) as platform attribute
value FQNs declared in the operator's policy snapshot, e.g.:

```
https://arkavo.ai/attr/classification/value/<classification>
https://arkavo.ai/attr/action/value/<action>
https://arkavo.ai/attr/mesh/value/<mesh_role>
```

Attribute *values* under an already-declared attribute (namespace + name) are
dynamic (resolved as synthetic values when `allow_direct_entitlements` is
on), so onboarding a new entitlement value requires no change to the policy
snapshot — only a new namespace or attribute name does.

It also supports Non-Person Entities (NPE) — device and agent tokens — by
resolving their client IDs. Device class ceilings additionally cap a
*device* NPE's direct entitlements to its attested class (e.g., an
`unverified` device can only access `internal` data); agent NPEs are not
subject to a ceiling.

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

    # Claim name override (default shown). Controls which claim carries the
    # PE account ID surfaced on the SUBJECT entity; the entitlements
    # (arkavo_entitlements), user ID (sub), and issuer (iss) claim names are
    # fixed and not configurable.
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
along with `arkavo_roles`, `arkavo_entitlements`, and the raw `arkavo_npe`
data — all self-asserted, materialized-claims data gated by the same check.
This marker carries the issuer decision forward into the claims-entity path.

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
   `arkavo_trusted: true` and store `arkavo_roles`, `arkavo_entitlements`, and
   `arkavo_npe` in the SUBJECT entity's claims.
4. **Entity synthesis**: Create a SUBJECT entity carrying the claims, and an
   ENVIRONMENT entity if the token includes an `arkavo_npe` block.
5. **Claims-entity resolution**: On the second pass, `ResolveEntities` checks
   `trust_materialized_claims && claims["arkavo_trusted"] == true` to decide
   whether to emit direct entitlements.
6. **Direct entitlements emission**: Emit each `arkavo_entitlements` value
   (already a platform attribute value FQN, e.g.
   `https://arkavo.ai/attr/classification/value/restricted`) as a direct
   entitlement, lowercased and deduplicated.
7. **Device ceiling**: If the subject is a device NPE (non-person entity), apply
   the ceiling for its device class.

Subject mappings are not used — all authorization flows through direct
entitlements and the policy snapshot vocabulary.

## Agent status (`agent_status`)

An agent keeps its delegated entitlements only while authnz-rs says the
agent identity (its `did:key`, the token's `sub`) is eligible and the token
is current. The resolver asks on every `ResolveEntities`
call for an agent subject, so every v2 decision made from a token that
authentication signature-verified — the KAS path, and RAR's request-token
identifiers (see **Scope**) — sees a quarantine once the status lease runs
out (see **Timing** below), including a PEP that resolves a chain it built
earlier from such a token. A token identifier a caller supplies directly to
`GetDecision` or `GetEntitlements` is outside this guarantee (see
**Scope**).

```yaml
services:
  entityresolution:
    mode: arkavo
    trust_materialized_claims: true
    trusted_issuer: https://identity.arkavo.net
    agent_status:
      url: https://identity.arkavo.net   # https; plain http only on loopback
      client_id: <status-client-id>      # listed in authnz-rs AGENT_STATUS_CLIENT_IDS
      # Left empty on purpose and set via
      # OPENTDF_SERVICES_ENTITYRESOLUTION_AGENT_STATUS_CLIENT_SECRET: the key
      # must still exist here for the environment variable to take effect.
      client_secret: ""
      timeout: 3s                        # per call; at most 5s
```

| Field | Description | Default |
| --- | --- | --- |
| `agent_status.url` | authnz-rs base URL. The resolver calls `GET {url}/agents/{did}/status` (contract v2), `{did}` being the token's `sub`. `https` with a host and no userinfo, query or fragment; plain `http` only on loopback. | |
| `agent_status.client_id` | Confidential `client_credentials` client; its service CWT goes in `X-Auth-Token`. authnz-rs must list it in `AGENT_STATUS_CLIENT_IDS`. | |
| `agent_status.client_secret` | Secret for `client_id`. Never logged. | |
| `agent_status.timeout` | Per-call timeout; one status check (token call plus status call) is bounded at twice this. At most `5s`. | `3s` |

Setting any of `url`, `client_id` or `client_secret` enables the block, and
a block that fails validation stops the server at startup. With none of them
set, every agent subject resolves with no entitlements, and the server logs
a warning only when `trust_materialized_claims` is `true` (with it `false`,
entitlements are already disabled on both paths, so no warning). The
`OPENTDF_SERVICES_ENTITYRESOLUTION_AGENT_STATUS_*` environment
variables only take effect when the same key is present in the YAML file.
`cache_expiration` has no effect in this mode: the resolver keeps no entity
cache, and the 5 s bound depends on that.

**Which subjects are checked.** A trusted-issuer subject is checked when it
carries any agent marker: an `arkavo_npe` of any type but `device`
(including a missing or malformed type), `arkavo_swarm`,
`arkavo_state_version` (whatever its value), or an `agent` role in
`arkavo_roles`. A marker only widens the check; it never grants anything.
A checked subject must be an `arkavo_npe` of type `agent`;
any other combination (a swarm without an agent NPE, an unknown NPE type) is
refused without calling authnz-rs, so a
new NPE type is refused until this resolver allows it. Person and device
subjects carry none of these markers and are never checked, so an authnz-rs
outage does not change their decisions.

**When an agent keeps its entitlements.** All of these hold:

- its token's `cnf` carries a public key (`cnf.jwk` with `kty` `OKP` and `x`,
  or `EC` with `x` and `y`; the CWT verifier renders it from the COSE_Key
  authnz-rs mints), so its DPoP proof was key-bound (algorithm held to the
  key, single-use `jti`) where authentication ran (the KAS path);
- it has `sub` (a `did:key`: `did:key:z` and base58btc, at most 128
  characters), `arkavo_state_version` (an integer from 1 to 2^53 − 1, read
  exactly as written in a JWT payload or as a CBOR integer),
  `arkavo_swarm` and `arkavo_account_id` (read from `client_id_claim`); a
  token missing one is refused without calling authnz-rs. A token minted
  before contract v2 has no `arkavo_state_version`;
- authnz-rs answers `state = eligible` for that DID (`unassessed`,
  `suspended` and `quarantined` all refuse; authnz-rs derives `suspended`
  from an expired appraisal), with `agent` equal to `sub`, `swarm` equal to
  `arkavo_swarm`, `owner` equal to the account id, and a `state_version` of
  at least 1 that is not below the highest this process has seen for the DID;
- the token's `arkavo_state_version` equals that `state_version`: any
  mismatch refuses. A lower one is a token minted before the identity's
  latest state change (for example before a quarantine, then recovery and
  re-appraisal, or before a swarm change) and is refused; a higher one means
  the answer is older than the token and is refused too. An appraisal
  renewal does not change `state_version`, so renewing never invalidates
  tokens the agent already holds.

An allowing answer is cached per DID for `min(valid_until - now, 5s)`
(authnz-rs also caps `valid_until` at the end of the appraisal); a denying
one is never cached, and a token newer than the cached answer asks again. Any failure to get an answer (timeout, non-200, a redirect,
an undecodable body) refuses.

**Timing.** Status is re-fetched at most 5 s after identity's last allowing
answer. A live answer decides the request it was fetched for even when its
`valid_until` is missing or already past on this host's clock (deliberate,
for clock skew with identity); it is just not cached. The KAS releases the
key after the decision, so PDP and KAS processing time add to that window:
this is a bound on how stale a status can be, not a hard 5 s release
deadline.

**What a refusal looks like.** The agent's SUBJECT resolves with no
entitlements and no claims, and `ResolveEntities` still succeeds. The PDP
denies (and audits the denial), and the KAS answers every key access object
with the same `forbidden` an ABAC denial gets, inside a normal rewrap
response. The reason, the status's state and `state_version`, the token's
`arkavo_state_version` and the incident id go to the log as
`arkavo: agent entitlements withheld`; reasons that refuse every agent
(unconfigured, the status client not allowed, its credentials rejected, a
checker fault) are logged at `ERROR`.

**Where the refusal happens.** The KAS asks for its decision after it has
unwrapped each key access object and verified its policy binding, so a
refused agent's keys are unwrapped in KAS memory but never re-wrapped to the
agent. A refused agent can tell a tampered policy binding (`bad request`)
from a valid one (`forbidden`), exactly as any caller denied by ABAC can.

**Requirement on TDF authors: every sealed Arkavo TDF must carry a data
attribute.** The KAS releases a policy without data attributes without
asking the authorization service at all, so none of the above applies to
it: a TDF without a data attribute stays readable by a quarantined agent.
It is also released to an agent token that carries no `cnf` (no proof of
possession), if the issuer ever mints one: authnz-rs always mints a COSE
`cnf` for agents, and authentication demands DPoP whenever `cnf` is
present, but with `server.auth.enforceDPoP: false` nothing else requires
it. Use at least one attribute value the agent must hold, such as
`https://arkavo.ai/attr/tdf/value/decrypt`.

**No subject mappings.** Refusal works by withholding: a withheld agent
resolves with no claims, so no subject mapping is evaluated for it. But a
`NOT_IN` condition is true whenever its selector is missing, so a `NOT_IN`
mapping grants to every person and every admitted agent whose claims simply
lack that field, beyond their delegated entitlements, and any other mapping
can grant on claims the issuer controls. The policy file this deployment
actually loads (`services.authorization.policy_file`) must have no subject
mappings. `examples/config/policy.arkavo.yaml` keeps `subject_mappings: []`
and a test in `service/policy/filestore` fails if that changes; the
production draft config points at a different file, which that test does
not see. An admitted (eligible) agent's claims still carry
`arkavo_account_id`, and a bare-string `arkavo_roles` value is now kept on
the subject's claims too; neither matters while the deployed policy keeps
`subject_mappings: []`, which `TestArkavoSnapshot_HasNoSubjectMappings`
pins for the in-repo example.

**Scope.** The check covers decisions made from a token that authentication
signature-verified: the KAS (which always sends the raw bearer) and RAR's
`/token` endpoint (`service/authorization/v2/rar.go`), which verifies the
caller's `subject_token` before forwarding it as a request-token identifier
to `GetEntitlements`/`GetDecisionMultiResource`. The ERS decodes an
`EntityIdentifier_Token`'s claims without verifying its signature
(`DecodeClaimsFromToken`, `jwt.WithVerify(false)`), and the JIT PDP does not
verify it either, so a token identifier a caller supplies directly to
`GetDecision` or `GetEntitlements` — bypassing the KAS and RAR's own
verification — is asserted exactly like a supplied entity chain (this was
already true of entity chains in claims-passthrough mode, and under the KAS
gate this replaces): a SUBJECT carrying `arkavo_trusted` and no agent marker
is not checked. In arkavo deployments, only trusted PEPs may call those
endpoints with entity-chain or caller-supplied token identifiers. v1
authorization (`GetDecisions`) is not supported in arkavo mode: the v1
entity resolver has no arkavo mode, so v1 decisions never reach this check.

**Deployment.** Deploy this together with the proof-of-possession change
(the CWT verifier's COSE_Key `cnf` rendering): once agent tokens
authenticate, an arkavo resolver without this check grants their delegated
entitlements with no status check. Configure `agent_status` in the process
that runs this resolver and verify the status credentials (a 403 or a
credentials refusal is logged at `ERROR`) before agent traffic is enabled.
As a concrete pre-rollout check: after configuring `agent_status`, run a
smoke rewrap as a known-eligible agent and check the ERS log has no
`arkavo: agent entitlements withheld` at `ERROR` (a 403 from the status
endpoint or rejected credentials) — the client mints its service token
lazily, so nothing is checked at startup. Dissemination for agents is a
separate KAS option, `services.kas.enforce_dissem`, off by default.

**Known limits.** The `state_version` high-water mark is per process and in
memory, so a restarted or sibling platform process accepts any version of 1
or more that equals the token's; the token/version binding still refuses a
token minted before the identity's latest state change. Status freshness is
bounded as described under **Timing**, not as a release deadline. Supplied entity chains are outside the check (see **Scope**).

## Testing

```bash
cd service && go test ./entityresolution/arkavo/...
```

No outbound Arkavo or authnz-rs calls — tests exercise claims passthrough
directly with mocked JWT/CWT payloads, and the status client against an
in-process fake of authnz-rs.
