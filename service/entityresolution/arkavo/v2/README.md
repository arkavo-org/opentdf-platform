# Arkavo agent gate (v2)

This package is no longer an entity resolver of its own. It holds the agent
gate that the composite entity resolver
([`../../composite/v2`](../../composite/v2)) applies to every subject before
it runs its sources:

- `AgentDenial(ctx, checker, claims, ownerClaim)` judges a subject's claims.
  It returns nil when the subject carries no agent marker or authnz-rs finds
  the agent eligible, and a `*agentstatus.DenialError` (or the checker's own
  error) when it refuses the agent. A nil checker refuses every agent. A
  panicking checker refuses rather than failing the call.
- `LogAgentDenial(ctx, logger, subject, err)` logs a refusal as
  `arkavo: agent entitlements withheld`, with the reason and status fields
  and never a token, proof or credential.
- `parseArkavoClaims` reads the authnz-rs claims both depend on
  (`arkavo_npe`, `arkavo_swarm`, `arkavo_state_version`, `cnf`,
  `arkavo_account_id` and the rest).

The composite configures the checker from `constraints.agent_status` and
passes `arkavo_account_id` as the owner claim. A refused agent gets no grants
and no properties from any source. The composite's configuration is in
[`docs/Configuring.md`](../../../../docs/Configuring.md#composite-resolver);
the vocabulary for local testing is
[`examples/config/policy.arkavo.yaml`](../../../../examples/config/policy.arkavo.yaml).

## Agent status

An agent keeps its delegated entitlements only while authnz-rs says the
agent identity (its `did:key`, the token's `sub`) is eligible and the token
is current.

```yaml
services:
  entityresolution:
    # evidence and sources: see docs/Configuring.md
    constraints:
      agent_status:
        url: https://identity.arkavo.net   # https; plain http only on loopback
        client_id: <status-client-id>      # listed in authnz-rs AGENT_STATUS_CLIENT_IDS
        # Left empty on purpose and set via
        # OPENTDF_SERVICES_ENTITYRESOLUTION_CONSTRAINTS_AGENT_STATUS_CLIENT_SECRET:
        # the key must still exist here for the environment variable to take
        # effect.
        client_secret: ""
        timeout: 3s                        # per call; at most 5s
```

| Field | Description | Default |
| --- | --- | --- |
| `constraints.agent_status.url` | authnz-rs base URL. The resolver calls `GET {url}/agents/{did}/status` (contract v2), `{did}` being the token's `sub`. `https` with a host and no userinfo, query or fragment; plain `http` only on loopback. | |
| `constraints.agent_status.client_id` | Confidential `client_credentials` client; its service CWT goes in `X-Auth-Token`. authnz-rs must list it in `AGENT_STATUS_CLIENT_IDS`. | |
| `constraints.agent_status.client_secret` | Secret for `client_id`. Never logged. | |
| `constraints.agent_status.timeout` | Per-call timeout; one status check (token call plus status call) is bounded at twice this. At most `5s`. | `3s` |

Setting any of `url`, `client_id` or `client_secret` enables the block, and
a block that fails validation stops the server at startup. With none of them
set, every agent subject gets no grants. The
`OPENTDF_SERVICES_ENTITYRESOLUTION_CONSTRAINTS_AGENT_STATUS_*` environment
variables only take effect when the same key is present in the YAML file.
`cache_expiration` has no effect on the composite resolver: it keeps no
entity cache, and the 5 s bound depends on that.

**When the check runs.** The composite judges a subject when it resolves it:
for each token in `CreateEntityChainsFromTokens`, after verifying the CWT,
and in `ResolveEntities` for a claims chain from a PEP on
`evidence.claims_chain_peps`. A decision made from a token (the KAS rewrap
and licence routes) creates its chain and so asks afresh, subject to the
lease under **Timing**. A sealed chain is not judged again when it is
resolved: the answer sealed into its `arkavo_evidence` stands until the
evidence expires, which is the token's `exp`. A chain from any other caller
carries no claims, so it is never an agent and gets no grants either.

**Which subjects are checked.** A subject is checked when it carries any
agent marker: an `arkavo_npe` of any type but `device` (including a missing
or malformed type), `arkavo_swarm`, `arkavo_state_version` (whatever its
value), or an `agent` role in `arkavo_roles`. A marker only widens the
check; it never grants anything. A checked subject must be an `arkavo_npe`
of type `agent`; any other combination (a swarm without an agent NPE, an
unknown NPE type) is refused without calling authnz-rs, so a new NPE type is
refused until this gate allows it. Person and device subjects carry none of
these markers and are never checked, so an authnz-rs outage does not change
their decisions.

**When an agent keeps its entitlements.** All of these hold:

- its token's `cnf` carries a public key (`cnf.jwk` with `kty` `OKP` and `x`,
  or `EC` with `x` and `y`; the CWT verifier renders it from the COSE_Key
  authnz-rs mints), so its DPoP proof was key-bound (algorithm held to the
  key, single-use `jti`) where authentication ran (the KAS path);
- it has `sub` (a `did:key`: `did:key:z` and base58btc, at most 128
  characters), `arkavo_state_version` (an integer from 1 to 2^53 − 1),
  `arkavo_swarm` and `arkavo_account_id`; a token missing one is refused
  without calling authnz-rs. A token minted before contract v2 has no
  `arkavo_state_version`;
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
one is never cached, and a token newer than the cached answer asks again.
Any failure to get an answer (timeout, non-200, a redirect, an undecodable
body) refuses.

**Timing.** Status is re-fetched at most 5 s after identity's last allowing
answer. A live answer decides the request it was fetched for even when its
`valid_until` is missing or already past on this host's clock (deliberate,
for clock skew with identity); it is just not cached. The KAS releases the
key after the decision, so PDP and KAS processing time add to that window:
this is a bound on how stale a status can be, not a hard 5 s release
deadline. A sealed chain held and resolved later carries the answer it was
sealed with (see **When the check runs**).

**What a refusal looks like.** The agent's subject resolves with no
entitlements and no properties, and the RPC still succeeds. The PDP denies
(and audits the denial), and the KAS answers every key access object with
the same `forbidden` an ABAC denial gets, inside a normal rewrap response.
The reason, the status's state and `state_version`, the token's
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

**Subject mappings.** Refusal works by withholding: a refused agent resolves
with no properties, so no subject mapping that needs a property matches it.
But a `NOT_IN` condition is true whenever its selector is missing, so a
`NOT_IN` mapping grants to a refused agent, and to every subject whose
properties simply lack that field. The policy file this deployment loads
(`services.authorization.policy_file`) must have no `NOT_IN` mapping that
grants what agents must not hold. `examples/config/policy.arkavo.yaml` keeps
`subject_mappings: []`, which `TestArkavoSnapshot_HasNoSubjectMappings` (in
`service/policy/filestore`) pins; the production config points at a
different file, which that test does not see.

**Scope.** The composite verifies every token it is handed (a CWT signed by
a configured issuer, with that issuer's audience and an `exp` still ahead),
so a decision from any token identifier, whether the KAS, RAR's `/token`
endpoint or a caller of `GetDecision`, is checked; an unsigned JWT gets no
grants at all. A claims chain is asserted by the PEP that sends it: the gate
judges the claims it carries, so only PEPs trusted to forward a subject's
claims as verified belong on `evidence.claims_chain_peps`. v1 authorization
(`GetDecisions`) is not supported: the v1 entity resolver has no composite,
so v1 decisions never reach this check.

**Before agent traffic.** Configure `constraints.agent_status` and verify
the status credentials: run a smoke rewrap as a known-eligible agent and
check the ERS log has no `arkavo: agent entitlements withheld` at `ERROR` (a
403 from the status endpoint or rejected credentials). The client mints its
service token lazily, so nothing is checked at startup. Dissemination for
agents is a separate KAS option, `services.kas.enforce_dissem`, off by
default.

**Known limits.** The `state_version` high-water mark is per process and in
memory, so a restarted or sibling platform process accepts any version of 1
or more that equals the token's; the token/version binding still refuses a
token minted before the identity's latest state change. Status freshness is
bounded as described under **Timing**, not as a release deadline, and a
sealed chain is not re-checked before it expires.

## Testing

```bash
cd service && go test ./entityresolution/arkavo/... ./entityresolution/composite/...
```

No outbound authnz-rs calls: the gate's tests call `AgentDenial` on claim
maps, with fake checkers and the real status client against an in-process
fake of authnz-rs. The composite's tests cover the gate through the v2 PDP.
