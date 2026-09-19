# Jev decision models in authorization

The platform can consult a [TypeSafe Jev](https://typesafe.ai) decision model,
reached through OpenRouter's Decisions API, at two points in the authorization
flow. Both are disabled by default.

Jev is a "System One" model: rather than generating text, it takes program state
plus typed questions and returns typed answers with calibrated probabilities.
There is no JSON prompting and no parsing layer — the question's type fixes the
answer's type.

## The safety model

A decision model is probabilistic. OpenTDF's policy evaluation is deterministic
ABAC on a security platform. The rule that reconciles the two:

> **A model answer may never grant access that policy evaluation denies.**

Every seam is built so that the model can only restrict a decision, require an
additional obligation, or derive claims that remain subject to normal subject
mapping. Concretely:

- The obligations trigger is **add-only**. Obligations that policy required are
  never withdrawn, and the trigger cannot flip a denial into a permit.
- The ERS provider derives **claims, not entitlements**. A derived claim grants
  nothing unless an operator has also written a subject mapping that consumes it.
- An answer below the configured confidence threshold is treated as **absent**,
  not as `false`, so an uncertain model never decides anything by omission.

## Data egress

Enabling a seam sends state to OpenRouter, which routes it to TypeSafe. Attribute
FQNs encode classification, and entity claims are frequently personal data.

`state_allowlist` is therefore mandatory: it names the keys permitted to leave the
platform, and anything unnamed is dropped before the call. Enabling the client
with an empty allowlist is a configuration error rather than a silent no-op.
Review the allowlist with whoever owns your data-handling obligations before
turning a seam on.

The API key is read from the environment once, when the service builds its
client, so rotating the key requires a restart.

## Shadow mode

Each seam has `mode: shadow` (the default) or `mode: enforce`. In shadow mode the
model is consulted and its answers and certainties are recorded in the audit
trail, but the outcome is unchanged. Run shadow against real traffic first, to
measure calibration, latency, and cost before granting a seam authority.

`fail_mode` applies only in enforce mode. A shadow-mode seam has no authority
over the outcome, so it can never fail a decision, whatever `fail_mode` says.

For the ERS provider, shadow-mode results surface on the entity representation
as `metadata_*` fields — `metadata_certainties`, `metadata_applied`,
`metadata_response_id` — alongside the resolved claims.

## Audit

Seams do not emit their own audit records. They publish observations to a
per-request collector, and the existing decision event folds them into
`EventMetaData["jev"]`, so a decision still produces exactly one audit record —
now carrying the response id, model, question, answer, certainty, mode, cost, and
whether the answer changed anything. Fail-open paths record the error.

The ERS provider is the exception: it may run in a separate service from the
decision, so it records into its `RawResult.Metadata` instead.

## Seam 1: obligation triggers

Requires an obligation on a request policy would not have obligated.

```yaml
services:
  authorization:
    jev:
      enabled: true
      model: typesafe/jev-1.13   # pinned; avoid the floating ~jev-latest alias
      api_key_env: OPENROUTER_API_KEY
      timeout: 500ms
      fail_mode: open            # open | closed
      confidence_threshold: 0.85
      state_allowlist:
        - action
        - attribute_value_fqns
      seams:
        obligations:
          enabled: true
          mode: shadow
      questions:
        is_anomalous:
          type: noul
          instructions: Is this access request unusual for this action and classification?
          criteria:
            "true": The action or classification combination is rarely requested together.
            "false": This is a routine request.
      rules:
        - question: is_anomalous
          obligation: https://example.org/obl/step_up/value/required
```

State keys available to the allowlist: `action`, `attribute_value_fqns`,
`pep_client_id`, `policy_triggered_obligations`.

Rule conditions, by question type:

| Type     | Field                    | Fires when                          |
| -------- | ------------------------ | ----------------------------------- |
| `noul`   | `when_false: true`       | the answer is false (default: true) |
| `choice` | `when_choice: [a, b]`    | the choice is listed                |
| `score`  | `when_score_at_or_above` | the score meets the bound           |

`fail_mode: open` means an unreachable model requires no obligation, which can
only lose a restriction policy never required. `fail_mode: closed` denies — but
only while the seam is enforcing; in shadow mode an unreachable model is
recorded and otherwise ignored.

## Seam 2: derived entity claims

Adds a `jev` provider to multi-strategy entity resolution. Answers become claims
that ordinary subject mappings may consume.

```yaml
services:
  entityresolution:
    mode: multi-strategy
    providers:
      risk_model:
        type: jev
        connection:
          enabled: true
          state_allowlist: [department, employment_type]
          confidence_threshold: 0.85
          seams:
            ers_claims:
              enabled: true
              mode: shadow
          questions:
            risk_tier:
              type: choice
              instructions: How much scrutiny does this employment context warrant?
              criteria:
                elevated: Contractor, recent start date, or unusual department.
                routine: Long-tenured direct employee.
    mapping_strategies:
      - name: derive_risk_tier
        provider: risk_model
        entity_type: subject
        input_mapping:
          - jwt_claim: department
            parameter: department
          - jwt_claim: employment_type
            parameter: employment_type
        output_mapping:
          - source_answer: risk_tier
            claim_name: risk_tier
            transformation: array
```

Two independent gates control egress here: `input_mapping` decides which JWT
claims become parameters at all, and `state_allowlist` filters those parameters
again by name.

Remember that the derived claim does nothing until a subject mapping matches it.
That indirection is deliberate — it keeps policy the only grantor of access.

## Latency

Jev responds in roughly 70–500 ms. KAS reaches the obligations seam through its
existing `GetDecision` RPC, so rewrap inherits that latency without code changes.
Set `timeout` to bound it, and consider `cache_ttl` (off by default) only after
thinking carefully about what it means to cache an authorization input.
