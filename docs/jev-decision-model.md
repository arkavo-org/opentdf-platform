# Jev decision models in authorization

The platform can consult a [TypeSafe Jev](https://typesafe.ai) decision model,
reached through OpenRouter's Decisions API, at three points in the authorization
flow. All are disabled by default.

Jev is a "System One" model: rather than generating text, it takes program state
plus typed questions and returns typed answers with probabilities. The question
defines a constrained answer domain rather than asking the application to parse
generated prose. The platform still validates response types, allowed values,
and numeric ranges at the HTTP trust boundary.

## The safety model

A decision model is probabilistic. OpenTDF's policy evaluation is deterministic
ABAC on a security platform. The rule that reconciles the two:

> **For restrict-only seams, the caller enforces `final permits` as a subset of
> `policy permits`. No returned model answer can expand the baseline permit set.**

Every seam is built so that the model can only restrict a decision, require an
additional obligation, or derive claims that remain subject to normal subject
mapping. Concretely:

- The obligations trigger is **add-only**. Obligations that policy required are
  never withdrawn, and the trigger cannot flip a denial into a permit. This
  holds only if the PEP performs the obligation before releasing access; the
  PDP cannot compel or independently verify PEP behavior.
- The ERS provider derives **claims, not entitlements**. A derived claim grants
  nothing unless an operator has also written a subject mapping that consumes it.
- The decision restrictor returns only resources to deny. The caller then
  independently intersects those results with policy's permit set. The return
  type supports the guarantee; the caller's monotonic application enforces it.
- An answer below the configured confidence threshold is treated as **absent**,
  not as `false`, so an uncertain model never decides anything by omission.

Deny-only limits privilege expansion. It does not guarantee detection or
availability: a false negative can miss a restriction, a false positive can deny
legitimate work, and an unavailable model invokes the configured failure mode.

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
`EventMetaData["jev"]`. The observations are attached once per request rather
than copied into every per-entity audit event, and carry the response id, model,
question, answer, certainty, mode, cost, and whether the answer changed anything.
Fail-open paths record the error.

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
        - resource_count
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
`pep_client_id`, `policy_triggered_obligations`, `resource_count`.

The Jev trigger evaluates the shape of the complete decision once. A rule that
fires adds its obligation to every resource in that decision; static policy
obligations remain resource-specific. This keeps the external dependency to one
model call rather than one serial call per resource.

Rule conditions, by question type:

| Type     | Field                    | Fires when                          |
| -------- | ------------------------ | ----------------------------------- |
| `noul`   | `when_false: true`       | the answer is false (default: true) |
| `choice` | `when_choice: [a, b]`    | the choice is listed                |
| `score`  | `when_score_at_or_above` | the score meets the bound           |

`fail_mode: open` means an unreachable model requires no obligation, which can
only lose a restriction policy never required. `fail_mode: closed` denies — but
only while the seam is enforcing; in shadow mode an unreachable model is
recorded and otherwise ignored. In either mode, an enforcing PEP must actually
perform every returned obligation before releasing data.

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
            claim_name: jev.risk_tier
            transformation: array
```

Two independent gates control egress here: `input_mapping` decides which JWT
claims become parameters at all, and `state_allowlist` filters those parameters
again by name.

Derived claim names must use the reserved `jev.` prefix so they cannot collide
with IdP claims. A derived claim does nothing until a subject mapping matches it,
but that means this seam can increase access through ordinary policy. Treat
user-editable JWT inputs as hostile, and do not make a high-value grant depend
solely on a model-derived claim.

## Latency

Jev responds in roughly 70–500 ms. KAS reaches the obligations seam through its
existing `GetDecision` RPC, so rewrap inherits that latency without code changes.
Set `timeout` to bound it, and consider `cache_ttl` (off by default) only after
thinking carefully about what it means to cache an authorization input.

## Seam 3: decision restrictor

For the case policy cannot express: a request where every attribute check passes
but the request as a whole looks wrong — a bulk pull at an odd hour, a pattern
unlike how this entity normally works.

```yaml
services:
  authorization:
    jev_restrictor:
      enabled: true
      model: typesafe/jev-1.13
      timeout: 500ms
      fail_mode: open
      confidence_threshold: 0.80   # see "Threshold trap" below before changing
      state_allowlist:
        - action
        - resource_count
      seams:
        restrictor:
          enabled: true
          mode: shadow
      questions:
        is_exfiltration:
          type: noul
          instructions: Does this request look like bulk exfiltration rather than ordinary work?
          criteria:
            "true": An unusually large or broad request for this entity and action.
            "false": A request consistent with ordinary use.
      rules:
        - question: is_exfiltration
          reason: looks like bulk exfiltration
```

State keys available to the allowlist: `entity_id`, `action`, `resource_count`,
`attribute_value_fqns`, `permitted_count`.

A rule that fires denies every resource policy permitted in that decision, so
this seam is aimed at request-shaped anomalies rather than per-resource
judgements. That also keeps it to one model call per decision.

Two properties are worth understanding before enabling it:

- **A returned answer cannot grant.** The `DecisionRestrictor` interface returns
  denials, not a decision. The caller independently applies them only to
  resources policy permitted, enforcing `final permits` as a subset of `policy
  permits`. A property test exercises this across randomised decisions and
  denial sets, including a restrictor that tries to deny everything. As with any
  in-process interface, this claim does not cover unrelated side effects or
  shared-state corruption by a malicious implementation.
- **A false positive denies a legitimate request.** This is the only seam where
  the model can cost a user access. Run it in shadow mode for long enough to see
  the false-positive rate on your traffic, and prefer the obligations seam where
  a step-up would do instead of a denial.

### Threshold trap

Set the threshold from measurement, not intuition. For a Noul answer, Jev
returns the probability that the proposition is true and no separate confidence
field. This integration derives `certainty` as `max(p, 1-p)` for uniform gating.
A threshold chosen to mean
"only act on overwhelming evidence" can silently make the seam inert: it never
fires, while the audit observation remains present with `applied=false`.

Measured against `typesafe/jev-1.13-20260917`, asking whether a request looks
like bulk exfiltration, with a request of 4812 secret resources in one call
([reproducible test and original run](https://github.com/arkavo-org/opentdf-platform/commit/f1b9638807fe47b5e698ac8dc82dd01460376184)):

| `confidence_threshold` | certainty observed | denied? |
| ---------------------- | ------------------ | ------- |
| 0.70                   | 0.82               | yes     |
| 0.80                   | 0.83               | yes     |
| 0.90                   | 0.81               | **no**  |
| 0.95                   | 0.82               | **no**  |
| 0.99                   | 0.83               | **no**  |

This example shows a threshold failure, not model calibration. Establishing
calibration requires labeled observations across many predictions. In this run,
the suspicious request's Noul probability was about 0.82–0.83; the routine read
returned a false probability near 0.04, which this integration reports as 0.96
derived certainty. Low-certainty answers need an explicit outcome: preserve the
policy baseline, require step-up, route for review, or deny, depending on risk.

Your questions will produce different distributions. `TestLiveConfidenceGatingIsMeaningful` in
`service/internal/jev/live_test.go` prints this table; point it at your
own questions and read the threshold off the result.

Resources policy already denied are never sent, and a decision with nothing
permitted skips the model call entirely.

## Running the live tests

The unit tests run against a fake transport and need no credentials. A separate
set of tests exercises the real model, and is excluded from ordinary builds by
the `jevlive` build tag, because `make test` runs `go test ./...` and these
tests cost money and need network access.

```sh
cp .env.example .env        # then add your OpenRouter key; .env is gitignored
set -a; . ./.env; set +a
cd service
go test -tags jevlive -v ./internal/jev/...
go test -tags jevlive -v ./internal/access/v2/jevrestrictor/...
```

They skip rather than fail when `OPENROUTER_API_KEY` is unset. What they check
is the contract we depend on — that the wire format still matches our structs,
that each question type returns the answer type we expect, and that redaction
holds end to end — plus one behavioural check that the model can actually tell
a bulk overnight pull from a routine read. A seam whose model cannot make that
distinction would be worthless.
