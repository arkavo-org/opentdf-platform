# Can AI Sit in the Authorization Path? Only If Code Keeps Authority

Putting an AI model in an authorization path sounds like a category error.
Authorization should be deterministic, explainable, and conservative. Models
are probabilistic, fallible, and operationally dependent on data and inference
services outside the policy engine.

That tension—not the HTTP call—was the interesting part of integrating TypeSafe
Jev with OpenTDF for the Arkavo network.

Jev is a System One model. It evaluates structured state and returns typed
answers: a choice, a score, or a Noul probability for a yes/no proposition. It
does not generate an explanation that application code must parse. TypeSafe
describes these models as narrow judgment components that deterministic code
combines into a larger workflow. Its documentation also makes an important
qualification: calibration is measured across groups of predictions and does
not guarantee that an individual answer is correct.

The design principle we landed on is:

> Jev supplies a probabilistic judgment. Deterministic code limits how that
> judgment can affect access.

For restrict-only seams, that becomes a concrete invariant:

```text
finalPermits ⊆ policyPermits
```

## A return type that cannot say “permit”

The clearest version appears in the decision restrictor:

```go
type DecisionRestrictor interface {
    Deny(
        context.Context,
        RestrictionRequest,
    ) (map[string]string, error)
}
```

The model-facing component returns resources to deny, not a replacement
decision. The caller then independently applies those denials only to resources
policy permitted. A returned answer therefore cannot expand the baseline permit
set.

The interface supports that guarantee; the caller enforces it. An in-process Go
interface does not make arbitrary side effects or shared-state corruption
impossible. The precise claim is about the returned value and the caller’s
monotonic application of it.

That distinction matters because deny-only does not mean harmless. A false
negative can miss a restriction. A false positive can deny legitimate work. An
unavailable model forces an explicit fail-open or fail-closed choice. Deny-only
limits privilege expansion; it does not guarantee detection or availability.

## Three seams, two threat models

We explored three integration points.

The obligation trigger is add-only. It can require step-up authentication,
watermarking, or another control, but cannot remove an obligation policy already
required. This preserves the baseline authorization boundary only when the
Policy Enforcement Point actually performs the obligation before releasing
access. OpenTDF’s PDP can report the directive; it cannot compel or independently
verify the PEP.

The decision restrictor is deny-only. It can narrow policy’s permit set based on
request-shaped signals that resource-by-resource ABAC does not express well,
such as a large pull at an unusual time.

The entity-resolution seam is different. It turns model answers into derived
claims, and OpenTDF subject mappings evaluate ERS representations to produce
entitlements. A derived claim is not itself an entitlement, but it can influence
a grant through ordinary policy. That is useful—and it is a separate threat
model.

We now require derived claims to use a reserved `jev.` namespace, validate the
remote answer against the submitted question domain, and treat user-influenceable
JWT inputs as hostile. Even with those controls, a high-value grant should not
depend solely on a model-derived claim.

## Same state shape, opposite judgment

In a live experiment against `typesafe/jev-1.13-20260917`, a routine read
produced a Noul exfiltration probability of 0.09 and a `routine` classification.
A request for 4,812 secret resources produced 0.85 and `critical`. A three-question
call took 426 ms and cost $0.000025 in that run.

Those figures are an observation, not a benchmark. They are tied to the model,
question wording, input, provider, and date. The tagged live test records the
reproduction path in the repository.

## The threshold trap

Our first documented confidence threshold was 0.95. It sounded appropriately
conservative for authorization. It was also wrong for the question we asked.

Across repeated suspicious examples, the Noul probability—and therefore this
integration’s derived certainty—sat near 0.82. A threshold of 0.95 did not make
the control safer. It made the control inert.

The vocabulary matters here:

- Choice and Score answers contain TypeSafe’s native `confidence`, derived from
  their probability distributions.
- Noul contains only the probability that the proposition is true.
- OpenTDF derives Noul `certainty` as `max(p, 1-p)` so confident true and
  confident false answers can use one threshold mechanism.

The 0.85 result was the exfiltration probability. The approximately 0.82 values
in the threshold experiment came from separate runs. They are not two native
fields from the same answer.

This demonstrates a threshold failure, not calibration. Establishing calibration
requires labeled outcomes across many predictions. Low-confidence answers also
need an explicit result: preserve baseline policy, require step-up, route to
review, or deny, depending on the consequence of being wrong.

## Typed does not mean “trust the network”

Jev’s question defines a constrained answer domain, which is materially better
than asking a general model for JSON and repairing whatever comes back. But a
remote response still crosses a trust boundary.

OpenTDF therefore validates that the answer type matches the submitted question,
Choice values belong to the configured option set, numeric values are finite and
in range, and Score values fit the configured scale. Typed model outputs do not
remove the application’s responsibility to validate schemas, allowed values,
and numeric ranges at the network boundary.

## What green tests missed

The first review found defects in shadow failure behavior, protobuf conversion,
audit ordering, entity identity, rule observation, threshold guidance, and
secret handling. A second integration review found that the ERS mapper was
well-tested but disconnected from the production strategy path, and that the
obligation hook made one serial external call per resource.

Both are classic integration failures: locally correct components joined by
incorrect wiring. The fixes add a full service-level ERS test and make the Jev
obligation trigger evaluate the complete decision once. A rule that fires adds
the obligation to every resource, while static policy obligations remain
resource-specific.

The lesson is not that tests are unhelpful. It is that a green component suite
cannot establish a cross-component security property. The highest-value tests
exercise the assembled decision path and reconcile the returned decision with
the audit record.

## What we would deploy

Our default is still off. The next state is shadow, not enforcement.

In shadow mode we measure answer distributions, false positives and negatives,
latency, cost, provider failures, and the effect different thresholds would have
had. Only then do we give a seam authority—and we prefer a PEP-enforced step-up
obligation over denial when that is sufficient.

For the Arkavo network, Jev is not a replacement policy engine. It is a bounded,
observable source of judgment inside a workflow whose authority remains in
deterministic code.

The model can contribute judgment. Policy must continue to own authority.

## Sources and reproduction

- [TypeSafe System One](https://docs.typesafe.ai/concepts/system-one)
- [TypeSafe confidence](https://docs.typesafe.ai/confidence)
- [OpenTDF subject mappings](https://opentdf.io/components/policy/subject_mappings)
- [OpenTDF obligations](https://opentdf.io/components/policy/obligations)
- [Threshold experiment commit](https://github.com/arkavo-org/opentdf-platform/commit/f1b9638807fe47b5e698ac8dc82dd01460376184)
- Live reproduction: `cd service && go test -tags jevlive -v ./internal/jev/... ./internal/access/v2/jevrestrictor/...`
