# Jev in OpenTDF — YouTube explainer script

Target length: 6–7 minutes.

## 0:00 — Cold open

**On screen:** Highlight the return type of `DecisionRestrictor.Deny`.

**Narration:**

“We put a probabilistic model in an authorization path. Then we designed its
interface so a returned answer cannot say permit.

That sounds like wordplay, but it is the central security boundary. Jev supplies
a judgment. Deterministic code decides what that judgment is allowed to change.”

## 0:30 — The apparent contradiction

**On screen:** Deterministic ABAC on the left; probabilistic Jev judgment on the
right.

“OpenTDF evaluates deterministic attribute-based policy. TypeSafe Jev evaluates
structured state and returns a Choice, Score, or yes/no probability. It avoids
free-form output, but its judgment is still probabilistic.

For our restrict-only seams, the invariant is simple: the final permit set must
be a subset of the set policy permitted.”

**On screen:** `finalPermits ⊆ policyPermits`

## 1:15 — The type and the caller

**On screen:** The interface, followed by the `applyRestrictions` loop.

“The restrictor returns a map of resource IDs to denial reasons. It does not
return a decision. Then the caller independently checks each returned ID and
only moves a resource from permitted to denied.

The interface supports the guarantee. The caller enforces it. We are not claiming
that an in-process interface prevents every malicious side effect; we are making
a precise claim about returned model answers.”

## 2:00 — Three seams

**On screen:** Three cards: Obligations, ERS claims, Restrictor.

“The obligation seam can add a step-up or watermark requirement. That works only
if the PEP actually performs the obligation before releasing access—the PDP
cannot compel it.

The restrictor can narrow a decision.

ERS claims are the sharp edge. OpenTDF subject mappings evaluate entity
representations and derive entitlements. A namespaced claim like
`jev.risk_tier` can therefore influence a grant through normal policy. It is not
the same threat model as deny-only restriction.”

## 2:55 — Live comparison

**On screen:** Two terminal panes using the tagged live test or captured,
timestamped output.

“Here is one observed run—not a general benchmark. A routine read produced an
exfiltration probability of 0.09 and `routine`. A 4,812-resource request produced
0.85 and `critical`. Three questions took 426 milliseconds and cost $0.000025 in
that run.”

**Production note:** Show the commit and command used to reproduce the output.

## 3:40 — Shadow versus enforce

**On screen:** First `mode: shadow`, then `mode: enforce`.

“In shadow mode, the suspicious answer is audited with `applied=false`, but the
policy decision is unchanged. In enforcement mode, the caller intersects the
model denials with policy’s permits.

Deny-only limits privilege expansion. It does not guarantee detection or
availability. A false negative misses a restriction; a false positive blocks a
legitimate user; a provider outage invokes fail-open or fail-closed behavior.”

## 4:25 — The threshold trap

**On screen:** Threshold table from the operator guide.

“We originally documented a threshold of 0.95 because it sounded conservative.
The suspicious examples sat near 0.82, so that setting silently prevented the
rule from firing.

For Choice and Score, Jev reports confidence from the probability distribution.
Noul has no separate confidence; it returns the probability of true. Our code
derives certainty as the larger of `p` and `1-p`.

This table demonstrates a bad threshold, not calibration. Calibration requires
labeled predictions at scale.”

## 5:15 — Typed output still crosses a network

**On screen:** Request questions, HTTP boundary, validated response.

“The model’s answer space is constrained, but the HTTP response is still
untrusted input. We validate the returned type, Choice membership, numeric
ranges, and Score scale before caching or using an answer.

Typed model outputs reduce ambiguity. They do not remove integration
validation.”

## 5:50 — What review found

**On screen:** Condensed defect table, then highlight the ERS end-to-end test and
batched obligation test.

“Green component tests missed disconnected ERS mapping and one serial model call
per resource. Those failures lived between well-tested components.

The fixes drive the actual service path and evaluate a decision-shaped
obligation request once. This is why the remaining end-to-end PDP test is more
valuable than another isolated helper test.”

## 6:25 — Close

**On screen:** Shadow → measure → enforce, followed by the subset equation.

“Our deployment sequence is off, then shadow, then measured enforcement. Prefer
a PEP-enforced step-up over denial where possible. Keep model-derived claims
namespaced, validate the wire response, and never confuse confidence with
correctness.

The model can contribute judgment. Policy must continue to own authority.”
