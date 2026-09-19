package obligations

import (
	"context"
	"errors"
	"testing"

	authz "github.com/opentdf/platform/protocol/go/authorization/v2"
	"github.com/opentdf/platform/protocol/go/policy"
	attrs "github.com/opentdf/platform/protocol/go/policy/attributes"
	"github.com/opentdf/platform/service/logger"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const dynamicObligationFQN = "https://example.org/obl/step_up/value/required"

// fakeTrigger records what it was asked and returns a canned answer.
type fakeTrigger struct {
	err      error
	returns  []string
	requests []TriggerRequest
}

func (f *fakeTrigger) AdditionalObligations(_ context.Context, req TriggerRequest) ([]string, error) {
	f.requests = append(f.requests, req)
	if f.err != nil {
		return nil, f.err
	}
	return f.returns, nil
}

func newPDPWithTrigger(t *testing.T, trigger DynamicTrigger, obligations []*policy.Obligation) *ObligationsPolicyDecisionPoint {
	t.Helper()

	attributesByValueFQN := map[string]*attrs.GetAttributeValuesByFqnsResponse_AttributeAndValue{
		mockAttrValFQN1: {
			Attribute: &policy.Attribute{Name: "attr1"},
			Value:     &policy.Value{Fqn: mockAttrValFQN1},
		},
	}

	var opts []Option
	if trigger != nil {
		opts = append(opts, WithDynamicTrigger(trigger))
	}

	pdp, err := NewObligationsPolicyDecisionPoint(
		t.Context(), logger.CreateTestLogger(),
		attributesByValueFQN, nil, obligations, opts...,
	)
	require.NoError(t, err)
	return pdp
}

func attrResource() []*authz.Resource {
	return []*authz.Resource{{
		EphemeralId: "r-0",
		Resource: &authz.Resource_AttributeValues_{
			AttributeValues: &authz.Resource_AttributeValues{Fqns: []string{mockAttrValFQN1}},
		},
	}}
}

func TestDynamicTriggerAddsObligationPolicyDidNotRequire(t *testing.T) {
	trigger := &fakeTrigger{returns: []string{dynamicObligationFQN}}
	pdp := newPDPWithTrigger(t, trigger, nil)

	perResource, all, err := pdp.getTriggeredObligations(
		t.Context(), actionRead, attrResource(), emptyDecisionRequestContext)
	require.NoError(t, err)

	assert.Equal(t, []string{dynamicObligationFQN}, all)
	assert.Equal(t, []string{dynamicObligationFQN}, perResource[0])
}

func TestDynamicTriggerIsConsultedWhenNoStaticTriggerExists(t *testing.T) {
	// Without a trigger the PDP short-circuits on an action no obligation
	// mentions; with one installed it must still be asked.
	trigger := &fakeTrigger{}
	pdp := newPDPWithTrigger(t, trigger, nil)

	_, _, err := pdp.getTriggeredObligations(
		t.Context(), actionCustom, attrResource(), emptyDecisionRequestContext)
	require.NoError(t, err)

	require.Len(t, trigger.requests, 1)
	assert.Equal(t, actionNameCustom, trigger.requests[0].ActionName)
	assert.Equal(t, []string{mockAttrValFQN1}, trigger.requests[0].AttributeValueFQNs)
}

func TestDynamicTriggerCannotRemovePolicyObligations(t *testing.T) {
	// The trigger returns nothing, so the policy-triggered obligation must
	// survive untouched.
	static := []*policy.Obligation{{
		Values: []*policy.ObligationValue{{
			Fqn: mockObligationFQN1,
			Triggers: []*policy.ObligationTrigger{{
				AttributeValue: &policy.Value{Fqn: mockAttrValFQN1},
				Action:         actionRead,
			}},
		}},
	}}
	trigger := &fakeTrigger{returns: nil}
	pdp := newPDPWithTrigger(t, trigger, static)

	_, all, err := pdp.getTriggeredObligations(
		t.Context(), actionRead, attrResource(), emptyDecisionRequestContext)
	require.NoError(t, err)

	assert.Equal(t, []string{mockObligationFQN1}, all,
		"a dynamic trigger may only add; policy obligations are never withdrawn")
	require.Len(t, trigger.requests, 1)
	assert.Equal(t, []string{mockObligationFQN1}, trigger.requests[0].PolicyTriggered,
		"the trigger sees what policy already required")
}

func TestDynamicTriggerDeduplicatesAgainstPolicy(t *testing.T) {
	static := []*policy.Obligation{{
		Values: []*policy.ObligationValue{{
			Fqn: mockObligationFQN1,
			Triggers: []*policy.ObligationTrigger{{
				AttributeValue: &policy.Value{Fqn: mockAttrValFQN1},
				Action:         actionRead,
			}},
		}},
	}}
	trigger := &fakeTrigger{returns: []string{mockObligationFQN1, dynamicObligationFQN}}
	pdp := newPDPWithTrigger(t, trigger, static)

	_, all, err := pdp.getTriggeredObligations(
		t.Context(), actionRead, attrResource(), emptyDecisionRequestContext)
	require.NoError(t, err)

	assert.ElementsMatch(t, []string{mockObligationFQN1, dynamicObligationFQN}, all)
	assert.Len(t, all, 2, "re-stating a policy obligation must not duplicate it")
}

func TestDynamicTriggerErrorFailsTheDecision(t *testing.T) {
	trigger := &fakeTrigger{err: errors.New("model unreachable")}
	pdp := newPDPWithTrigger(t, trigger, nil)

	_, _, err := pdp.getTriggeredObligations(
		t.Context(), actionRead, attrResource(), emptyDecisionRequestContext)

	require.Error(t, err, "a trigger that reports an error has chosen to fail closed")
	assert.Contains(t, err.Error(), "dynamic obligation trigger failed")
}

func TestNoTriggerLeavesBehaviourUnchanged(t *testing.T) {
	pdp := newPDPWithTrigger(t, nil, nil)

	_, all, err := pdp.getTriggeredObligations(
		t.Context(), actionRead, attrResource(), emptyDecisionRequestContext)
	require.NoError(t, err)
	assert.Empty(t, all)
}
