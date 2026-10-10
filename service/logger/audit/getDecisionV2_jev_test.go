package audit

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// These tests cover the glue that makes decision-model seams observable:
// seams publish observations to a per-request collector, and the decision
// event folds them in, so a decision still yields exactly one audit record.

func TestV2GetDecisionEventCarriesJevObservations(t *testing.T) {
	observations := []map[string]any{{
		"seam":        "obligations",
		"mode":        "enforce",
		"question":    "is_anomalous",
		"certainty":   0.97,
		"applied":     true,
		"effect":      "required_obligation:https://example.org/obl/step_up/value/required",
		"response_id": "gen-dec-oblig",
	}}

	event, err := CreateV2GetDecisionEvent(context.Background(), GetDecisionV2EventParams{
		EntityID:   "entity-1",
		ActionName: "read",
		Decision:   GetDecisionResultPermit,
		Jev:        observations,
	})
	require.NoError(t, err)

	require.Contains(t, event.EventMetaData, "jev",
		"a model-influenced decision must record that influence in its own audit event")
	assert.Equal(t, observations, event.EventMetaData["jev"])
}

func TestV2GetDecisionEventOmitsJevWhenNoModelConsulted(t *testing.T) {
	event, err := CreateV2GetDecisionEvent(context.Background(), GetDecisionV2EventParams{
		EntityID:   "entity-1",
		ActionName: "read",
		Decision:   GetDecisionResultPermit,
	})
	require.NoError(t, err)

	assert.NotContains(t, event.EventMetaData, "jev",
		"decisions made without a model must not gain an empty jev key")
}

func TestV2GetDecisionEventKeepsExistingMetadataAlongsideJev(t *testing.T) {
	event, err := CreateV2GetDecisionEvent(context.Background(), GetDecisionV2EventParams{
		EntityID:             "entity-1",
		ActionName:           "read",
		Decision:             GetDecisionResultDeny,
		ObligationsSatisfied: false,
		Jev:                  []map[string]any{{"seam": "obligations"}},
	})
	require.NoError(t, err)

	assert.Contains(t, event.EventMetaData, "jev")
	assert.Contains(t, event.EventMetaData, "resource_decisions")
	assert.Contains(t, event.EventMetaData, "obligations_satisfied")
	assert.Contains(t, event.EventMetaData, "fulfillable_obligation_value_fqns")
	assert.Equal(t, ActionResultFailure, event.Action.Result)
}
