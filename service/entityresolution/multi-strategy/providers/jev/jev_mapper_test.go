package jev

import (
	"testing"

	"github.com/opentdf/platform/service/entityresolution/multi-strategy/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestExtractParametersSelectsNamedClaims(t *testing.T) {
	m := NewMapper()

	params, err := m.ExtractParameters(
		types.JWTClaims{"dept": "finance", "ssn": "123-45-6789"},
		[]types.InputMapping{{JWTClaim: "dept", Parameter: "department"}},
	)
	require.NoError(t, err)

	assert.Equal(t, map[string]any{"department": "finance"}, params,
		"input_mapping is the first gate on what may reach the model")
}

func TestExtractParametersHonoursRequiredAndDefault(t *testing.T) {
	m := NewMapper()

	_, err := m.ExtractParameters(types.JWTClaims{},
		[]types.InputMapping{{JWTClaim: "dept", Parameter: "department", Required: true}})
	require.Error(t, err)

	params, err := m.ExtractParameters(types.JWTClaims{},
		[]types.InputMapping{{JWTClaim: "dept", Parameter: "department", Default: "unknown"}})
	require.NoError(t, err)
	assert.Equal(t, "unknown", params["department"])
}

func TestTransformResultsMapsAnswersToClaims(t *testing.T) {
	m := NewMapper()

	claims, err := m.TransformResults(
		map[string]any{"risk_tier": "elevated"},
		[]types.OutputMapping{{SourceAnswer: "risk_tier", ClaimName: "risk", Transformation: "array"}},
	)
	require.NoError(t, err)

	assert.Equal(t, []any{"elevated"}, claims["risk"],
		"subject mappings commonly match arrays, so the array transformation must apply")
}

func TestTransformResultsSkipsAbsentAnswers(t *testing.T) {
	m := NewMapper()

	claims, err := m.TransformResults(
		map[string]any{},
		[]types.OutputMapping{{SourceAnswer: "risk_tier", ClaimName: "risk"}},
	)
	require.NoError(t, err)

	assert.Empty(t, claims, "an answer withheld for low confidence yields no claim at all")
}

func TestValidateOutputMappingRequiresSourceAnswer(t *testing.T) {
	m := NewMapper()

	require.Error(t, m.ValidateOutputMapping([]types.OutputMapping{{ClaimName: "risk"}}))
	require.Error(t, m.ValidateOutputMapping([]types.OutputMapping{{SourceAnswer: "q"}}))
	require.Error(t, m.ValidateOutputMapping([]types.OutputMapping{
		{SourceAnswer: "q", ClaimName: "risk", Transformation: "ldap_dn_to_cn"},
	}), "provider-specific transformations from other providers must not be accepted")

	require.NoError(t, m.ValidateOutputMapping([]types.OutputMapping{
		{SourceAnswer: "q", ClaimName: "risk", Transformation: "array"},
	}))
}
