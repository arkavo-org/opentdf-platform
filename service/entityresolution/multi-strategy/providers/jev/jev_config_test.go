package jev

import (
	"testing"

	"github.com/go-viper/mapstructure/v2"
	jevclient "github.com/opentdf/platform/service/internal/jev"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestConfigDecodesDocumentedConnectionBlock pins the YAML shape published in
// docs/jev-decision-model.md. The provider's settings are squashed into the
// provider's `connection` map, so a change to either must break this test.
func TestConfigDecodesDocumentedConnectionBlock(t *testing.T) {
	connection := map[string]any{
		"enabled":              true,
		"state_allowlist":      []string{"department", "employment_type"},
		"confidence_threshold": 0.85,
		"seams": map[string]any{
			"ers_claims": map[string]any{"enabled": true, "mode": "shadow"},
		},
		"questions": map[string]any{
			"risk_tier": map[string]any{
				"type":         "choice",
				"instructions": "How much scrutiny?",
				"criteria":     map[string]any{"elevated": "contractor", "routine": "tenured"},
			},
		},
	}

	var cfg Config
	require.NoError(t, mapstructure.Decode(connection, &cfg))

	assert.True(t, cfg.Client.Enabled)
	assert.Equal(t, []string{"department", "employment_type"}, cfg.Client.StateAllowlist)
	assert.InDelta(t, 0.85, cfg.Client.ConfidenceThreshold, 1e-9)
	assert.Equal(t, jevclient.ModeShadow, cfg.Client.Seams.ERSClaims.Mode)

	require.Contains(t, cfg.Questions, "risk_tier")
	assert.Equal(t, jevclient.QuestionTypeChoice, cfg.Questions["risk_tier"].Type)
}

func TestValidateRejectsUnknownQuestionType(t *testing.T) {
	cfg := Config{
		Client: jevclient.Config{Enabled: true, StateAllowlist: []string{"a"}},
		Questions: map[string]jevclient.Question{
			"q": {Type: "guess", Instructions: "x"},
		},
	}
	require.Error(t, cfg.Validate())
}

func TestValidateRequiresInstructions(t *testing.T) {
	cfg := Config{
		Client: jevclient.Config{Enabled: true, StateAllowlist: []string{"a"}},
		Questions: map[string]jevclient.Question{
			"q": {Type: jevclient.QuestionTypeNoul},
		},
	}
	require.Error(t, cfg.Validate())
}

func TestValidateSkipsDisabledProvider(t *testing.T) {
	cfg := Config{Client: jevclient.Config{Enabled: false}}
	require.NoError(t, cfg.Validate(), "a disabled provider need not configure questions")
}
