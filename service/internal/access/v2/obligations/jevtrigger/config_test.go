package jevtrigger

import (
	"testing"

	"github.com/go-viper/mapstructure/v2"
	"github.com/opentdf/platform/service/internal/jev"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestConfigDecodesDocumentedYAML pins the services.authorization.jev block
// published in docs/jev-decision-model.md. A change to either must break here.
func TestConfigDecodesDocumentedYAML(t *testing.T) {
	raw := map[string]any{
		"enabled":              true,
		"model":                "typesafe/jev-1.13",
		"api_key_env":          "OPENROUTER_API_KEY",
		"timeout":              "500ms",
		"fail_mode":            "open",
		"confidence_threshold": 0.85,
		"state_allowlist": []string{
			StateKeyAction, StateKeyAttributeValueFQNs, StateKeyResourceCount,
		},
		"seams": map[string]any{
			"obligations": map[string]any{"enabled": true, "mode": "shadow"},
		},
		"questions": map[string]any{
			"is_anomalous": map[string]any{
				"type":         "noul",
				"instructions": "Is this request unusual?",
				"criteria":     map[string]any{"true": "rare", "false": "routine"},
			},
		},
		"rules": []any{
			map[string]any{
				"question":   "is_anomalous",
				"obligation": "https://example.org/obl/step_up/value/required",
			},
		},
	}

	var cfg Config
	require.NoError(t, mapstructure.Decode(raw, &cfg))

	assert.True(t, cfg.Client.Enabled)
	assert.Equal(t, "typesafe/jev-1.13", cfg.Client.Model,
		"the documented model must be the pinned version, not a floating alias")
	assert.Equal(t, jev.FailOpen, cfg.Client.FailMode)
	assert.Equal(t, jev.ModeShadow, cfg.Client.Seams.Obligations.Mode)

	require.Contains(t, cfg.Questions, "is_anomalous")
	assert.Equal(t, jev.QuestionTypeNoul, cfg.Questions["is_anomalous"].Type)

	require.Len(t, cfg.Rules, 1)
	assert.Equal(t, "is_anomalous", cfg.Rules[0].Question)
	assert.Equal(t, "https://example.org/obl/step_up/value/required", cfg.Rules[0].Obligation)
	require.NoError(t, cfg.Client.Validate())
}

func TestDocumentedStateKeysAreStable(t *testing.T) {
	// These names are the configuration contract for state_allowlist.
	assert.Equal(t, "action", StateKeyAction)
	assert.Equal(t, "attribute_value_fqns", StateKeyAttributeValueFQNs)
	assert.Equal(t, "pep_client_id", StateKeyPEPClientID)
	assert.Equal(t, "policy_triggered_obligations", StateKeyPolicyTriggered)
	assert.Equal(t, "resource_count", StateKeyResourceCount)
}
