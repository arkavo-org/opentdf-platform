package jevrestrictor

import (
	"testing"

	"github.com/go-viper/mapstructure/v2"
	"github.com/opentdf/platform/service/internal/jev"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestConfigDecodesDocumentedYAML pins the services.authorization.jev_restrictor
// block published in docs/jev-decision-model.md.
func TestConfigDecodesDocumentedYAML(t *testing.T) {
	raw := map[string]any{
		"enabled":              true,
		"model":                "typesafe/jev-1.13",
		"timeout":              "500ms",
		"fail_mode":            "open",
		"confidence_threshold": 0.95,
		"state_allowlist":      []string{StateKeyAction, StateKeyResourceCount},
		"seams": map[string]any{
			"restrictor": map[string]any{"enabled": true, "mode": "shadow"},
		},
		"questions": map[string]any{
			"is_exfiltration": map[string]any{
				"type":         "noul",
				"instructions": "Does this look like bulk exfiltration?",
				"criteria":     map[string]any{"true": "bulk", "false": "routine"},
			},
		},
		"rules": []any{
			map[string]any{
				"question": "is_exfiltration",
				"reason":   "looks like bulk exfiltration",
			},
		},
	}

	var cfg Config
	require.NoError(t, mapstructure.Decode(raw, &cfg))

	assert.True(t, cfg.Client.Enabled)
	assert.Equal(t, jev.ModeShadow, cfg.Client.Seams.Restrictor.Mode)
	assert.InDelta(t, 0.95, cfg.Client.ConfidenceThreshold, 1e-9)
	require.Len(t, cfg.Rules, 1)
	assert.Equal(t, "looks like bulk exfiltration", cfg.Rules[0].Reason)
	require.NoError(t, cfg.Client.Validate())
}

func TestDocumentedStateKeysAreStable(t *testing.T) {
	assert.Equal(t, "entity_id", StateKeyEntityID)
	assert.Equal(t, "action", StateKeyAction)
	assert.Equal(t, "resource_count", StateKeyResourceCount)
	assert.Equal(t, "attribute_value_fqns", StateKeyAttributeValueFQNs)
	assert.Equal(t, "permitted_count", StateKeyPermittedCount)
}
