package jev

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestValidateSkipsDisabledConfig(t *testing.T) {
	cfg := &Config{Enabled: false, Timeout: "nonsense"}
	assert.NoError(t, cfg.Validate(), "a disabled client need not be configured")
}

func TestValidateAppliesDefaults(t *testing.T) {
	cfg := &Config{Enabled: true, StateAllowlist: []string{"sub"}}
	require.NoError(t, cfg.Validate())

	assert.Equal(t, DefaultModel, cfg.Model)
	assert.Equal(t, DefaultBaseURL, cfg.BaseURL)
	assert.Equal(t, FailOpen, cfg.FailMode)
	assert.InDelta(t, DefaultConfidenceThreshold, cfg.ConfidenceThreshold, 1e-9)
	assert.Equal(t, DefaultTimeout, cfg.Timeout)
}

func TestValidateRejectsEmptyAllowlist(t *testing.T) {
	cfg := &Config{Enabled: true}
	assert.ErrorIs(t, cfg.Validate(), ErrNoStateAllowlist,
		"enabling Jev without an allowlist would send nothing and hide the misconfiguration")
}

func TestValidateRejectsBadValues(t *testing.T) {
	for name, cfg := range map[string]*Config{
		"timeout":   {Enabled: true, StateAllowlist: []string{"a"}, Timeout: "soon"},
		"cache_ttl": {Enabled: true, StateAllowlist: []string{"a"}, CacheTTL: "never"},
		"threshold": {Enabled: true, StateAllowlist: []string{"a"}, ConfidenceThreshold: 1.5},
		"fail_mode": {Enabled: true, StateAllowlist: []string{"a"}, FailMode: "maybe"},
		"seam_mode": {
			Enabled: true, StateAllowlist: []string{"a"},
			Seams: SeamsConfig{Obligations: SeamConfig{Enabled: true, Mode: "sometimes"}},
		},
	} {
		t.Run(name, func(t *testing.T) {
			assert.Error(t, cfg.Validate())
		})
	}
}

func TestSeamDefaultsToShadowAndNotEnforcing(t *testing.T) {
	assert.False(t, SeamConfig{Enabled: true, Mode: ModeShadow}.Enforcing())
	assert.False(t, SeamConfig{Enabled: false, Mode: ModeEnforce}.Enforcing(),
		"a disabled seam must never enforce")
	assert.True(t, SeamConfig{Enabled: true, Mode: ModeEnforce}.Enforcing())
}

func TestLogValueOmitsSecrets(t *testing.T) {
	cfg := &Config{Enabled: true, StateAllowlist: []string{"sub", "tier"}}
	require.NoError(t, cfg.Validate())

	rendered := cfg.LogValue().String()
	assert.Contains(t, rendered, "state_allowlist_size=2",
		"log the allowlist size, never the values it admits")
	assert.NotContains(t, rendered, "api_key")
}
