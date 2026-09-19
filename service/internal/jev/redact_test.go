package jev

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestRedactStateKeepsOnlyAllowlistedKeys(t *testing.T) {
	state := map[string]any{
		"clearance": "secret",
		"ssn":       "123-45-6789",
		"email":     "user@example.com",
	}

	got := RedactState(state, []string{"clearance"})

	assert.Equal(t, map[string]any{"clearance": "secret"}, got)
	assert.NotContains(t, got, "ssn", "unlisted keys must never leave the platform")
}

func TestRedactStateReturnsEmptyNotNil(t *testing.T) {
	got := RedactState(map[string]any{"a": 1}, nil)
	assert.NotNil(t, got, "a fully redacted state must marshal as {} rather than null")
	assert.Empty(t, got)
}

func TestRedactStateMatchesExactlyAndCaseSensitively(t *testing.T) {
	state := map[string]any{"Clearance": "secret", "clearance_level": "high"}
	got := RedactState(state, []string{"clearance"})
	assert.Empty(t, got, "allowlist entries must not match by prefix or fold case")
}

func TestRedactedKeysReportsDroppedNamesSorted(t *testing.T) {
	state := map[string]any{"z": 1, "a": 2, "keep": 3}
	assert.Equal(t, []string{"a", "z"}, RedactedKeys(state, []string{"keep"}))
}
