package composite

import (
	"testing"

	"github.com/opentdf/platform/service/entityresolution/source"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestTokenClaimsSource_SelectsOwnDefinitions(t *testing.T) {
	src := newTokenClaimsSource("arkavo_entitlements", []string{"https://patreon.arkavo.com/attr/arkavo-creator"})
	claims := map[string]any{"arkavo_entitlements": []any{
		"https://patreon.arkavo.com/attr/arkavo-creator/value/Publish", // owned, lowercased
		"https://patreon.arkavo.com/attr/arkavo-creator/value/publish", // duplicate once lowercased
		"https://patreon.arkavo.com/attr/arkavo-creator-pro/value/x",   // another definition with a shared prefix
		"https://patreon.arkavo.com/attr/campaign/value/123",           // another source's definition
		"https://other.example/attr/arkavo-creator/value/publish",      // another namespace
		"not an fqn",
		42,
	}, "other_claim": []any{"https://patreon.arkavo.com/attr/arkavo-creator/value/ignored"}}

	res, err := src.Resolve(t.Context(), source.Subject{Claims: claims, Kind: source.KindPerson}, source.Query{})
	require.NoError(t, err)
	assert.Equal(t, source.OutcomeComplete, res.Outcome)
	require.Len(t, res.Grants, 1)
	assert.Equal(t, "https://patreon.arkavo.com/attr/arkavo-creator/value/publish", res.Grants[0].FQN)
}

func TestTokenClaimsSource_NothingToGrantIsNotApplicable(t *testing.T) {
	src := newTokenClaimsSource("arkavo_entitlements", []string{"https://patreon.arkavo.com/attr/arkavo-creator"})
	for name, claims := range map[string]map[string]any{
		"no claims":      nil,
		"claim absent":   {"sub": "x"},
		"claim not list": {"arkavo_entitlements": "https://patreon.arkavo.com/attr/arkavo-creator/value/publish"},
	} {
		t.Run(name, func(t *testing.T) {
			res, err := src.Resolve(t.Context(), source.Subject{Claims: claims}, source.Query{})
			require.NoError(t, err)
			assert.Empty(t, res.Grants)
			assert.Equal(t, source.OutcomeNotApplicable, res.Outcome)
		})
	}
}
