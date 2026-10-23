package source

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestParseFQN(t *testing.T) {
	tests := []struct {
		name string
		in   string
		want FQN
		ok   bool
	}{
		{"campaign", "https://patreon.arkavo.com/attr/campaign/value/13167240", FQN{"patreon.arkavo.com", "campaign", "13167240"}, true},
		{"lowercased", "HTTPS://Patreon.Arkavo.com/attr/Campaign/value/X1", FQN{"patreon.arkavo.com", "campaign", "x1"}, true},
		{"lookalike namespace parses", "https://patreon.arkavo.com.evil/attr/campaign/value/1", FQN{"patreon.arkavo.com.evil", "campaign", "1"}, true},
		{"no value segment", "https://patreon.arkavo.com/attr/campaign", FQN{}, false},
		{"value keyword without value", "https://patreon.arkavo.com/attr/campaign/value", FQN{}, false},
		{"empty value", "https://patreon.arkavo.com/attr/campaign/value/", FQN{}, false},
		{"http scheme", "http://patreon.arkavo.com/attr/campaign/value/1", FQN{}, false},
		{"extra segment", "https://patreon.arkavo.com/attr/campaign/value/1/2", FQN{}, false},
		{"attrs typo", "https://patreon.arkavo.com/attrs/campaign/value/1", FQN{}, false},
		{"empty namespace", "https:///attr/campaign/value/1", FQN{}, false},
		{"empty definition", "https://patreon.arkavo.com/attr//value/1", FQN{}, false},
		{"empty string", "", FQN{}, false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, ok := ParseFQN(tc.in)
			assert.Equal(t, tc.ok, ok)
			assert.Equal(t, tc.want, got)
		})
	}
}

func TestFQNStrings(t *testing.T) {
	f, ok := ParseFQN("HTTPS://Patreon.Arkavo.com/attr/Campaign/value/13167240")
	require.True(t, ok)
	assert.Equal(t, "https://patreon.arkavo.com/attr/campaign", f.DefinitionFQN())
	assert.Equal(t, "https://patreon.arkavo.com/attr/campaign/value/13167240", f.String())
}

func TestParseDefinition(t *testing.T) {
	ns, def, ok := ParseDefinition("https://patreon.arkavo.com/attr/campaign-tier")
	require.True(t, ok)
	assert.Equal(t, "patreon.arkavo.com", ns)
	assert.Equal(t, "campaign-tier", def)

	for _, in := range []string{
		"https://patreon.arkavo.com/attr/campaign/value/1",
		"https://patreon.arkavo.com/attr/",
		"https://patreon.arkavo.com/attr",
		"http://patreon.arkavo.com/attr/campaign",
		"https://patreon.arkavo.com/attrs/campaign",
		"",
	} {
		_, _, valid := ParseDefinition(in)
		assert.False(t, valid, in)
	}
}

func TestKindOf(t *testing.T) {
	assert.Equal(t, KindPerson, KindOf(map[string]any{}))
	assert.Equal(t, KindPerson, KindOf(nil))
	assert.Equal(t, KindDevice, KindOf(map[string]any{"arkavo_npe": map[string]any{"type": "device"}}))
	assert.Equal(t, KindAgent, KindOf(map[string]any{"arkavo_npe": map[string]any{"type": "agent"}}))
	assert.Equal(t, KindAgent, KindOf(map[string]any{"arkavo_swarm": "s"}))
	assert.Equal(t, KindDevice, KindOf(map[string]any{"aud": "arkavo:devicecheck"}))
	assert.Equal(t, KindDevice, KindOf(map[string]any{"aud": []any{"arkavo", "arkavo:devicecheck"}}))
	assert.Equal(t, KindDevice, KindOf(map[string]any{"aud": []string{"arkavo:devicecheck"}}))
	assert.Equal(t, KindPerson, KindOf(map[string]any{"aud": []any{"arkavo", "https://platform.arkavo.net"}}))
	assert.Equal(t, KindPerson, KindOf(map[string]any{"aud": "arkavo"}))
	// An agent marker wins over a DeviceCheck audience.
	assert.Equal(t, KindAgent, KindOf(map[string]any{"aud": "arkavo:devicecheck", "arkavo_swarm": "s"}))
}
