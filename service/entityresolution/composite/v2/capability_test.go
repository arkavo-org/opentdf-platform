package composite

import (
	"testing"

	"github.com/opentdf/platform/service/entityresolution/source"
	"github.com/stretchr/testify/assert"
)

const (
	testIssuer    = "https://identity.arkavo.net"
	campaignDef   = "https://patreon.arkavo.com/attr/campaign"
	campaignValue = "https://patreon.arkavo.com/attr/campaign/value/123"
	tierDef       = "https://patreon.arkavo.com/attr/campaign-tier"
)

func TestCapability_Admits(t *testing.T) {
	base := SourceConfig{ID: "s", Issuer: testIssuer, Grants: []string{campaignDef}}
	assertable := base
	assertable.PEPAssertable = true
	agentsOnly := base
	agentsOnly.Subjects = []source.Kind{source.KindAgent}

	iss := func(v string) map[string]any { return map[string]any{"iss": v} }
	tests := []struct {
		name    string
		sc      SourceConfig
		subject source.Subject
		want    bool
	}{
		{"verified, matching iss", base, source.Subject{Kind: source.KindPerson, Trust: source.TrustVerified, Claims: iss(testIssuer)}, true},
		{"verified, another iss", base, source.Subject{Kind: source.KindPerson, Trust: source.TrustVerified, Claims: iss("https://evil.example")}, false},
		{"verified, no iss", base, source.Subject{Kind: source.KindPerson, Trust: source.TrustVerified, Claims: map[string]any{}}, false},
		{"PEP, not assertable", base, source.Subject{Kind: source.KindPerson, Trust: source.TrustPEP, Claims: iss(testIssuer)}, false},
		{"PEP, assertable, matching iss", assertable, source.Subject{Kind: source.KindPerson, Trust: source.TrustPEP, Claims: iss(testIssuer)}, true},
		{"PEP, assertable, no iss", assertable, source.Subject{Kind: source.KindPerson, Trust: source.TrustPEP, Claims: map[string]any{}}, false},
		{"PEP, assertable, another iss", assertable, source.Subject{Kind: source.KindPerson, Trust: source.TrustPEP, Claims: iss("x")}, false},
		{"kind not listed", agentsOnly, source.Subject{Kind: source.KindPerson, Trust: source.TrustVerified, Claims: iss(testIssuer)}, false},
		{"default subjects cover every kind", base, source.Subject{Kind: source.KindDevice, Trust: source.TrustVerified, Claims: iss(testIssuer)}, true},
		{"trust none", base, source.Subject{Kind: source.KindPerson, Trust: source.TrustNone}, true},
		{"trust none, kind not listed", agentsOnly, source.Subject{Kind: source.KindPerson, Trust: source.TrustNone}, false},
		{"unknown trust level", base, source.Subject{Kind: source.KindPerson, Trust: source.Trust(99), Claims: iss(testIssuer)}, false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, newCapability(tc.sc).admits(tc.subject))
		})
	}
}

func TestCapability_Allows(t *testing.T) {
	c := newCapability(SourceConfig{ID: "s", Issuer: testIssuer, Grants: []string{campaignDef}})
	tests := []struct {
		name  string
		grant source.Grant
		want  bool
	}{
		{"owned definition, default action", source.Grant{FQN: campaignValue, Actions: []string{"read"}}, true},
		{"owned definition, mixed case", source.Grant{FQN: "https://Patreon.Arkavo.com/attr/Campaign/value/123", Actions: []string{"read"}}, true},
		{"owned definition, no actions", source.Grant{FQN: campaignValue}, true},
		{"another definition", source.Grant{FQN: tierDef + "/value/123_gold", Actions: []string{"read"}}, false},
		{"a prefix of an owned definition is not owned", source.Grant{FQN: campaignDef + "-tier/value/1", Actions: []string{"read"}}, false},
		{"unparseable", source.Grant{FQN: "not-an-fqn", Actions: []string{"read"}}, false},
		{"a definition, not a value", source.Grant{FQN: campaignDef, Actions: []string{"read"}}, false},
		{"action not allowed", source.Grant{FQN: campaignValue, Actions: []string{"write"}}, false},
		{"one action not allowed", source.Grant{FQN: campaignValue, Actions: []string{"read", "write"}}, false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, c.allows(tc.grant))
		})
	}

	t.Run("configured actions replace the read default", func(t *testing.T) {
		pub := newCapability(SourceConfig{ID: "s", Issuer: testIssuer, Grants: []string{campaignDef}, Actions: []string{"publish"}})
		assert.True(t, pub.allows(source.Grant{FQN: campaignValue, Actions: []string{"publish"}}))
		assert.False(t, pub.allows(source.Grant{FQN: campaignValue, Actions: []string{"read"}}))
	})
}
