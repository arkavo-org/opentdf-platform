package composite

import (
	"encoding/base64"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/opentdf/platform/service/entityresolution/source"
	"github.com/opentdf/platform/service/internal/agentstatus"
	"github.com/opentdf/platform/service/internal/chaindevice"
	"github.com/opentdf/platform/service/internal/publishingstatus"
	"github.com/opentdf/platform/service/pkg/config"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

var (
	testSealKey = base64.StdEncoding.EncodeToString([]byte(strings.Repeat("k", 32)))
	oldSealKey  = base64.StdEncoding.EncodeToString([]byte(strings.Repeat("o", 40)))
)

// validConfig is the spec §7 shape: a patreon source and identity-core, one
// issuer.
func validConfig() Config {
	return Config{
		Deadline: 300 * time.Millisecond,
		Evidence: EvidenceConfig{
			Issuers: []IssuerConfig{{
				Issuer:      testIssuer,
				COSEKeysURL: testIssuer + "/.well-known/cose-keys",
				Audience:    "https://platform.arkavo.net",
			}},
			SealKey:          testSealKey,
			PreviousSealKeys: []string{oldSealKey},
			ClaimsChainPEPs:  []string{"00000000-0000-0000-0000-000000000001"},
		},
		Sources: []SourceConfig{
			{
				ID: "patreon", Type: "patreon-token", Issuer: testIssuer,
				Grants:        []string{campaignDef, tierDef},
				PropertiesKey: "patreon", PEPAssertable: true,
				Options: map[string]any{"infer_unknown_as_free": true},
			},
			{
				ID: "identity-core", Type: "token-claims", Issuer: testIssuer,
				Grants:  []string{"https://patreon.arkavo.com/attr/arkavo-creator"},
				Actions: []string{"publish"},
				Options: map[string]any{"claim": "arkavo_entitlements"},
			},
		},
	}
}

func TestValidate(t *testing.T) {
	require.NoError(t, validConfig().Validate(), "the spec shape is valid")

	tests := []struct {
		name   string
		mutate func(*Config)
		want   []string // substrings of the error
	}{
		{"no issuers", func(c *Config) { c.Evidence.Issuers = nil }, []string{"evidence.issuers"}},
		{"issuer without a name", func(c *Config) { c.Evidence.Issuers[0].Issuer = "" }, []string{"issuer"}},
		{"issuer without cose_keys_url", func(c *Config) { c.Evidence.Issuers[0].COSEKeysURL = "" }, []string{"cose_keys_url"}},
		{"issuer without audience", func(c *Config) { c.Evidence.Issuers[0].Audience = "" }, []string{"audience"}},
		{"empty seal_key", func(c *Config) { c.Evidence.SealKey = "" }, []string{"seal_key"}},
		{"seal_key not base64", func(c *Config) { c.Evidence.SealKey = "not base64 !!" }, []string{"seal_key", "base64"}},
		{"seal_key under 32 bytes", func(c *Config) {
			c.Evidence.SealKey = base64.StdEncoding.EncodeToString([]byte(strings.Repeat("k", 31)))
		}, []string{"seal_key", "32"}},
		{"previous key not base64", func(c *Config) { c.Evidence.PreviousSealKeys = []string{"not base64 !!"} }, []string{"previous_seal_keys[0]", "base64"}},
		{"previous key under 32 bytes", func(c *Config) {
			c.Evidence.PreviousSealKeys = []string{base64.StdEncoding.EncodeToString([]byte("short"))}
		}, []string{"previous_seal_keys[0]", "32"}},
		{"empty claims_chain_peps entry", func(c *Config) { c.Evidence.ClaimsChainPEPs = []string{""} }, []string{"claims_chain_peps"}},
		{"source with an empty id", func(c *Config) { c.Sources[0].ID = "" }, []string{"sources[0]", "id"}},
		{"duplicate source id", func(c *Config) { c.Sources[1].ID = "patreon" }, []string{"duplicate", "patreon"}},
		{"unknown source type", func(c *Config) { c.Sources[0].Type = "live-http" }, []string{"live-http"}},
		{"unknown subject kind", func(c *Config) { c.Sources[0].Subjects = []source.Kind{"robot"} }, []string{"robot"}},
		{"grant is not a definition FQN", func(c *Config) { c.Sources[0].Grants = []string{"campaign"} }, []string{"campaign", "definition"}},
		{"grant is a value FQN", func(c *Config) { c.Sources[0].Grants = []string{campaignValue} }, []string{"definition"}},
		{"source issuer is not an evidence issuer", func(c *Config) { c.Sources[0].Issuer = "https://evil.example" }, []string{"patreon", "evil.example"}},
		{"source without an issuer", func(c *Config) { c.Sources[0].Issuer = "" }, []string{"patreon", "issuer"}},
		{"two sources share a definition", func(c *Config) { c.Sources[1].Grants = []string{"https://Patreon.arkavo.com/attr/campaign"} }, []string{campaignDef, "patreon", "identity-core"}},
		{"token-claims without a claim", func(c *Config) { delete(c.Sources[1].Options, "claim") }, []string{"identity-core", "claim"}},
		{"token-claims with a non-string claim", func(c *Config) { c.Sources[1].Options["claim"] = 5 }, []string{"identity-core", "claim"}},
		{"patreon-token with an unknown option", func(c *Config) { c.Sources[0].Options["claims"] = []any{"arkavo_patreon"} }, []string{"patreon", "claims"}},
		{"token-claims with an unknown option", func(c *Config) { c.Sources[1].Options["claims"] = "x" }, []string{"identity-core", "claims"}},
		{"agent_status timeout over the lease", func(c *Config) {
			c.Constraints.AgentStatus = agentstatus.Config{URL: "https://identity.example.com", ClientID: "c", ClientSecret: "s", Timeout: 6 * time.Second}
		}, []string{"agent_status"}},
		{"agent_status half filled", func(c *Config) {
			c.Constraints.AgentStatus = agentstatus.Config{URL: "https://identity.example.com", ClientID: "c"}
		}, []string{"agent_status"}},
		{"publishing_status half filled", func(c *Config) {
			c.Constraints.PublishingStatus = publishingstatus.Config{URL: "https://platform.example.com", ClientID: "c"}
		}, []string{"constraints.publishing_status"}},
		// A bare YAML integer decodes as nanoseconds: every source would time
		// out, which denies everything silently.
		{"deadline under 1ms", func(c *Config) { c.Deadline = 300 }, []string{"deadline", "1ms", "300ms"}},
		{"negative deadline", func(c *Config) { c.Deadline = -time.Second }, []string{"deadline", "1ms"}},
		{"duplicate issuer", func(c *Config) {
			c.Evidence.Issuers = append(c.Evidence.Issuers, IssuerConfig{
				Issuer: testIssuer, COSEKeysURL: "https://elsewhere.example/.well-known/cose-keys", Audience: "https://platform.arkavo.net",
			})
		}, []string{"evidence.issuers[1]", "duplicate", testIssuer}},
		{"two sources share a properties_key", func(c *Config) {
			c.Sources[0].PropertiesKey = "shared"
			c.Sources[1].PropertiesKey = "shared"
		}, []string{"properties_key", `"shared"`, "patreon", "identity-core"}},
		{"patreon-token missing campaign-tier", func(c *Config) { c.Sources[0].Grants = []string{campaignDef} }, []string{"patreon", campaignDef, tierDef}},
		{"patreon-token with an extra definition", func(c *Config) {
			c.Sources[0].Grants = []string{campaignDef, tierDef, "https://patreon.arkavo.com/attr/extra"}
		}, []string{"patreon", campaignDef, tierDef}},
		{"patreon-token grants outside its entitlements_namespace", func(c *Config) {
			c.Sources[0].Options["entitlements_namespace"] = "creators.example"
		}, []string{"patreon", "https://creators.example/attr/campaign", "https://creators.example/attr/campaign-tier"}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			cfg := validConfig()
			// validConfig shares nothing with another call, but its Options
			// maps are mutated in place by some cases.
			tc.mutate(&cfg)
			err := cfg.Validate()
			require.Error(t, err)
			for _, w := range tc.want {
				assert.Contains(t, err.Error(), w)
			}
		})
	}

	t.Run("patreon-token grants match its namespace, case aside", func(t *testing.T) {
		cfg := validConfig()
		cfg.Sources[0].Grants = []string{"https://Patreon.arkavo.com/attr/campaign-tier", "https://patreon.arkavo.com/attr/Campaign"}
		require.NoError(t, cfg.Validate())

		cfg.Sources[0].Options["entitlements_namespace"] = "Creators.example"
		cfg.Sources[0].Grants = []string{"https://creators.example/attr/campaign", "https://creators.example/attr/campaign-tier"}
		require.NoError(t, cfg.Validate())
	})
	t.Run("a deadline of exactly 1ms is valid", func(t *testing.T) {
		cfg := validConfig()
		cfg.Deadline = time.Millisecond
		assert.NoError(t, cfg.Validate())
	})
	t.Run("a complete agent_status block is valid", func(t *testing.T) {
		cfg := validConfig()
		cfg.Constraints.AgentStatus = agentstatus.Config{URL: "https://identity.example.com", ClientID: "c", ClientSecret: "s", Timeout: 2 * time.Second}
		assert.NoError(t, cfg.Validate())
	})
	t.Run("seal key errors never echo the key", func(t *testing.T) {
		cfg := validConfig()
		cfg.Evidence.SealKey = "c2VjcmV0LXNlY3JldC1zZWNyZXQ=" // decodes to 19 bytes
		err := cfg.Validate()
		require.Error(t, err)
		assert.NotContains(t, err.Error(), cfg.Evidence.SealKey)
	})
}

// Devices narrow grants by the policy file's device_rules and never grant,
// so a config still setting device_class_caps, or a device-class source,
// fails startup, pointing to device_rules.
func TestValidate_RefusesRemovedDeviceSettings(t *testing.T) {
	for name, tc := range map[string]struct {
		mutate func(*Config)
		want   []string
	}{
		"constraints.device_class_caps": {
			func(c *Config) {
				c.Constraints.DeviceClassCaps = map[string][]string{"managed": {creatorCampaign}}
			},
			[]string{"constraints.device_class_caps", "device_rules"},
		},
		"a device-class source": {
			func(c *Config) {
				c.Sources = append(c.Sources, SourceConfig{
					ID: "devices", Type: "device-class", Issuer: testIssuer,
					Grants: []string{"https://arkavo.ai/attr/classification"},
					Options: map[string]any{"classes": map[string]any{
						"managed": []any{"https://arkavo.ai/attr/classification/value/confidential"},
					}},
				})
			},
			[]string{`source "devices"`, `"device-class"`, "device_rules"},
		},
	} {
		t.Run(name, func(t *testing.T) {
			cfg := validConfig()
			tc.mutate(&cfg)

			err := cfg.Validate()

			require.Error(t, err)
			for _, w := range tc.want {
				assert.Contains(t, err.Error(), w)
			}
		})
	}
}

// A source's properties land at the top level of a representation, under
// its properties_key, where the PDP reads a device marker. Only the composite
// may write the marker, so its key is reserved, as is the device token's
// claim.
func TestValidate_ReservedPropertiesKeys(t *testing.T) {
	for _, key := range []string{chaindevice.PropKey, chaindevice.TokenClaim} {
		t.Run(key, func(t *testing.T) {
			cfg := validConfig()
			cfg.Sources[1].PropertiesKey = key

			err := cfg.Validate()

			require.Error(t, err)
			for _, w := range []string{"identity-core", "properties_key", `"` + key + `"`, "reserved"} {
				assert.Contains(t, err.Error(), w)
			}
		})
	}
}

func TestConfig_LogValueRedactsKeys(t *testing.T) {
	cfg := validConfig()
	out := cfg.Evidence.LogValue().String() + cfg.LogValue().String()
	assert.NotContains(t, out, cfg.Evidence.SealKey)
	assert.NotContains(t, out, cfg.Evidence.PreviousSealKeys[0])
	assert.Contains(t, out, testIssuer)
}

// Printing the config with fmt, in any verb, as a value, a pointer or a field
// of a larger struct, redacts the seal keys as LogValue does.
func TestConfig_FormatRedactsKeys(t *testing.T) {
	cfg := validConfig()
	type wrapper struct{ Entity Config }
	values := map[string]any{
		"Config":         cfg,
		"*Config":        &cfg,
		"EvidenceConfig": cfg.Evidence,
		"*Evidence":      &cfg.Evidence,
		"field":          wrapper{cfg},
	}
	for name, v := range values {
		for _, verb := range []string{"%v", "%+v", "%#v", "%s", "%d", "%q", "%x"} {
			t.Run(name+" "+verb, func(t *testing.T) {
				out := fmt.Sprintf(verb, v)
				assert.NotContains(t, out, cfg.Evidence.SealKey)
				assert.NotContains(t, out, cfg.Evidence.PreviousSealKeys[0])
			})
		}
	}
	assert.Contains(t, fmt.Sprintf("%v", cfg), testIssuer, "the rest of the summary still prints")
	assert.Contains(t, fmt.Sprint(cfg), redacted)
}

func loadServiceConfig(t *testing.T, body string) config.ServiceConfig {
	t.Helper()
	path := filepath.Join(t.TempDir(), "opentdf.yaml")
	require.NoError(t, os.WriteFile(path, []byte("services:\n  entityresolution:\n"+body), 0o600))
	legacy, err := config.NewLegacyLoader("test", path)
	require.NoError(t, err)
	defaults, err := config.NewDefaultSettingsLoader()
	require.NoError(t, err)
	cfg, err := config.Load(t.Context(), legacy, defaults)
	require.NoError(t, err)
	return cfg.Services["entityresolution"]
}

func TestDecodeConfig_AbsentIsNotPresent(t *testing.T) {
	for name, in := range map[string]config.ServiceConfig{
		"nil":            nil,
		"a mode block":   {"mode": "keycloak", "url": "http://localhost:8888/auth"},
		"other settings": {"deadline": "250ms"},
	} {
		t.Run(name, func(t *testing.T) {
			_, present, err := DecodeConfig(in)
			require.NoError(t, err)
			assert.False(t, present)
		})
	}
}

func TestDecodeConfig_DurationString(t *testing.T) {
	cfg, present, err := DecodeConfig(config.ServiceConfig{"deadline": "250ms", "sources": []any{}})
	require.NoError(t, err)
	assert.True(t, present)
	assert.Equal(t, 250*time.Millisecond, cfg.Deadline)
}

// A bare integer in the YAML decodes to nanoseconds; Validate refuses it
// rather than letting every source time out.
func TestDecodeConfig_BareIntegerDeadlineFailsValidation(t *testing.T) {
	cfg, present, err := DecodeConfig(loadServiceConfig(t, "    deadline: 300\n    sources: []\n"))
	require.NoError(t, err)
	require.True(t, present)
	assert.Equal(t, 300*time.Nanosecond, cfg.Deadline)

	err = cfg.Validate()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "deadline")
}

func TestDecodeConfig_DefaultDeadline(t *testing.T) {
	cfg, present, err := DecodeConfig(config.ServiceConfig{"sources": []any{}})
	require.NoError(t, err)
	assert.True(t, present)
	assert.Equal(t, 300*time.Millisecond, cfg.Deadline)
}

func TestDecodeConfig_SpecShape(t *testing.T) {
	in := loadServiceConfig(t, `    deadline: 250ms
    evidence:
      issuers:
        - issuer: https://identity.arkavo.net
          cose_keys_url: https://identity.arkavo.net/.well-known/cose-keys
          audience: https://platform.arkavo.net
      verify_entity_tokens: true
      seal_key: `+testSealKey+`
      claims_chain_peps: [pep-1]
    sources:
      - id: patreon
        type: patreon-token
        issuer: https://identity.arkavo.net
        grants: [https://patreon.arkavo.com/attr/campaign, https://patreon.arkavo.com/attr/campaign-tier]
        properties_key: patreon
        infer_unknown_as_free: true
        pep_assertable: true
      - id: identity-core
        type: token-claims
        issuer: https://identity.arkavo.net
        claim: arkavo_entitlements
        subjects: [person, agent]
        actions: [publish]
        grants: [https://patreon.arkavo.com/attr/arkavo-creator]
`)
	cfg, present, err := DecodeConfig(in)
	require.NoError(t, err)
	require.True(t, present)
	require.NoError(t, cfg.Validate())

	assert.Equal(t, 250*time.Millisecond, cfg.Deadline)
	assert.Equal(t, testSealKey, cfg.Evidence.SealKey)
	assert.Equal(t, []string{"pep-1"}, cfg.Evidence.ClaimsChainPEPs)
	require.Len(t, cfg.Sources, 2)
	assert.True(t, cfg.Sources[0].PEPAssertable)
	assert.Equal(t, "patreon", cfg.Sources[0].PropertiesKey)
	assert.Equal(t, true, cfg.Sources[0].Options["infer_unknown_as_free"], "type-specific keys land in Options")
	assert.Equal(t, "arkavo_entitlements", cfg.Sources[1].Options["claim"])
	assert.Equal(t, []source.Kind{source.KindPerson, source.KindAgent}, cfg.Sources[1].Subjects)
	assert.Equal(t, []string{"publish"}, cfg.Sources[1].Actions)
}

// TestDecodeConfig_AgentStatusTimeout ports the decode cases of arkavo's
// agent_status config test to constraints.agent_status.
func TestDecodeConfig_AgentStatusTimeout(t *testing.T) {
	const head = "    sources: []\n    constraints:\n      agent_status:\n"
	decode := func(t *testing.T, body string) Config {
		t.Helper()
		cfg, present, err := DecodeConfig(loadServiceConfig(t, head+body))
		require.NoError(t, err)
		require.True(t, present)
		return cfg
	}

	t.Run("a full block decodes; timeout parses as a duration", func(t *testing.T) {
		cfg := decode(t, "        url: https://identity.example.com\n        client_id: opentdf\n        client_secret: s\n        timeout: 2s\n")
		st := cfg.Constraints.AgentStatus
		assert.True(t, st.Enabled())
		assert.Equal(t, 2*time.Second, st.Timeout)
		assert.Equal(t, "opentdf", st.ClientID)
		assert.Equal(t, agentstatus.Secret("s"), st.ClientSecret)
	})
	t.Run("the secret can come from the environment when its key is in the file", func(t *testing.T) {
		t.Setenv("TEST_SERVICES_ENTITYRESOLUTION_CONSTRAINTS_AGENT_STATUS_CLIENT_SECRET", "from-env")
		cfg := decode(t, "        url: https://identity.example.com\n        client_id: opentdf\n        client_secret: \"\"\n")
		assert.Equal(t, agentstatus.Secret("from-env"), cfg.Constraints.AgentStatus.ClientSecret)
	})
	t.Run("the environment alone cannot supply a key missing from the file", func(t *testing.T) {
		t.Setenv("TEST_SERVICES_ENTITYRESOLUTION_CONSTRAINTS_AGENT_STATUS_CLIENT_SECRET", "from-env")
		cfg := decode(t, "        url: https://identity.example.com\n        client_id: opentdf\n")
		assert.Empty(t, cfg.Constraints.AgentStatus.ClientSecret)
		assert.Error(t, cfg.Validate(), "url and client_id without a secret is a half-filled block")
	})
	t.Run("no block is unconfigured", func(t *testing.T) {
		cfg, _, err := DecodeConfig(loadServiceConfig(t, "    sources: []\n"))
		require.NoError(t, err)
		assert.False(t, cfg.Constraints.AgentStatus.Enabled())
	})
	t.Run("a timeout over the 5 s lease fails validation", func(t *testing.T) {
		cfg := decode(t, "        url: https://identity.example.com\n        client_id: opentdf\n        client_secret: s\n        timeout: 6s\n")
		assert.Error(t, cfg.Validate())
	})
}

func TestDecodeConfig_PublishingStatus(t *testing.T) {
	const body = "    sources: []\n    constraints:\n      publishing_status:\n" +
		"        url: https://platform.example.com\n" +
		"        dial_address: 127.0.0.1:443\n" +
		"        identity_url: https://identity.example.com\n" +
		"        client_id: opentdf\n" +
		"        client_secret: s\n" +
		"        timeout: 2s\n" +
		"        cache_ttl: 3s\n"
	cfg, present, err := DecodeConfig(loadServiceConfig(t, body))
	require.NoError(t, err)
	require.True(t, present)
	ps := cfg.Constraints.PublishingStatus
	assert.True(t, ps.Enabled())
	assert.Equal(t, "https://platform.example.com", ps.URL)
	assert.Equal(t, "127.0.0.1:443", ps.DialAddress)
	assert.Equal(t, "https://identity.example.com", ps.IdentityURL)
	assert.Equal(t, "opentdf", ps.ClientID)
	assert.Equal(t, 2*time.Second, ps.Timeout)
	assert.Equal(t, 3*time.Second, ps.CacheTTL)
	assert.Contains(t, cfg.LogValue().String(), "https://platform.example.com")
	assert.NotContains(t, cfg.LogValue().String(), "client_secret")

	none, _, err := DecodeConfig(loadServiceConfig(t, "    sources: []\n"))
	require.NoError(t, err)
	assert.False(t, none.Constraints.PublishingStatus.Enabled())
}
