package composite

import (
	"testing"
	"time"

	"github.com/opentdf/platform/service/internal/identityentities"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// identityConfig is validConfig with the patreon source served from identity.
func identityConfig() Config {
	cfg := validConfig()
	cfg.Sources[0].Type = typePatreonIdentity
	cfg.Sources[0].Deadline = 3500 * time.Millisecond
	cfg.IdentityEntities = identityentities.Config{
		URL: "https://identity.arkavo.net", ClientID: "opentdf-platform", ClientSecret: "s3cret",
	}
	return cfg
}

func TestValidate_PatreonIdentity(t *testing.T) {
	require.NoError(t, identityConfig().Validate())
	for _, serve := range []string{serveToken, serveIdentity} {
		cfg := identityConfig()
		cfg.Sources[0].Options["serve"] = serve
		require.NoError(t, cfg.Validate(), serve)
	}

	tests := []struct {
		name   string
		mutate func(*Config)
		want   []string
	}{
		{"no identity_entities", func(c *Config) { c.IdentityEntities = identityentities.Config{} }, []string{"patreon", "identity_entities"}},
		{"identity_entities half filled", func(c *Config) { c.IdentityEntities.ClientSecret = "" }, []string{"identity_entities.client_secret"}},
		{"unknown serve", func(c *Config) { c.Sources[0].Options["serve"] = "both" }, []string{"serve"}},
		{"unknown option", func(c *Config) { c.Sources[0].Options["srve"] = "identity" }, []string{"srve"}},
		{"missing campaign-tier", func(c *Config) { c.Sources[0].Grants = []string{campaignDef} }, []string{"patreon-identity", campaignDef, tierDef}},
		{"source deadline under 1ms", func(c *Config) { c.Sources[0].Deadline = 3500 }, []string{"deadline", "1ms"}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			cfg := identityConfig()
			tc.mutate(&cfg)
			err := cfg.Validate()
			require.Error(t, err)
			for _, w := range tc.want {
				assert.Contains(t, err.Error(), w)
			}
			assert.NotContains(t, err.Error(), "s3cret")
		})
	}
}

// The client secret comes from the environment, which reaches the
// identity_entities block but could not reach a list item, and a source's
// deadline decodes from a duration string.
func TestDecodeConfig_PatreonIdentity(t *testing.T) {
	t.Setenv("TEST_SERVICES_ENTITYRESOLUTION_IDENTITY_ENTITIES_CLIENT_SECRET", "from-env")
	in := loadServiceConfig(t, `    identity_entities:
      url: https://identity.arkavo.net
      client_id: opentdf-platform
      client_secret: ""
      cache_ttl: 30s
    sources:
      - id: patreon
        type: patreon-identity
        issuer: https://identity.arkavo.net
        grants:
          - https://patreon.arkavo.com/attr/campaign
          - https://patreon.arkavo.com/attr/campaign-tier
        deadline: 3500ms
        serve: identity
`)
	cfg, present, err := DecodeConfig(in)
	require.NoError(t, err)
	require.True(t, present)
	assert.Equal(t, "from-env", string(cfg.IdentityEntities.ClientSecret))
	assert.Equal(t, 30*time.Second, cfg.IdentityEntities.CacheTTL)
	require.Len(t, cfg.Sources, 1)
	assert.Equal(t, 3500*time.Millisecond, cfg.Sources[0].Deadline)
	assert.Equal(t, "identity", cfg.Sources[0].Options["serve"])
	assert.NotContains(t, cfg.String(), "from-env")
}
