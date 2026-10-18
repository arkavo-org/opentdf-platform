package composite

import (
	"path/filepath"
	"strings"
	"testing"

	"github.com/opentdf/platform/service/internal/agentstatus"
	"github.com/opentdf/platform/service/pkg/config"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// registerBody is a minimal composite service block. The COSE key URL is
// unreachable: NewCWTVerifier only warns when the first fetch fails.
var registerBody = `    evidence:
      issuers:
        - issuer: https://identity.arkavo.net
          cose_keys_url: http://127.0.0.1:1/.well-known/cose-keys
          audience: https://platform.arkavo.net
      seal_key: ` + testSealKey + `
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
        grants: [https://patreon.arkavo.com/attr/arkavo-creator]
      - id: device-class
        type: device-class
        issuer: https://identity.arkavo.net
        grants: [https://arkavo.ai/attr/classification]
        classes:
          managed: [https://arkavo.ai/attr/classification/value/confidential]
`

func TestRegister_BuildsComposite(t *testing.T) {
	svc, err := Register(loadServiceConfig(t, registerBody), testLogger(t))
	require.NoError(t, err)
	require.NotNil(t, svc)

	require.Len(t, svc.sources, 3)
	ids := make([]string, 0, len(svc.sources))
	for _, s := range svc.sources {
		ids = append(ids, s.id)
		assert.NotNil(t, s.src, s.id)
	}
	assert.Equal(t, []string{"patreon", "identity-core", "device-class"}, ids)
	assert.Equal(t, "patreon", svc.sources[0].propsKey)
	assert.True(t, svc.sources[0].cap.pepAssertable)

	require.Len(t, svc.verifiers, 1)
	assert.NotNil(t, svc.verifiers["https://identity.arkavo.net"])
	assert.True(t, svc.peps["pep-1"])
	assert.Len(t, svc.sealKeys, 1)

	// An unset agent_status is a nil interface, never a typed nil *Client,
	// so the resolver's nil check withholds every agent.
	assert.True(t, svc.agentStatus == nil, "no agent_status means a nil checker") //nolint:testifylint // assert.Nil also accepts a typed nil
}

func TestRegister_AgentStatus(t *testing.T) {
	body := registerBody + `    constraints:
      agent_status:
        url: https://identity.example.com
        client_id: c
        client_secret: s
`
	svc, err := Register(loadServiceConfig(t, body), testLogger(t))
	require.NoError(t, err)
	require.NotNil(t, svc.agentStatus)
	_, ok := svc.agentStatus.(*agentstatus.Client)
	assert.True(t, ok)
}

func TestRegister_RejectsInvalidConfig(t *testing.T) {
	tests := map[string]struct {
		in   config.ServiceConfig
		want string
	}{
		"no seal key": {
			in:   loadServiceConfig(t, replaceOnce(t, registerBody, "seal_key: "+testSealKey, "seal_key: \"\"")),
			want: "seal_key",
		},
		"two sources share a definition": {
			in: loadServiceConfig(t, replaceOnce(t, registerBody,
				"grants: [https://patreon.arkavo.com/attr/arkavo-creator]",
				"grants: [https://patreon.arkavo.com/attr/campaign]")),
			want: "one source owns a definition",
		},
		"unknown source type": {
			in:   loadServiceConfig(t, replaceOnce(t, registerBody, "type: device-class", "type: live-http")),
			want: "live-http",
		},
		"unknown patreon option": {
			in:   loadServiceConfig(t, replaceOnce(t, registerBody, "infer_unknown_as_free: true", "claims: [arkavo_patreon]")),
			want: "claims",
		},
		"undecodable config": {
			in:   config.ServiceConfig{"sources": "not a list"},
			want: "sources",
		},
	}
	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			svc, err := Register(tc.in, testLogger(t))
			require.Error(t, err)
			assert.Nil(t, svc)
			assert.Contains(t, err.Error(), tc.want)
		})
	}
}

// TestExampleConfigsValidate decodes the services.entityresolution block of
// each shipped example config. The seal key is a secret the deployment
// supplies, so the tests set one.
func TestExampleConfigsValidate(t *testing.T) {
	for _, name := range []string{
		"opentdf-patreon-prod.yaml",
		"opentdf-patreon-local-test.yaml",
		"opentdf-arkavo-local-test.yaml",
	} {
		t.Run(name, func(t *testing.T) {
			path := filepath.Join("..", "..", "..", "..", "examples", "config", name)
			legacy, err := config.NewLegacyLoader("test", path)
			require.NoError(t, err)
			defaults, err := config.NewDefaultSettingsLoader()
			require.NoError(t, err)
			loaded, err := config.Load(t.Context(), legacy, defaults)
			require.NoError(t, err)

			cfg, present, err := DecodeConfig(loaded.Services["entityresolution"])
			require.NoError(t, err)
			require.True(t, present, "sources selects the composite")
			assert.Empty(t, cfg.Evidence.SealKey, "the deployment supplies the seal key")
			cfg.Evidence.SealKey = testSealKey
			require.NoError(t, cfg.Validate())
		})
	}
}

func replaceOnce(t *testing.T, s, old, repl string) string {
	t.Helper()
	require.Equal(t, 1, strings.Count(s, old), "%q must occur once", old)
	return strings.Replace(s, old, repl, 1)
}
