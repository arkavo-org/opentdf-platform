package arkavo

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/opentdf/platform/service/internal/agentstatus"
	"github.com/opentdf/platform/service/pkg/config"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// writeConfig writes a platform config whose arkavo ERS block is body
// (indented under services.entityresolution).
func writeConfig(t *testing.T, body string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "opentdf.yaml")
	content := "services:\n  entityresolution:\n    mode: arkavo\n    trust_materialized_claims: true\n    trusted_issuer: " + issuer + "\n" + body
	require.NoError(t, os.WriteFile(path, []byte(content), 0o600))
	return path
}

// registerFrom loads path with the server's default loaders (legacy, then
// default settings) and registers the resolver from the result.
func registerFrom(t *testing.T, path string) *EntityResolutionService {
	t.Helper()
	legacy, err := config.NewLegacyLoader("test", path)
	require.NoError(t, err)
	defaults, err := config.NewDefaultSettingsLoader()
	require.NoError(t, err)
	cfg, err := config.Load(t.Context(), legacy, defaults)
	require.NoError(t, err)
	svc, _ := RegisterArkavoERS(cfg.Services["entityresolution"], testLogger(t))
	return svc
}

func TestRegisterArkavoERS_AgentStatusConfig(t *testing.T) {
	t.Run("a full block builds a status client; timeout parses as a duration", func(t *testing.T) {
		svc := registerFrom(t, writeConfig(t, "    agent_status:\n      url: https://identity.example.com\n      client_id: opentdf\n      client_secret: s\n      timeout: 2s\n"))
		require.NotNil(t, svc.agentStatus)
		assert.Equal(t, 2*time.Second, svc.cfg.AgentStatus.Timeout)
	})
	t.Run("the secret can come from the environment when its key is in the file", func(t *testing.T) {
		t.Setenv("TEST_SERVICES_ENTITYRESOLUTION_AGENT_STATUS_CLIENT_SECRET", "from-env")
		svc := registerFrom(t, writeConfig(t, "    agent_status:\n      url: https://identity.example.com\n      client_id: opentdf\n      client_secret: \"\"\n"))
		require.NotNil(t, svc.agentStatus)
		assert.Equal(t, agentstatus.Secret("from-env"), svc.cfg.AgentStatus.ClientSecret)
	})
	t.Run("the environment alone cannot supply a key missing from the file", func(t *testing.T) {
		t.Setenv("TEST_SERVICES_ENTITYRESOLUTION_AGENT_STATUS_CLIENT_SECRET", "from-env")
		path := writeConfig(t, "    agent_status:\n      url: https://identity.example.com\n      client_id: opentdf\n")
		assert.Panics(t, func() { registerFrom(t, path) }, "url and client_id without a secret is a half-filled block")
	})
	t.Run("no block: unconfigured, and the checker interface is truly nil", func(t *testing.T) {
		svc := registerFrom(t, writeConfig(t, ""))
		assert.Nil(t, svc.agentStatus)
	})
	t.Run("a timeout over the 5 s lease fails startup", func(t *testing.T) {
		path := writeConfig(t, "    agent_status:\n      url: https://identity.example.com\n      client_id: opentdf\n      client_secret: s\n      timeout: 6s\n")
		assert.Panics(t, func() { registerFrom(t, path) })
	})
}
