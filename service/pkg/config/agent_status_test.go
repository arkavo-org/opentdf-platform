package config

import (
	"os"
	"testing"

	"github.com/opentdf/platform/service/internal/agentstatus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestGetDefaultKVs_AgentStatusClientSecretEmpty pins the fix for the bug
// where Secret.MarshalJSON always rendered "[REDACTED]": that string, once
// seeded as this key's default, stood in for a missing client_secret and
// let an unconfigured agent_status block pass validate(). An unset secret
// must default to "".
func TestGetDefaultKVs_AgentStatusClientSecretEmpty(t *testing.T) {
	kvs, err := getDefaultKVs()
	require.NoError(t, err)

	v, ok := kvs["server.auth.agent_status.client_secret"]
	require.True(t, ok, "server.auth.agent_status.client_secret should be a known default key")
	assert.Empty(t, v)
}

func writeAgentStatusConfig(t *testing.T, secretLine string) string {
	t.Helper()
	tempFile, err := os.CreateTemp(t.TempDir(), "config-*.yaml")
	require.NoError(t, err)
	t.Cleanup(func() { os.Remove(tempFile.Name()) })

	content := "server:\n" +
		"  auth:\n" +
		"    agent_status:\n" +
		"      url: https://identity.test\n" +
		"      client_id: opentdf\n" +
		secretLine
	_, err = tempFile.WriteString(content)
	require.NoError(t, err)
	require.NoError(t, tempFile.Close())
	return tempFile.Name()
}

// TestLoadConfig_AgentStatusMissingSecretRefused pins the other half of the
// same bug: a config file with url and client_id but no client_secret must
// resolve to an empty secret, and agentstatus.New must refuse it rather than
// silently accepting a "[REDACTED]" placeholder as a real secret.
func TestLoadConfig_AgentStatusMissingSecretRefused(t *testing.T) {
	file := writeAgentStatusConfig(t, "")

	cfg, err := LoadConfig(t.Context(), configKey, file)
	require.NoError(t, err)

	agentStatusCfg := cfg.Server.Auth.AgentStatus
	assert.Equal(t, "https://identity.test", agentStatusCfg.URL)
	assert.Empty(t, string(agentStatusCfg.ClientSecret))

	_, err = agentstatus.New(agentStatusCfg)
	require.ErrorContains(t, err, "client_secret")
}

// TestLoadConfig_AgentStatusWithSecretLoads confirms a configured secret
// loads through intact (not silently redacted or dropped) and produces a
// usable checker.
func TestLoadConfig_AgentStatusWithSecretLoads(t *testing.T) {
	file := writeAgentStatusConfig(t, "      client_secret: real\n")

	cfg, err := LoadConfig(t.Context(), configKey, file)
	require.NoError(t, err)

	agentStatusCfg := cfg.Server.Auth.AgentStatus
	assert.Equal(t, "real", string(agentStatusCfg.ClientSecret))

	_, err = agentstatus.New(agentStatusCfg)
	require.NoError(t, err)
}
