package agentstatus

import (
	"bytes"
	"encoding/json"
	"fmt"
	"log/slog"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestConfigValidate(t *testing.T) {
	ok := Config{URL: "https://identity.arkavo.net", ClientID: "opentdf", ClientSecret: "s"}
	require.NoError(t, ok.validate())
	require.NoError(t, Config{URL: "http://127.0.0.1:8081", ClientID: "c", ClientSecret: "s"}.validate())

	for name, cfg := range map[string]Config{
		"plain http off loopback": {URL: "http://identity.arkavo.net", ClientID: "c", ClientSecret: "s"},
		"non-http scheme":         {URL: "ftp://identity.arkavo.net", ClientID: "c", ClientSecret: "s"},
		"no host":                 {URL: "https://", ClientID: "c", ClientSecret: "s"},
		"no client id":            {URL: "https://identity.arkavo.net", ClientSecret: "s"},
		"no client secret":        {URL: "https://identity.arkavo.net", ClientID: "c"},
	} {
		t.Run(name, func(t *testing.T) { require.Error(t, cfg.validate()) })
	}
	assert.False(t, Config{}.Enabled())
	assert.True(t, ok.Enabled())
}

func TestSecretNeverRendered(t *testing.T) {
	cfg := Config{URL: "https://identity.arkavo.net", ClientID: "opentdf", ClientSecret: "s3cret-value"}
	raw, err := json.Marshal(cfg)
	require.NoError(t, err)
	var buf bytes.Buffer
	slog.New(slog.NewTextHandler(&buf, nil)).Info("cfg", slog.Any("agent_status", cfg))
	slog.New(slog.NewJSONHandler(&buf, nil)).Info("cfg", slog.Any("agent_status", cfg))

	for _, rendered := range []string{string(raw), buf.String(), fmt.Sprintf("%+v", cfg)} {
		assert.NotContains(t, rendered, "s3cret-value")
	}
}

func TestSecretMarshalJSON(t *testing.T) {
	empty, err := json.Marshal(Secret(""))
	require.NoError(t, err)
	assert.JSONEq(t, `""`, string(empty))

	set, err := json.Marshal(Secret("s3cret-value"))
	require.NoError(t, err)
	assert.JSONEq(t, `"[REDACTED]"`, string(set))
}

// pkg/config seeds its viper defaults from json.Marshal of a zero config
// (getDefaultKVs). If an unset secret rendered as "[REDACTED]", that string
// would become the default client_secret, and a config that omits the secret
// would pass validate() and fail every agent at the token endpoint instead of
// at startup.
func TestMissingSecretSurvivesDefaultsRoundTrip(t *testing.T) {
	defaults, err := json.Marshal(Config{})
	require.NoError(t, err)
	var kv map[string]any
	require.NoError(t, json.Unmarshal(defaults, &kv))
	assert.Empty(t, kv["client_secret"])

	var loaded Config
	require.NoError(t, json.Unmarshal(defaults, &loaded))
	loaded.URL = "https://identity.arkavo.net"
	loaded.ClientID = "opentdf"
	require.ErrorContains(t, loaded.validate(), "client_secret")
}
