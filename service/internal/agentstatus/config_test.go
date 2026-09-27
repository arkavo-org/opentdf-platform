package agentstatus

import (
	"bytes"
	"encoding/json"
	"fmt"
	"log/slog"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestConfigValidate(t *testing.T) {
	ok := Config{URL: "https://identity.arkavo.net", ClientID: "opentdf", ClientSecret: "s"}
	require.NoError(t, ok.validate())
	require.NoError(t, Config{URL: "http://127.0.0.1:8081", ClientID: "c", ClientSecret: "s"}.validate())
	require.NoError(t, Config{URL: "https://identity.arkavo.net", ClientID: "c", ClientSecret: "s", Timeout: maxStatusTTL}.validate(),
		"a timeout equal to the status lease is allowed")

	for name, cfg := range map[string]Config{
		"plain http off loopback":         {URL: "http://identity.arkavo.net", ClientID: "c", ClientSecret: "s"},
		"plain http to a non-loopback IP": {URL: "http://10.0.0.1", ClientID: "c", ClientSecret: "s"},
		"userinfo with password":          {URL: "https://user:pw@identity.arkavo.net", ClientID: "c", ClientSecret: "s"},
		"userinfo without password":       {URL: "https://user@identity.arkavo.net", ClientID: "c", ClientSecret: "s"},
		"non-http scheme":                 {URL: "ftp://identity.arkavo.net", ClientID: "c", ClientSecret: "s"},
		"no host":                         {URL: "https://", ClientID: "c", ClientSecret: "s"},
		"no client id":                    {URL: "https://identity.arkavo.net", ClientSecret: "s"},
		"no client secret":                {URL: "https://identity.arkavo.net", ClientID: "c"},
		// A live answer could otherwise be older than the 5 s lease a
		// quarantine is promised to land within.
		"timeout longer than the status lease": {URL: "https://identity.arkavo.net", ClientID: "c", ClientSecret: "s", Timeout: maxStatusTTL + time.Millisecond},
	} {
		t.Run(name, func(t *testing.T) { require.Error(t, cfg.validate()) })
	}
	assert.False(t, Config{}.Enabled())
	assert.True(t, ok.Enabled())
}

// A URL that carries credentials must not have them echoed into the startup
// error, whether it parses or not.
func TestValidateDoesNotEchoURLCredentials(t *testing.T) {
	for name, raw := range map[string]string{
		"parses":          "https://user:s3cret-value@identity.arkavo.net",
		"fails url.Parse": "https://user:s3cret-value@identity.arkavo.net:99999x",
	} {
		t.Run(name, func(t *testing.T) {
			err := Config{URL: raw, ClientID: "c", ClientSecret: "s"}.validate()
			require.Error(t, err)
			assert.NotContains(t, err.Error(), "s3cret-value")
		})
	}
}

func TestSecretNeverRendered(t *testing.T) {
	cfg := Config{URL: "https://identity.arkavo.net", ClientID: "opentdf", ClientSecret: "s3cret-value"}
	raw, err := json.Marshal(cfg)
	require.NoError(t, err)
	var buf bytes.Buffer
	for _, h := range []slog.Handler{slog.NewTextHandler(&buf, nil), slog.NewJSONHandler(&buf, nil)} {
		slog.New(h).Info("cfg",
			slog.Any("agent_status", cfg),
			slog.Any("s", cfg.ClientSecret),
		)
	}
	rendered := []string{string(raw), buf.String()}

	type named struct {
		Name        string
		AgentStatus Config
	}
	type embedded struct {
		Name string
		Config
	}
	for _, v := range []any{cfg.ClientSecret, cfg, named{"auth", cfg}, embedded{"auth", cfg}, &cfg} {
		for _, verb := range []string{"%v", "%+v", "%#v", "%s", "%d", "%q", "%x"} {
			rendered = append(rendered, fmt.Sprintf(verb, v))
		}
	}
	for _, r := range rendered {
		assert.NotContains(t, r, "s3cret-value")
	}
}

// LogValue is what slog resolves before either handler formats the secret.
func TestSecretLogValue(t *testing.T) {
	v := Secret("s3cret-value").LogValue()
	assert.Equal(t, slog.KindString, v.Kind())
	assert.Equal(t, redacted, v.String())

	var text, js bytes.Buffer
	slog.New(slog.NewTextHandler(&text, nil)).Info("m", slog.Any("s", Secret("s3cret-value")))
	slog.New(slog.NewJSONHandler(&js, nil)).Info("m", slog.Any("s", Secret("s3cret-value")))
	assert.Contains(t, text.String(), "s="+redacted)
	assert.Contains(t, js.String(), `"s":"`+redacted+`"`)
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
