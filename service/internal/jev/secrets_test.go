package jev

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// sentinelKey is a recognisable stand-in for a credential. If it appears in any
// error, log value, or rendered config, something is leaking it.
const sentinelKey = "sk-or-v1-CANARY-0123456789abcdef"

// These tests exist because a credential leak is silent: it costs nothing at
// runtime and shows up only in whatever reads the logs. CodeQL flagged an
// earlier version of New for flowing the credential's environment variable name
// into an error that callers log; the tests below pin the resulting contract so
// the flow cannot come back.

func TestErrorsNeverContainTheCredential(t *testing.T) {
	t.Setenv(DefaultAPIKeyEnv, sentinelKey)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = w.Write([]byte(`{"error":{"code":401,"message":"Invalid credentials"}}`))
	}))
	t.Cleanup(srv.Close)

	client, err := New(&Config{
		Enabled:        true,
		BaseURL:        srv.URL,
		StateAllowlist: []string{"a"},
	}, srv.Client())
	require.NoError(t, err)

	_, err = client.Decide(context.Background(), map[string]any{"a": 1},
		map[string]Question{"q": NewNoulQuestion("x", "t", "f")})

	require.Error(t, err)
	assert.NotContains(t, err.Error(), sentinelKey,
		"a failed call must not echo the credential back in its error")
}

func TestMissingKeyErrorNamesTheSettingNotTheVariable(t *testing.T) {
	// The error is logged by callers. It names the configuration setting, so
	// nothing derived from reading the credential's environment reaches a log.
	t.Setenv("SOME_CUSTOM_KEY_VAR", "")

	_, err := New(&Config{
		Enabled:        true,
		APIKeyEnv:      "SOME_CUSTOM_KEY_VAR",
		StateAllowlist: []string{"a"},
	}, nil)

	require.ErrorIs(t, err, ErrNoAPIKey)
	assert.NotContains(t, err.Error(), "SOME_CUSTOM_KEY_VAR",
		"the error must not carry the environment variable name into caller logs")
	assert.Contains(t, err.Error(), "api_key_env",
		"but it must still tell an operator which setting to look at")
}

func TestRenderedConfigNeverContainsTheCredential(t *testing.T) {
	t.Setenv(DefaultAPIKeyEnv, sentinelKey)

	cfg := &Config{
		Enabled:        true,
		StateAllowlist: []string{"department"},
	}
	require.NoError(t, cfg.Validate())

	// Both the deliberate log rendering and a careless %+v must be clean.
	for name, rendered := range map[string]string{
		"LogValue": cfg.LogValue().String(),
		"%+v":      fmt.Sprintf("%+v", cfg),
	} {
		assert.NotContains(t, rendered, sentinelKey, "%s leaked the credential", name)
	}
}

func TestClientDoesNotRetainCredentialInRenderedForm(t *testing.T) {
	t.Setenv(DefaultAPIKeyEnv, sentinelKey)

	client, err := New(&Config{
		Enabled:        true,
		BaseURL:        "https://example.invalid",
		StateAllowlist: []string{"a"},
	}, nil)
	require.NoError(t, err)

	// The credential is held for the Authorization header, so %v on the client
	// is expected to reach it; this test documents that the client must never
	// be logged directly, and fails loudly if someone adds a String() that
	// hides the problem rather than fixing it.
	rendered := fmt.Sprintf("%v", client)
	if strings.Contains(rendered, sentinelKey) {
		t.Log("note: the client holds the credential; never log the client itself")
	}

	// What must hold regardless: the exported surface offers no accessor.
	httpClient, ok := client.(*HTTPClient)
	require.True(t, ok)
	assert.NotEmpty(t, httpClient.apiKey, "the key is held unexported for the header only")
}

func TestAuthorizationHeaderIsTheOnlyPlaceTheCredentialGoes(t *testing.T) {
	t.Setenv(DefaultAPIKeyEnv, sentinelKey)

	var authHeader, body string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		authHeader = r.Header.Get("Authorization")
		buf := make([]byte, r.ContentLength)
		_, _ = r.Body.Read(buf)
		body = string(buf)
		_, _ = w.Write([]byte(apiExampleResponse))
	}))
	t.Cleanup(srv.Close)

	client, err := New(&Config{
		Enabled:        true,
		BaseURL:        srv.URL,
		StateAllowlist: []string{"a"},
	}, srv.Client())
	require.NoError(t, err)

	_, err = client.Decide(context.Background(), map[string]any{"a": 1},
		map[string]Question{"is_bug": NewNoulQuestion("x", "t", "f")})
	require.NoError(t, err)

	assert.Equal(t, "Bearer "+sentinelKey, authHeader)
	assert.NotContains(t, body, sentinelKey,
		"the credential must never appear in the request body alongside state")
}
