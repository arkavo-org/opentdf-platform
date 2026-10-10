package jev

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func newTestClient(t *testing.T, handler http.HandlerFunc, mutate func(*Config)) Client {
	t.Helper()

	srv := httptest.NewServer(handler)
	t.Cleanup(srv.Close)

	t.Setenv(DefaultAPIKeyEnv, "test-key")
	cfg := &Config{
		Enabled:        true,
		BaseURL:        srv.URL,
		StateAllowlist: []string{"ticket"},
	}
	if mutate != nil {
		mutate(cfg)
	}

	client, err := New(cfg, srv.Client())
	require.NoError(t, err)
	return client
}

const noulResponse = `{
  "id":"gen-dec-test",
  "model":"typesafe/jev-1.13-20260917",
  "answers":{"q":{"type":"noul","noul":0.9}},
  "usage":{"cost":0.000001,"input_tokens":4,"output_tokens":1}
}`

func TestDecidePostsToDecisionsPathWithAuth(t *testing.T) {
	var gotPath, gotAuth string
	var gotBody request
	var decodeErr error

	client := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		gotAuth = r.Header.Get("Authorization")
		decodeErr = json.NewDecoder(r.Body).Decode(&gotBody)
		_, _ = w.Write([]byte(apiExampleResponse))
	}, nil)

	resp, err := client.Decide(context.Background(),
		map[string]any{"ticket": "blank screen after pay"},
		map[string]Question{
			"is_bug": NewNoulQuestion("Is this a defect?", "broken behavior", "a question"),
		})
	require.NoError(t, err)
	require.NoError(t, decodeErr)

	assert.Equal(t, decisionsPath, gotPath)
	assert.Equal(t, "Bearer test-key", gotAuth)
	assert.Equal(t, DefaultModel, gotBody.Model, "model must be pinned, not floating")
	assert.Equal(t, QuestionTypeNoul, gotBody.Questions["is_bug"].Type)
	assert.Equal(t, "payments", resp.Answers["team"].Choice)
}

func TestDecideRequiresQuestions(t *testing.T) {
	client := newTestClient(t, func(http.ResponseWriter, *http.Request) {
		t.Fatal("must not call the API with no questions")
	}, nil)

	_, err := client.Decide(context.Background(), map[string]any{}, nil)
	assert.ErrorIs(t, err, ErrNoQuestions)
}

func TestDecideSurfacesNonOKStatus(t *testing.T) {
	client := newTestClient(t, func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusTooManyRequests)
		_, _ = w.Write([]byte(`{"error":{"code":429,"message":"Rate limit exceeded"}}`))
	}, nil)

	_, err := client.Decide(context.Background(), map[string]any{},
		map[string]Question{"q": NewNoulQuestion("x", "t", "f")})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "429")
	assert.Contains(t, err.Error(), "Rate limit exceeded")
}

func TestDecideRespectsContextCancellation(t *testing.T) {
	client := newTestClient(t, func(w http.ResponseWriter, _ *http.Request) {
		time.Sleep(200 * time.Millisecond)
		_, _ = w.Write([]byte(apiExampleResponse))
	}, nil)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Millisecond)
	defer cancel()

	_, err := client.Decide(ctx, map[string]any{},
		map[string]Question{"q": NewNoulQuestion("x", "t", "f")})
	assert.Error(t, err, "a slow model must not outlive the caller's deadline")
}

func TestCacheDisabledByDefault(t *testing.T) {
	calls := 0
	client := newTestClient(t, func(w http.ResponseWriter, _ *http.Request) {
		calls++
		_, _ = w.Write([]byte(noulResponse))
	}, nil)

	qs := map[string]Question{"q": NewNoulQuestion("x", "t", "f")}
	for range 2 {
		_, err := client.Decide(context.Background(), map[string]any{"ticket": "a"}, qs)
		require.NoError(t, err)
	}
	assert.Equal(t, 2, calls, "caching must be opt-in")
}

func TestCacheServesRepeatedIdenticalRequests(t *testing.T) {
	calls := 0
	client := newTestClient(t, func(w http.ResponseWriter, _ *http.Request) {
		calls++
		_, _ = w.Write([]byte(noulResponse))
	}, func(c *Config) { c.CacheTTL = "1m" })

	qs := map[string]Question{"q": NewNoulQuestion("x", "t", "f")}
	for range 3 {
		_, err := client.Decide(context.Background(), map[string]any{"ticket": "a"}, qs)
		require.NoError(t, err)
	}
	assert.Equal(t, 1, calls)

	// Different state must miss the cache.
	_, err := client.Decide(context.Background(), map[string]any{"ticket": "b"}, qs)
	require.NoError(t, err)
	assert.Equal(t, 2, calls)
}

func TestNewReturnsNoopWhenDisabled(t *testing.T) {
	client, err := New(&Config{Enabled: false}, nil)
	require.NoError(t, err)

	_, err = client.Decide(context.Background(), nil, nil)
	assert.ErrorIs(t, err, ErrDisabled)
}

func TestNewRequiresAPIKeyWhenEnabled(t *testing.T) {
	t.Setenv(DefaultAPIKeyEnv, "")
	_, err := New(&Config{Enabled: true, StateAllowlist: []string{"x"}}, nil)
	assert.ErrorIs(t, err, ErrNoAPIKey)
}
