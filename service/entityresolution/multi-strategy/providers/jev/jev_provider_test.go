package jev

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/opentdf/platform/service/entityresolution/multi-strategy/types"
	jevclient "github.com/opentdf/platform/service/internal/jev"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// modelResponse answers the two questions the test catalog poses: a confident
// choice and a noul answer that sits below any sane threshold.
const modelResponse = `{
  "id": "gen-dec-test",
  "model": "typesafe/jev-1.13-20260917",
  "answers": {
    "risk_tier": {"type":"choice","choice":"elevated","confidence":0.93,
                  "probabilities":{"elevated":0.93,"routine":0.07}},
    "is_anomalous": {"type":"noul","noul":0.55}
  },
  "usage": {"cost": 0.000002, "input_tokens": 120, "output_tokens": 20}
}`

func testConfig(t *testing.T, serverURL string, seam jevclient.SeamConfig) Config {
	t.Helper()
	t.Setenv(jevclient.DefaultAPIKeyEnv, "test-key")

	return Config{
		Client: jevclient.Config{
			Enabled:             true,
			BaseURL:             serverURL,
			StateAllowlist:      []string{"department"},
			ConfidenceThreshold: 0.8,
			Seams:               jevclient.SeamsConfig{ERSClaims: seam},
		},
		Questions: map[string]jevclient.Question{
			"risk_tier": jevclient.NewChoiceQuestion("How risky?", map[string]any{
				"elevated": "unusual", "routine": "normal",
			}),
			"is_anomalous": jevclient.NewNoulQuestion("Anomalous?", "yes", "no"),
		},
	}
}

func newProvider(t *testing.T, seam jevclient.SeamConfig, handler http.HandlerFunc) *Provider {
	t.Helper()
	if handler == nil {
		handler = func(w http.ResponseWriter, _ *http.Request) {
			_, _ = w.Write([]byte(modelResponse))
		}
	}
	srv := httptest.NewServer(handler)
	t.Cleanup(srv.Close)

	p, err := NewProvider("risk", testConfig(t, srv.URL, seam))
	require.NoError(t, err)
	return p
}

func TestEnforcingModeDerivesOnlyConfidentAnswers(t *testing.T) {
	p := newProvider(t, jevclient.SeamConfig{Enabled: true, Mode: jevclient.ModeEnforce}, nil)

	result, err := p.ResolveEntity(context.Background(), types.MappingStrategy{Name: "s"},
		map[string]any{"department": "finance"})
	require.NoError(t, err)

	assert.Equal(t, "elevated", result.Data["risk_tier"])
	assert.NotContains(t, result.Data, "is_anomalous",
		"a 0.55 noul answer is barely better than a coin flip and must not become a claim")
	assert.Equal(t, true, result.Metadata["applied"])
	assert.Equal(t, "gen-dec-test", result.Metadata["response_id"])
}

func TestShadowModeConsultsButDerivesNothing(t *testing.T) {
	p := newProvider(t, jevclient.SeamConfig{Enabled: true, Mode: jevclient.ModeShadow}, nil)

	result, err := p.ResolveEntity(context.Background(), types.MappingStrategy{Name: "s"},
		map[string]any{"department": "finance"})
	require.NoError(t, err)

	assert.Empty(t, result.Data, "shadow mode must not produce claims")
	assert.Equal(t, true, result.Metadata["consulted"])
	assert.Equal(t, false, result.Metadata["applied"])
	assert.NotNil(t, result.Metadata["certainties"], "shadow mode exists to be measured")
}

func TestDisabledSeamNeverCallsTheModel(t *testing.T) {
	p := newProvider(t, jevclient.SeamConfig{Enabled: false, Mode: jevclient.ModeEnforce},
		func(http.ResponseWriter, *http.Request) {
			t.Fatal("a disabled seam must not reach the network")
		})

	result, err := p.ResolveEntity(context.Background(), types.MappingStrategy{Name: "s"},
		map[string]any{"department": "finance"})
	require.NoError(t, err)
	assert.Empty(t, result.Data)
	assert.Equal(t, false, result.Metadata["consulted"])
}

func TestStateAllowlistWithholdsUnlistedParameters(t *testing.T) {
	var sent map[string]any
	p := newProvider(t, jevclient.SeamConfig{Enabled: true, Mode: jevclient.ModeEnforce},
		func(w http.ResponseWriter, r *http.Request) {
			var body struct {
				State map[string]any `json:"state"`
			}
			if err := decodeJSON(r, &body); err != nil {
				w.WriteHeader(http.StatusBadRequest)
				return
			}
			sent = body.State
			_, _ = w.Write([]byte(modelResponse))
		})

	_, err := p.ResolveEntity(context.Background(), types.MappingStrategy{Name: "s"},
		map[string]any{"department": "finance", "ssn": "123-45-6789"})
	require.NoError(t, err)

	assert.Equal(t, map[string]any{"department": "finance"}, sent,
		"only allowlisted parameters may leave the platform")
	assert.NotContains(t, sent, "ssn")
}

func TestFailOpenYieldsNoClaims(t *testing.T) {
	p := newProvider(t, jevclient.SeamConfig{Enabled: true, Mode: jevclient.ModeEnforce},
		func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusInternalServerError)
		})

	result, err := p.ResolveEntity(context.Background(), types.MappingStrategy{Name: "s"},
		map[string]any{"department": "finance"})

	require.NoError(t, err, "fail-open must not break entity resolution")
	assert.Empty(t, result.Data, "an unreachable model withholds claims rather than inventing them")
	assert.NotEmpty(t, result.Metadata["error"])
}

func TestFailClosedSurfacesTheError(t *testing.T) {
	t.Setenv(jevclient.DefaultAPIKeyEnv, "test-key")
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	t.Cleanup(srv.Close)

	cfg := testConfig(t, srv.URL, jevclient.SeamConfig{Enabled: true, Mode: jevclient.ModeEnforce})
	cfg.Client.FailMode = jevclient.FailClosed

	p, err := NewProvider("risk", cfg)
	require.NoError(t, err)

	_, err = p.ResolveEntity(context.Background(), types.MappingStrategy{Name: "s"},
		map[string]any{"department": "finance"})
	require.Error(t, err)
}

func TestNewProviderRejectsEmptyQuestionCatalog(t *testing.T) {
	t.Setenv(jevclient.DefaultAPIKeyEnv, "test-key")
	cfg := Config{Client: jevclient.Config{Enabled: true, StateAllowlist: []string{"a"}}}

	_, err := NewProvider("risk", cfg)
	require.ErrorIs(t, err, ErrNoQuestions)
}
