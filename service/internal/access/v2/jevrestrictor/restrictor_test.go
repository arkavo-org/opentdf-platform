package jevrestrictor

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	access "github.com/opentdf/platform/service/internal/access/v2"
	"github.com/opentdf/platform/service/internal/jev"
	"github.com/opentdf/platform/service/logger"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// modelResponse is a confident "yes, anomalous".
const modelResponse = `{
  "id": "gen-dec-restrict",
  "model": "typesafe/jev-1.13-20260917",
  "answers": {"is_exfiltration": {"type":"noul","noul":0.98}},
  "usage": {"cost": 0.000004, "input_tokens": 110, "output_tokens": 12}
}`

func decodeJSON(r *http.Request, into any) error {
	return json.NewDecoder(r.Body).Decode(into)
}

func baseConfig(t *testing.T, url string, mode jev.Mode) Config {
	t.Helper()
	t.Setenv(jev.DefaultAPIKeyEnv, "test-key")

	return Config{
		Client: jev.Config{
			Enabled:             true,
			BaseURL:             url,
			StateAllowlist:      []string{StateKeyAction, StateKeyResourceCount},
			ConfidenceThreshold: 0.8,
			Seams: jev.SeamsConfig{
				Restrictor: jev.SeamConfig{Enabled: true, Mode: mode},
			},
		},
		Questions: map[string]jev.Question{
			"is_exfiltration": jev.NewNoulQuestion("Bulk exfiltration?", "yes", "no"),
		},
		Rules: []Rule{{Question: "is_exfiltration", Reason: "looks like bulk exfiltration"}},
	}
}

func newRestrictor(t *testing.T, mode jev.Mode, handler http.HandlerFunc, mutate func(*Config)) *Restrictor {
	t.Helper()
	if handler == nil {
		handler = func(w http.ResponseWriter, _ *http.Request) {
			_, _ = w.Write([]byte(modelResponse))
		}
	}
	srv := httptest.NewServer(handler)
	t.Cleanup(srv.Close)

	cfg := baseConfig(t, srv.URL, mode)
	if mutate != nil {
		mutate(&cfg)
	}

	r, err := New(cfg, logger.CreateTestLogger())
	require.NoError(t, err)
	require.NotNil(t, r)
	return r
}

func request(permitted ...bool) access.RestrictionRequest {
	resources := make([]access.RestrictionResource, len(permitted))
	for i, p := range permitted {
		resources[i] = access.RestrictionResource{
			EphemeralID:        "r-" + string(rune('0'+i)),
			AttributeValueFQNs: []string{"https://example.org/attr/a/value/b"},
			Permitted:          p,
		}
	}
	return access.RestrictionRequest{EntityID: "e-1", ActionName: "read", Resources: resources}
}

func TestEnforcingModeDeniesPermittedResources(t *testing.T) {
	r := newRestrictor(t, jev.ModeEnforce, nil, nil)
	ctx := jev.Collect(t.Context())

	denials, err := r.Deny(ctx, request(true, true))
	require.NoError(t, err)

	assert.Len(t, denials, 2)
	assert.Equal(t, "looks like bulk exfiltration", denials["r-0"])

	obs := jev.Observations(ctx)
	require.Len(t, obs, 1)
	assert.True(t, obs[0].Applied)
}

func TestDeniesOnlyResourcesPolicyPermitted(t *testing.T) {
	r := newRestrictor(t, jev.ModeEnforce, nil, nil)

	denials, err := r.Deny(jev.Collect(t.Context()), request(true, false))
	require.NoError(t, err)

	assert.Contains(t, denials, "r-0")
	assert.NotContains(t, denials, "r-1",
		"a resource policy already denied needs no further denial")
}

func TestShadowModeDeniesNothing(t *testing.T) {
	r := newRestrictor(t, jev.ModeShadow, nil, nil)
	ctx := jev.Collect(t.Context())

	denials, err := r.Deny(ctx, request(true, true))
	require.NoError(t, err)

	assert.Empty(t, denials, "shadow mode must not change the decision")

	obs := jev.Observations(ctx)
	require.Len(t, obs, 1)
	assert.False(t, obs[0].Applied)
	assert.InDelta(t, 0.98, obs[0].Certainty, 1e-9)
}

func TestFullyDeniedDecisionSkipsTheModel(t *testing.T) {
	r := newRestrictor(t, jev.ModeEnforce, func(http.ResponseWriter, *http.Request) {
		t.Fatal("must not spend a call on a decision that cannot change")
	}, nil)

	denials, err := r.Deny(jev.Collect(t.Context()), request(false, false))
	require.NoError(t, err)
	assert.Empty(t, denials)
}

func TestOnlyAllowlistedStateLeavesThePlatform(t *testing.T) {
	var sent map[string]any
	r := newRestrictor(t, jev.ModeEnforce, func(w http.ResponseWriter, req *http.Request) {
		var body struct {
			State map[string]any `json:"state"`
		}
		if err := decodeJSON(req, &body); err != nil {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		sent = body.State
		_, _ = w.Write([]byte(modelResponse))
	}, nil)

	_, err := r.Deny(jev.Collect(t.Context()), request(true))
	require.NoError(t, err)

	assert.Contains(t, sent, StateKeyAction)
	assert.Contains(t, sent, StateKeyResourceCount)
	assert.NotContains(t, sent, StateKeyEntityID,
		"an unlisted key must not be sent even though the restrictor knows it")
	assert.NotContains(t, sent, StateKeyAttributeValueFQNs)
}

func TestLowConfidenceDeniesNothing(t *testing.T) {
	r := newRestrictor(t, jev.ModeEnforce, nil, func(c *Config) {
		c.Client.ConfidenceThreshold = 0.99
	})

	denials, err := r.Deny(jev.Collect(t.Context()), request(true))
	require.NoError(t, err)
	assert.Empty(t, denials, "0.98 does not clear a 0.99 bar")
}

func TestFailOpenDeniesNothing(t *testing.T) {
	r := newRestrictor(t, jev.ModeEnforce, func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusServiceUnavailable)
	}, nil)
	ctx := jev.Collect(t.Context())

	denials, err := r.Deny(ctx, request(true))

	require.NoError(t, err, "fail-open leaves policy's decision standing")
	assert.Empty(t, denials)
	require.Len(t, jev.Observations(ctx), 1)
	assert.NotEmpty(t, jev.Observations(ctx)[0].Error)
}

func TestFailClosedReturnsError(t *testing.T) {
	r := newRestrictor(t, jev.ModeEnforce, func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusServiceUnavailable)
	}, func(c *Config) { c.Client.FailMode = jev.FailClosed })

	_, err := r.Deny(jev.Collect(t.Context()), request(true))
	require.Error(t, err)
	assert.Contains(t, err.Error(), "fail_mode is closed")
}

func TestShadowModeNeverFailsClosed(t *testing.T) {
	// A shadow-mode seam has no authority, so fail_mode must not let it break
	// a decision it cannot influence.
	r := newRestrictor(t, jev.ModeShadow, func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusServiceUnavailable)
	}, func(c *Config) { c.Client.FailMode = jev.FailClosed })

	denials, err := r.Deny(jev.Collect(t.Context()), request(true))
	require.NoError(t, err, "shadow mode must never fail a decision")
	assert.Empty(t, denials)
}

func TestDisabledSeamBuildsNoRestrictor(t *testing.T) {
	t.Setenv(jev.DefaultAPIKeyEnv, "test-key")
	cfg := baseConfig(t, "http://unused", jev.ModeEnforce)
	cfg.Client.Seams.Restrictor.Enabled = false

	r, err := New(cfg, logger.CreateTestLogger())
	require.NoError(t, err)
	assert.Nil(t, r)
}

func TestNilRestrictorIsSafeToCall(t *testing.T) {
	var r *Restrictor
	denials, err := r.Deny(t.Context(), request(true))
	require.NoError(t, err)
	assert.Empty(t, denials)
}

func TestNewRejectsRuleForUnknownQuestion(t *testing.T) {
	t.Setenv(jev.DefaultAPIKeyEnv, "test-key")
	cfg := baseConfig(t, "http://unused", jev.ModeEnforce)
	cfg.Rules = []Rule{{Question: "not_asked"}}

	_, err := New(cfg, logger.CreateTestLogger())
	require.Error(t, err)
	assert.Contains(t, err.Error(), "unknown question")
}

func TestNewRejectsEmptyRules(t *testing.T) {
	t.Setenv(jev.DefaultAPIKeyEnv, "test-key")
	cfg := baseConfig(t, "http://unused", jev.ModeEnforce)
	cfg.Rules = nil

	_, err := New(cfg, logger.CreateTestLogger())
	require.ErrorIs(t, err, ErrNoRules)
}
