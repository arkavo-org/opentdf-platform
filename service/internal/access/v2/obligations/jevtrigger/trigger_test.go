package jevtrigger

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/opentdf/platform/service/internal/access/v2/obligations"
	"github.com/opentdf/platform/service/internal/jev"
	"github.com/opentdf/platform/service/logger"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const (
	stepUpObligation = "https://example.org/obl/step_up/value/required"
	attrValFQN       = "https://example.org/attr/classification/value/secret"
)

// modelResponse answers a confident "yes" to the anomaly question and gives a
// confident "elevated" risk tier.
const modelResponse = `{
  "id": "gen-dec-oblig",
  "model": "typesafe/jev-1.13-20260917",
  "answers": {
    "is_anomalous": {"type":"noul","noul":0.97},
    "risk_tier": {"type":"choice","choice":"elevated","confidence":0.91,
                  "probabilities":{"elevated":0.91,"routine":0.09}}
  },
  "usage": {"cost": 0.000003, "input_tokens": 90, "output_tokens": 14}
}`

func baseConfig(t *testing.T, url string, mode jev.Mode) Config {
	t.Helper()
	t.Setenv(jev.DefaultAPIKeyEnv, "test-key")

	return Config{
		Client: jev.Config{
			Enabled:             true,
			BaseURL:             url,
			StateAllowlist:      []string{StateKeyAction, StateKeyAttributeValueFQNs},
			ConfidenceThreshold: 0.8,
			Seams: jev.SeamsConfig{
				Obligations: jev.SeamConfig{Enabled: true, Mode: mode},
			},
		},
		Questions: map[string]jev.Question{
			"is_anomalous": jev.NewNoulQuestion("Anomalous?", "yes", "no"),
			"risk_tier":    jev.NewChoiceQuestion("Risk?", map[string]any{"elevated": "e", "routine": "r"}),
		},
		Rules: []Rule{{Question: "is_anomalous", Obligation: stepUpObligation}},
	}
}

func newTrigger(t *testing.T, mode jev.Mode, handler http.HandlerFunc, mutate func(*Config)) *Trigger {
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

	trigger, err := New(cfg, logger.CreateTestLogger())
	require.NoError(t, err)
	require.NotNil(t, trigger)
	return trigger
}

func request() obligations.TriggerRequest {
	return obligations.TriggerRequest{
		ActionName:         "read",
		AttributeValueFQNs: []string{attrValFQN},
		PEPClientID:        "some-pep",
	}
}

func TestEnforcingModeRequiresObligation(t *testing.T) {
	trigger := newTrigger(t, jev.ModeEnforce, nil, nil)
	ctx := jev.Collect(t.Context())

	got, err := trigger.AdditionalObligations(ctx, request())
	require.NoError(t, err)

	assert.Equal(t, []string{stepUpObligation}, got)

	obs := jev.Observations(ctx)
	require.Len(t, obs, 1)
	assert.True(t, obs[0].Applied)
	assert.Equal(t, "required_obligation:"+stepUpObligation, obs[0].Effect)
	assert.Equal(t, "gen-dec-oblig", obs[0].ResponseID)
}

func TestShadowModeObservesButRequiresNothing(t *testing.T) {
	trigger := newTrigger(t, jev.ModeShadow, nil, nil)
	ctx := jev.Collect(t.Context())

	got, err := trigger.AdditionalObligations(ctx, request())
	require.NoError(t, err)

	assert.Empty(t, got, "shadow mode must not change the decision")

	obs := jev.Observations(ctx)
	require.Len(t, obs, 1)
	assert.False(t, obs[0].Applied)
	assert.InDelta(t, 0.97, obs[0].Certainty, 1e-9,
		"shadow mode still records what the model would have done")
}

func TestOnlyAllowlistedStateLeavesThePlatform(t *testing.T) {
	var sentState map[string]any
	trigger := newTrigger(t, jev.ModeEnforce, func(w http.ResponseWriter, r *http.Request) {
		var body struct {
			State map[string]any `json:"state"`
		}
		if err := decodeJSON(r, &body); err != nil {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		sentState = body.State
		_, _ = w.Write([]byte(modelResponse))
	}, nil)

	_, err := trigger.AdditionalObligations(jev.Collect(t.Context()), request())
	require.NoError(t, err)

	assert.Contains(t, sentState, StateKeyAction)
	assert.Contains(t, sentState, StateKeyAttributeValueFQNs)
	assert.NotContains(t, sentState, StateKeyPEPClientID,
		"an unlisted state key must not be sent even though the trigger knows it")
}

func TestWhenFalseInvertsBooleanRule(t *testing.T) {
	trigger := newTrigger(t, jev.ModeEnforce, nil, func(c *Config) {
		c.Rules = []Rule{{Question: "is_anomalous", Obligation: stepUpObligation, WhenFalse: true}}
	})

	got, err := trigger.AdditionalObligations(jev.Collect(t.Context()), request())
	require.NoError(t, err)
	assert.Empty(t, got, "a confident true must not satisfy a when_false rule")
}

func TestChoiceRuleMatchesListedChoice(t *testing.T) {
	trigger := newTrigger(t, jev.ModeEnforce, nil, func(c *Config) {
		c.Rules = []Rule{{
			Question: "risk_tier", Obligation: stepUpObligation,
			WhenChoice: []string{"elevated"},
		}}
	})

	got, err := trigger.AdditionalObligations(jev.Collect(t.Context()), request())
	require.NoError(t, err)
	assert.Equal(t, []string{stepUpObligation}, got)
}

func TestChoiceRuleIgnoresUnlistedChoice(t *testing.T) {
	trigger := newTrigger(t, jev.ModeEnforce, nil, func(c *Config) {
		c.Rules = []Rule{{
			Question: "risk_tier", Obligation: stepUpObligation,
			WhenChoice: []string{"routine"},
		}}
	})

	got, err := trigger.AdditionalObligations(jev.Collect(t.Context()), request())
	require.NoError(t, err)
	assert.Empty(t, got)
}

func TestLowConfidenceAnswerRequiresNothing(t *testing.T) {
	trigger := newTrigger(t, jev.ModeEnforce, nil, func(c *Config) {
		c.Client.ConfidenceThreshold = 0.99
	})

	got, err := trigger.AdditionalObligations(jev.Collect(t.Context()), request())
	require.NoError(t, err)
	assert.Empty(t, got, "0.97 does not clear a 0.99 bar, so the rule must not fire")
}

func TestFailOpenRequiresNothing(t *testing.T) {
	trigger := newTrigger(t, jev.ModeEnforce, func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusServiceUnavailable)
	}, nil)
	ctx := jev.Collect(t.Context())

	got, err := trigger.AdditionalObligations(ctx, request())

	require.NoError(t, err, "failing open loses only an obligation policy never required")
	assert.Empty(t, got)

	obs := jev.Observations(ctx)
	require.Len(t, obs, 1)
	assert.NotEmpty(t, obs[0].Error, "a fail-open path must still be visible in the audit trail")
}

func TestFailClosedReturnsError(t *testing.T) {
	trigger := newTrigger(t, jev.ModeEnforce, func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusServiceUnavailable)
	}, func(c *Config) { c.Client.FailMode = jev.FailClosed })

	_, err := trigger.AdditionalObligations(jev.Collect(t.Context()), request())
	require.Error(t, err)
	assert.Contains(t, err.Error(), "fail_mode is closed")
}

func TestDisabledSeamBuildsNoTrigger(t *testing.T) {
	t.Setenv(jev.DefaultAPIKeyEnv, "test-key")
	cfg := baseConfig(t, "http://unused", jev.ModeEnforce)
	cfg.Client.Seams.Obligations.Enabled = false

	trigger, err := New(cfg, logger.CreateTestLogger())
	require.NoError(t, err)
	assert.Nil(t, trigger, "a disabled seam must install nothing")
}

func TestNilTriggerIsSafeToCall(t *testing.T) {
	var trigger *Trigger
	got, err := trigger.AdditionalObligations(t.Context(), request())
	require.NoError(t, err)
	assert.Empty(t, got)
}

func TestNewRejectsRuleForUnknownQuestion(t *testing.T) {
	t.Setenv(jev.DefaultAPIKeyEnv, "test-key")
	cfg := baseConfig(t, "http://unused", jev.ModeEnforce)
	cfg.Rules = []Rule{{Question: "not_asked", Obligation: stepUpObligation}}

	_, err := New(cfg, logger.CreateTestLogger())
	require.Error(t, err)
	assert.Contains(t, err.Error(), "unknown question")
}

func TestNewRejectsRuleWithoutObligation(t *testing.T) {
	t.Setenv(jev.DefaultAPIKeyEnv, "test-key")
	cfg := baseConfig(t, "http://unused", jev.ModeEnforce)
	cfg.Rules = []Rule{{Question: "is_anomalous"}}

	_, err := New(cfg, logger.CreateTestLogger())
	require.Error(t, err)
	assert.Contains(t, err.Error(), "no obligation")
}

func TestShadowModeNeverFailsClosed(t *testing.T) {
	// A shadow-mode seam has no authority over the decision, so it must not be
	// able to fail one. Without this guard, fail_mode: closed plus an
	// unreachable model would break every decision -- and so every KAS rewrap
	// -- which is precisely what shadow mode exists to prevent.
	trigger := newTrigger(t, jev.ModeShadow, func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusServiceUnavailable)
	}, func(c *Config) { c.Client.FailMode = jev.FailClosed })
	ctx := jev.Collect(t.Context())

	got, err := trigger.AdditionalObligations(ctx, request())

	require.NoError(t, err, "shadow mode must never fail a decision it cannot influence")
	assert.Empty(t, got)

	obs := jev.Observations(ctx)
	require.Len(t, obs, 1)
	assert.NotEmpty(t, obs[0].Error, "the unreachable model is still recorded")
}
