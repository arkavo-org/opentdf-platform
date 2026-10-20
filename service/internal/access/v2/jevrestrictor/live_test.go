//go:build jevlive

package jevrestrictor

import (
	"os"
	"strconv"
	"testing"

	access "github.com/opentdf/platform/service/internal/access/v2"
	"github.com/opentdf/platform/service/internal/jev"
	"github.com/opentdf/platform/service/logger"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// These exercise the restrictor seam end to end against the real model:
// operator config in, live decision, denials and observations out.
//
//	set -a; . ./.env; set +a
//	cd service && go test -tags jevlive -v ./internal/access/v2/jevrestrictor/...

func liveConfig(t *testing.T, mode jev.Mode, threshold float64) Config {
	t.Helper()
	if os.Getenv(jev.DefaultAPIKeyEnv) == "" {
		t.Skipf("%s not set; source .env to run live tests", jev.DefaultAPIKeyEnv)
	}

	return Config{
		Client: jev.Config{
			Enabled:             true,
			Timeout:             "30s",
			ConfidenceThreshold: threshold,
			StateAllowlist: []string{
				StateKeyAction, StateKeyResourceCount,
				StateKeyAttributeValueFQNs, StateKeyPermittedCount,
			},
			Seams: jev.SeamsConfig{
				Restrictor: jev.SeamConfig{Enabled: true, Mode: mode},
			},
		},
		Questions: map[string]jev.Question{
			"is_exfiltration": jev.NewNoulQuestion(
				"Does this access request look like bulk data exfiltration rather than ordinary work?",
				"The number of resources requested at once is far beyond what a person reads in the course of their work.",
				"The request is consistent with ordinary day-to-day use.",
			),
		},
		Rules: []Rule{{Question: "is_exfiltration", Reason: "looks like bulk exfiltration"}},
	}
}

// bulkDecision is a decision policy fully permitted, over many secret resources.
func bulkDecision(n int) access.RestrictionRequest {
	resources := make([]access.RestrictionResource, n)
	for i := range resources {
		resources[i] = access.RestrictionResource{
			EphemeralID:        "r-" + strconv.Itoa(i),
			AttributeValueFQNs: []string{"https://example.org/attr/classification/value/secret"},
			Permitted:          true,
		}
	}
	return access.RestrictionRequest{EntityID: "analyst-1", ActionName: "read", Resources: resources}
}

func singleDecision() access.RestrictionRequest {
	return access.RestrictionRequest{
		EntityID:   "analyst-1",
		ActionName: "read",
		Resources: []access.RestrictionResource{{
			EphemeralID:        "r-0",
			AttributeValueFQNs: []string{"https://example.org/attr/classification/value/confidential"},
			Permitted:          true,
		}},
	}
}

func TestLiveRestrictorDeniesBulkRequest(t *testing.T) {
	r, err := New(liveConfig(t, jev.ModeEnforce, 0.8), logger.CreateTestLogger())
	require.NoError(t, err)
	require.NotNil(t, r)

	ctx := jev.Collect(t.Context())
	denials, err := r.Deny(ctx, bulkDecision(4812))
	require.NoError(t, err)

	obs := jev.Observations(ctx)
	require.Len(t, obs, 1)
	t.Logf("bulk:    answer=%v certainty=%.3f applied=%v cost=$%.8f",
		obs[0].Answer, obs[0].Certainty, obs[0].Applied, obs[0].Cost)

	assert.Len(t, denials, 4812, "a fired rule denies every resource policy permitted")
	assert.True(t, obs[0].Applied)
}

func TestLiveRestrictorLeavesRoutineRequestAlone(t *testing.T) {
	r, err := New(liveConfig(t, jev.ModeEnforce, 0.8), logger.CreateTestLogger())
	require.NoError(t, err)

	ctx := jev.Collect(t.Context())
	denials, err := r.Deny(ctx, singleDecision())
	require.NoError(t, err)

	obs := jev.Observations(ctx)
	require.Len(t, obs, 1)
	t.Logf("routine: answer=%v certainty=%.3f applied=%v",
		obs[0].Answer, obs[0].Certainty, obs[0].Applied)

	assert.Empty(t, denials, "a single ordinary read must not be denied")
	assert.False(t, obs[0].Applied)
}

func TestLiveShadowModeDeniesNothing(t *testing.T) {
	r, err := New(liveConfig(t, jev.ModeShadow, 0.8), logger.CreateTestLogger())
	require.NoError(t, err)

	ctx := jev.Collect(t.Context())
	denials, err := r.Deny(ctx, bulkDecision(4812))
	require.NoError(t, err)

	obs := jev.Observations(ctx)
	require.Len(t, obs, 1)
	t.Logf("shadow:  certainty=%.3f applied=%v", obs[0].Certainty, obs[0].Applied)

	assert.Empty(t, denials, "shadow mode must not deny, however certain the model is")
	assert.False(t, obs[0].Applied)
	assert.Positive(t, obs[0].Certainty, "but it must still record what it would have done")
}

// TestLiveThresholdCalibration measures where thresholds actually land against
// the real model, so the guidance in docs/jev-decision-model.md is grounded in
// observation rather than guessed.
func TestLiveThresholdCalibration(t *testing.T) {
	for _, threshold := range []float64{0.7, 0.8, 0.9, 0.95, 0.99} {
		r, err := New(liveConfig(t, jev.ModeEnforce, threshold), logger.CreateTestLogger())
		require.NoError(t, err)

		ctx := jev.Collect(t.Context())
		denials, err := r.Deny(ctx, bulkDecision(4812))
		require.NoError(t, err)

		obs := jev.Observations(ctx)
		require.Len(t, obs, 1)
		t.Logf("threshold=%.2f certainty=%.3f denied=%v",
			threshold, obs[0].Certainty, len(denials) > 0)
	}
}
