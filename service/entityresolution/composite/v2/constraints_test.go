package composite

import (
	"context"
	"sync/atomic"
	"testing"
	"time"

	"github.com/opentdf/platform/service/entityresolution/source"
	"github.com/opentdf/platform/service/internal/agentstatus"
	"github.com/stretchr/testify/assert"
)

const (
	tdfDef     = "https://arkavo.ai/attr/tdf"
	agentDID   = "did:key:z6Mkagent"
	agentOwner = "00000000-0000-0000-0000-000000000001"
)

// agentClaims is a contract v2 agent token: an arkavo_npe of type agent, a
// state version, a swarm and a key-bound cnf.
func agentClaims(exp time.Time) map[string]any {
	return map[string]any{
		"iss": testIssuer, "sub": agentDID, "exp": exp,
		"arkavo_account_id":    agentOwner,
		"arkavo_entitlements":  []any{decryptValue},
		"arkavo_npe":           map[string]any{"type": "agent", "delegation_id": agentDID, "depth": 0},
		"arkavo_state_version": 3,
		"arkavo_swarm":         "kit-42",
		"cnf": map[string]any{"jwk": map[string]any{
			"kty": "OKP", "crv": "Ed25519", "x": "11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo",
		}},
	}
}

func tdfSource() configuredSource {
	sc := SourceConfig{ID: "identity-core", Issuer: testIssuer, Grants: []string{tdfDef}}
	return sourceOf(sc, newTokenClaimsSource("arkavo_entitlements", sc.Grants))
}

// inferFree is the patreon source with infer_unknown_as_free, so a subject
// it resolves always carries properties.
func inferFree() configuredSource {
	return sourceOf(SourceConfig{ID: "patreon", Issuer: testIssuer, Grants: []string{campaignDef, tierDef}, PropertiesKey: "patreon"},
		sourceFunc(func(context.Context, source.Subject, source.Query) (source.Resolution, error) {
			return source.Resolution{Properties: map[string]any{"status": "former"}, Outcome: source.OutcomeComplete}, nil
		}))
}

// countingChecker counts status checks.
type countingChecker struct {
	statusAnswer
	calls atomic.Int32
}

func (c *countingChecker) Check(ctx context.Context, s agentstatus.Subject) error {
	c.calls.Add(1)
	return c.statusAnswer.Check(ctx, s)
}

func TestAgentWithheldWhenStatusUnset(t *testing.T) {
	log, buf := bufferLogger()
	svc := newTestService(t, testConfig(), verifiersFor(&fakeVerifier{}), []configuredSource{tdfSource(), inferFree()}, nil)
	svc.logger = log

	ev := tokenEvidence(t, svc, signCWT(t, agentClaims(time.Now().Add(time.Hour))))

	assert.Empty(t, ev.Grants)
	assert.Empty(t, ev.Props)
	assert.Equal(t, source.OutcomeComplete, ev.Outcomes["_token"], "the token is valid; only the agent is withheld")
	assert.Contains(t, buf.String(), "agent entitlements withheld")
	assert.Contains(t, buf.String(), agentstatus.ReasonUnconfigured)
	assert.Contains(t, buf.String(), agentDID)
}

func TestAgentWithheldWhenNotEligible(t *testing.T) {
	checker := &countingChecker{statusAnswer: statusAnswer{err: &agentstatus.DenialError{Reason: agentstatus.ReasonNotEligible, Agent: agentDID}}}
	svc := newTestService(t, testConfig(), verifiersFor(&fakeVerifier{}), []configuredSource{tdfSource(), inferFree()}, checker)

	ev := tokenEvidence(t, svc, signCWT(t, agentClaims(time.Now().Add(time.Hour))))

	assert.Empty(t, ev.Grants)
	assert.Empty(t, ev.Props)
	assert.Equal(t, int32(1), checker.calls.Load())
}

func TestAgentAdmittedWhenEligible(t *testing.T) {
	checker := &countingChecker{}
	svc := newTestService(t, testConfig(), verifiersFor(&fakeVerifier{}), []configuredSource{tdfSource(), inferFree()}, checker)

	ev := tokenEvidence(t, svc, signCWT(t, agentClaims(time.Now().Add(time.Hour))))

	assert.Equal(t, []string{decryptValue}, grantFQNs(ev))
	assert.Contains(t, ev.Props, "patreon")
	assert.Equal(t, int32(1), checker.calls.Load())
}

// A person carries no agent marker, so the status service is never asked and
// an identity outage cannot change a person's decision.
func TestAgentGate_PersonIsNeverChecked(t *testing.T) {
	checker := &countingChecker{statusAnswer: statusAnswer{err: &agentstatus.DenialError{Reason: agentstatus.ReasonUnreachable}}}
	svc := newTestService(t, testConfig(), verifiersFor(&fakeVerifier{}), []configuredSource{patreonSource()}, checker)

	ev := tokenEvidence(t, svc, signCWT(t, creatorClaims(time.Now().Add(time.Hour))))

	assert.Contains(t, grantFQNs(ev), creatorCampaign)
	assert.Zero(t, checker.calls.Load())
}
