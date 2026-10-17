package composite

import (
	"context"
	"sync/atomic"
	"testing"
	"time"

	"github.com/opentdf/platform/service/entityresolution/source"
	"github.com/opentdf/platform/service/internal/agentstatus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const (
	tdfDef       = "https://arkavo.ai/attr/tdf"
	agentDID     = "did:key:z6Mkagent"
	agentOwner   = "00000000-0000-0000-0000-000000000001"
	classifyDef  = "https://arkavo.ai/attr/classification"
	classPublic  = "https://arkavo.ai/attr/classification/value/public"
	attestedNPE  = "attested"
	managedClass = "managed"
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

func device(class string) source.Subject {
	npe := map[string]any{"type": "device"}
	if class != "" {
		npe["class"] = class
	}
	claims := map[string]any{"iss": testIssuer, "arkavo_npe": npe}
	return source.Subject{Claims: claims, Kind: source.KindOf(claims), Trust: source.TrustVerified}
}

func sealed(fqns ...string) []sealedGrant {
	out := make([]sealedGrant, 0, len(fqns))
	for _, f := range fqns {
		out = append(out, sealedGrant{FQN: f, Actions: []string{"read"}, Source: "s"})
	}
	return out
}

func TestDeviceCaps_MissingClassIsNoCap(t *testing.T) {
	caps := map[string]map[string]bool{managedClass: {classInternal: true}}
	grants := sealed(classInternal, classConfidential)

	assert.Equal(t, grants, capGrants(caps, device(attestedNPE), grants), "attested has no cap")
	assert.Equal(t, grants, capGrants(caps, device(""), grants), "unverified has no cap")
	assert.Equal(t, grants, capGrants(nil, device(managedClass), grants), "no caps configured")

	person := source.Subject{Claims: map[string]any{"iss": testIssuer}, Kind: source.KindPerson, Trust: source.TrustVerified}
	assert.Equal(t, grants, capGrants(caps, person, grants), "caps bind devices only")
}

func TestDeviceCaps_IntersectNeverAdds(t *testing.T) {
	caps := map[string]map[string]bool{
		managedClass:    {classInternal: true, classPublic: true},
		classUnverified: {},
	}
	grants := sealed(classInternal, classConfidential)

	assert.Equal(t, sealed(classInternal), capGrants(caps, device(managedClass), grants),
		"the cap keeps internal, removes confidential and never adds public")
	assert.Empty(t, capGrants(caps, device(""), grants), "a device with no class is unverified, capped to nothing")
}

// The caps are applied on the token route, after the union, to every
// source's grants, the device-class source's included.
func TestDeviceCaps_AppliedOnTokenRoute(t *testing.T) {
	cfg := testConfig()
	cfg.Constraints.DeviceClassCaps = map[string][]string{managedClass: {"HTTPS://arkavo.ai/attr/classification/value/Internal"}}
	devices := SourceConfig{ID: "device-class", Issuer: testIssuer, Grants: []string{classifyDef}}
	svc := newTestService(t, cfg, verifiersFor(&fakeVerifier{}), []configuredSource{
		sourceOf(devices, newDeviceClassSource(map[string][]string{managedClass: {classInternal, classConfidential}})),
		tdfSource(),
	}, nil)
	claims := creatorClaims(time.Now().Add(time.Hour))
	claims["arkavo_entitlements"] = []any{decryptValue}
	claims["arkavo_npe"] = map[string]any{"type": "device", "class": managedClass}

	ev := tokenEvidence(t, svc, signCWT(t, claims))

	assert.Equal(t, []string{classInternal}, grantFQNs(ev))
	require.Equal(t, source.OutcomeComplete, ev.Outcomes["device-class"])
}
