package arkavo

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"connectrpc.com/connect"
	"github.com/opentdf/platform/protocol/go/entity"
	entityresolutionV2 "github.com/opentdf/platform/protocol/go/entityresolution/v2"
	"github.com/opentdf/platform/service/internal/agentstatus"
	"github.com/opentdf/platform/service/logger"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/types/known/anypb"
	"google.golang.org/protobuf/types/known/structpb"
)

const (
	testAgentDID = "did:key:z6Mkagent"
	testOwner    = "00000000-0000-0000-0000-000000000001"
	testWorkload = "wl-00112233445566778899aabbccddeeff"
	testSwarm    = "kit-42"

	statusClientSecret = "status-client-secret-never-logged"
	statusServiceToken = "svc-cwt-never-logged"

	// testAgentX is the public half of an Ed25519 agent key (base64url).
	testAgentX = "11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo"
)

// testAgentJWK is the agent key as cnf.jwk.
func testAgentJWK() map[string]interface{} {
	return map[string]interface{}{"kty": "OKP", "crv": "Ed25519", "x": testAgentX}
}

type fakeChecker struct {
	mu    sync.Mutex
	err   error
	calls int
	got   agentstatus.Subject
}

func (f *fakeChecker) Check(_ context.Context, s agentstatus.Subject) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls++
	f.got = s
	return f.err
}

func (f *fakeChecker) callCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.calls
}

func (f *fakeChecker) setErr(err error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.err = err
}

type checkerFunc func(context.Context, agentstatus.Subject) error

func (f checkerFunc) Check(ctx context.Context, s agentstatus.Subject) error { return f(ctx, s) }

func wantSubject() agentstatus.Subject {
	return agentstatus.Subject{DID: testAgentDID, Workload: testWorkload, Swarm: testSwarm, Owner: testOwner}
}

func trustedCfg() Config { return Config{TrustMaterializedClaims: true, TrustedIssuer: issuer} }

// gateSvc is a trusted-issuer resolver whose log is captured.
func gateSvc(t *testing.T, cfg Config, checker agentstatus.Checker) (*EntityResolutionService, *bytes.Buffer) {
	t.Helper()
	svc := newSvc(t, cfg)
	buf := &bytes.Buffer{}
	svc.logger = &logger.Logger{Logger: slog.New(slog.NewJSONHandler(buf, &slog.HandlerOptions{Level: slog.LevelDebug}))}
	svc.agentStatus = checker
	return svc, buf
}

func tokenWith(t *testing.T, mutate func(map[string]interface{})) string {
	t.Helper()
	claims := agentClaims(issuer)
	mutate(claims)
	return buildJWT(t, claims)
}

// resolveSubject resolves a chain and returns the SUBJECT's representation.
func resolveSubject(t *testing.T, svc *EntityResolutionService, ents []*entity.Entity) *entityresolutionV2.EntityRepresentation {
	t.Helper()
	resp, err := svc.ResolveEntities(t.Context(), connect.NewRequest(&entityresolutionV2.ResolveEntitiesRequest{Entities: ents}))
	require.NoError(t, err, "a withheld agent must never fail the resolution")
	reps := resp.Msg.GetEntityRepresentations()
	require.Len(t, reps, len(ents), "one representation per entity")
	for i, e := range ents {
		if e.GetCategory() == entity.Entity_CATEGORY_SUBJECT {
			return reps[i]
		}
	}
	t.Fatal("no subject entity")
	return nil
}

// assertWithheld: no entitlements and no claims, so no subject mapping can
// match either.
func assertWithheld(t *testing.T, rep *entityresolutionV2.EntityRepresentation) {
	t.Helper()
	assert.Equal(t, "arkavo-subject", rep.GetOriginalId())
	assert.Empty(t, rep.GetDirectEntitlements())
	assert.Empty(t, rep.GetAdditionalProps())
}

func logRecords(t *testing.T, buf *bytes.Buffer) []map[string]any {
	t.Helper()
	var out []map[string]any
	for _, line := range strings.Split(strings.TrimSpace(buf.String()), "\n") {
		if line == "" {
			continue
		}
		var rec map[string]any
		require.NoError(t, json.Unmarshal([]byte(line), &rec))
		out = append(out, rec)
	}
	return out
}

// withheldRecord is the single denial the buffer holds.
func withheldRecord(t *testing.T, buf *bytes.Buffer) map[string]any {
	t.Helper()
	var found map[string]any
	for _, rec := range logRecords(t, buf) {
		if rec["msg"] == agentWithheldMsg {
			require.Nil(t, found, "more than one denial record")
			found = rec
		}
	}
	require.NotNil(t, found, "no denial record")
	return found
}

func TestAgentGate_EligibleAgentKeepsDelegatedEntitlements(t *testing.T) {
	checker := &fakeChecker{}
	svc, buf := gateSvc(t, trustedCfg(), checker)
	rep := resolveSubject(t, svc, chainsFor(t, svc, agentToken(t, issuer)))
	assert.Len(t, rep.GetDirectEntitlements(), 2)
	assert.NotEmpty(t, rep.GetAdditionalProps())
	assert.Equal(t, 1, checker.callCount())
	assert.Equal(t, wantSubject(), checker.got)
	assert.NotContains(t, buf.String(), agentWithheldMsg)
}

func TestAgentGate_QuarantinedAgentResolvesWithNothing(t *testing.T) {
	checker := &fakeChecker{err: &agentstatus.DenialError{Reason: agentstatus.ReasonNotEligible, Workload: testWorkload, Generation: 4, Incident: "inc-9"}}
	svc, buf := gateSvc(t, trustedCfg(), checker)
	tok := agentToken(t, issuer)
	assertWithheld(t, resolveSubject(t, svc, chainsFor(t, svc, tok)))
	rec := withheldRecord(t, buf)
	assert.Equal(t, "WARN", rec["level"])
	assert.Equal(t, agentstatus.ReasonNotEligible, rec["reason"])
	assert.Equal(t, "inc-9", rec["incident"])
	assert.InDelta(t, 4, rec["generation"], 0)
	assert.Equal(t, testAgentDID, rec["agent"])
	assert.Equal(t, testOwner, rec["owner"])
	assert.Equal(t, testWorkload, rec["workload"])
	assert.Equal(t, testSwarm, rec["swarm"])
	assert.NotContains(t, buf.String(), tok)
}

// A PEP may create a chain once and resolve it later; the status in force at
// resolution time decides.
func TestAgentGate_ChainResolvedAfterQuarantineIsWithheld(t *testing.T) {
	checker := &fakeChecker{}
	svc, _ := gateSvc(t, trustedCfg(), checker)
	ents := chainsFor(t, svc, agentToken(t, issuer))
	require.Len(t, resolveSubject(t, svc, ents).GetDirectEntitlements(), 2)

	checker.setErr(&agentstatus.DenialError{Reason: agentstatus.ReasonNotEligible, Workload: testWorkload})
	assertWithheld(t, resolveSubject(t, svc, ents))
	assert.Equal(t, 2, checker.callCount(), "every resolution asks")
}

func TestAgentGate_UnconfiguredWithholdsEveryAgentAtError(t *testing.T) {
	svc, buf := gateSvc(t, trustedCfg(), nil)
	assertWithheld(t, resolveSubject(t, svc, chainsFor(t, svc, agentToken(t, issuer))))
	rec := withheldRecord(t, buf)
	assert.Equal(t, "ERROR", rec["level"])
	assert.Equal(t, agentstatus.ReasonUnconfigured, rec["reason"])
}

func TestAgentGate_AgentWithoutKeyCnfIsWithheldWithoutAsking(t *testing.T) {
	jkt := map[string]interface{}{"jkt": "0ZcOCORZNYy-DWpqq30jZyJGHTN0d2HglBV3uiguA4I"}
	for name, mutate := range map[string]func(map[string]interface{}){
		"no cnf":             func(c map[string]interface{}) { delete(c, "cnf") },
		"cnf.jkt thumbprint": func(c map[string]interface{}) { c["cnf"] = jkt },
		"cnf not an object":  func(c map[string]interface{}) { c["cnf"] = "jwk" },
		"cnf.jwk null":       func(c map[string]interface{}) { c["cnf"] = map[string]interface{}{"jwk": nil} },
		"cnf.jwk empty":      func(c map[string]interface{}) { c["cnf"] = map[string]interface{}{"jwk": map[string]interface{}{}} },
		"cnf.jwk without kty": func(c map[string]interface{}) {
			c["cnf"] = map[string]interface{}{"jwk": map[string]interface{}{"x": testAgentX}}
		},
		"cnf.jwk of kty RSA": func(c map[string]interface{}) {
			c["cnf"] = map[string]interface{}{"jwk": map[string]interface{}{"kty": "RSA", "n": "sXch", "e": "AQAB"}}
		},
		"cnf.jwk OKP without x": func(c map[string]interface{}) {
			c["cnf"] = map[string]interface{}{"jwk": map[string]interface{}{"kty": "OKP", "crv": "Ed25519"}}
		},
		"cnf.jwk EC without y": func(c map[string]interface{}) {
			c["cnf"] = map[string]interface{}{"jwk": map[string]interface{}{"kty": "EC", "crv": "P-256", "x": testAgentX}}
		},
	} {
		t.Run(name, func(t *testing.T) {
			checker := &fakeChecker{}
			svc, buf := gateSvc(t, trustedCfg(), checker)
			assertWithheld(t, resolveSubject(t, svc, chainsFor(t, svc, tokenWith(t, mutate))))
			assert.Equal(t, 0, checker.callCount())
			assert.Equal(t, reasonNotKeyBound, withheldRecord(t, buf)["reason"])
		})
	}
}

// A P-256 agent key (kty EC with x and y) is key-bound too.
func TestAgentGate_ECKeyCnfIsKeyBound(t *testing.T) {
	checker := &fakeChecker{}
	svc, _ := gateSvc(t, trustedCfg(), checker)
	tok := tokenWith(t, func(c map[string]interface{}) {
		c["cnf"] = map[string]interface{}{"jwk": map[string]interface{}{"kty": "EC", "crv": "P-256", "x": testAgentX, "y": testAgentX}}
	})
	assert.Len(t, resolveSubject(t, svc, chainsFor(t, svc, tok)).GetDirectEntitlements(), 2)
	assert.Equal(t, 1, checker.callCount())
}

// A person or device token never reaches the status service: an identity
// outage must not change their decisions.
func TestAgentGate_PersonAndDeviceNeverAsk(t *testing.T) {
	down := &fakeChecker{err: &agentstatus.DenialError{Reason: agentstatus.ReasonUnreachable}}
	svc, buf := gateSvc(t, Config{
		TrustMaterializedClaims: true, TrustedIssuer: issuer,
		DeviceClassCeilings: map[string][]string{"unverified": {"https://arkavo.ai/attr/classification/value/internal"}},
	}, down)
	person := buildJWT(t, map[string]interface{}{
		"iss": issuer, "sub": testOwner,
		"arkavo_roles":        []interface{}{"user"},
		"arkavo_entitlements": []interface{}{"https://arkavo.ai/attr/tdf/value/decrypt"},
	})
	device := buildJWT(t, map[string]interface{}{
		"iss": issuer, "sub": testOwner,
		"arkavo_npe": map[string]interface{}{"type": "device", "class": "unverified", "device_id": "K1"},
	})
	assert.Len(t, resolveSubject(t, svc, chainsFor(t, svc, person)).GetDirectEntitlements(), 1)
	assert.Len(t, resolveSubject(t, svc, chainsFor(t, svc, device)).GetDirectEntitlements(), 1)
	assert.Equal(t, 0, down.callCount())
	assert.NotContains(t, buf.String(), agentWithheldMsg)
}

// Any agent marker gates a token, and a gated token that is not an
// arkavo_npe of type agent is withheld without asking identity (#45's
// partial-shape fixtures). A token that looks partly like an agent's is
// never resolved as a person.
func TestAgentGate_PartialAgentShapesAreWithheld(t *testing.T) {
	base := func() map[string]interface{} {
		return map[string]interface{}{
			"iss": issuer, "sub": testAgentDID,
			"arkavo_account_id":   testOwner,
			"arkavo_entitlements": []interface{}{"https://arkavo.ai/attr/tdf/value/decrypt"},
			"cnf":                 map[string]interface{}{"jwk": testAgentJWK()},
		}
	}
	for name, add := range map[string]map[string]interface{}{
		"arkavo_workload alone":                 {"arkavo_workload": testWorkload},
		"arkavo_swarm alone":                    {"arkavo_swarm": testSwarm},
		"agent role without arkavo_npe":         {"arkavo_roles": []interface{}{"user", "agent"}},
		"agent role as a bare string":           {"arkavo_roles": "agent"},
		"device npe also carrying a workload":   {"arkavo_npe": map[string]interface{}{"type": "device"}, "arkavo_workload": testWorkload},
		"arkavo_npe that is not an object":      {"arkavo_npe": "agent"},
		"arkavo_npe without a type":             {"arkavo_npe": map[string]interface{}{"delegation_id": testAgentDID}},
		"arkavo_npe with a non-string type":     {"arkavo_npe": map[string]interface{}{"type": 7}},
		"arkavo_npe with an unknown type":       {"arkavo_npe": map[string]interface{}{"type": "service"}},
		"swarm and workload without arkavo_npe": {"arkavo_workload": testWorkload, "arkavo_swarm": testSwarm},
	} {
		t.Run(name, func(t *testing.T) {
			claims := base()
			for k, v := range add {
				claims[k] = v
			}
			checker := &fakeChecker{}
			svc, buf := gateSvc(t, trustedCfg(), checker)
			assertWithheld(t, resolveSubject(t, svc, chainsFor(t, svc, buildJWT(t, claims))))
			assert.Equal(t, 0, checker.callCount())
			assert.Equal(t, reasonNotAgentProfile, withheldRecord(t, buf)["reason"])
		})
	}
}

// An agent whose arkavo_workload has the wrong type reaches the checker with
// an empty workload, which checkSubject refuses without calling identity.
func TestAgentGate_WorkloadOfTheWrongTypeReachesTheCheckerEmpty(t *testing.T) {
	checker := &fakeChecker{}
	svc, _ := gateSvc(t, trustedCfg(), checker)
	tok := tokenWith(t, func(c map[string]interface{}) { c["arkavo_workload"] = 42 })
	resolveSubject(t, svc, chainsFor(t, svc, tok))
	require.Equal(t, 1, checker.callCount())
	assert.Empty(t, checker.got.Workload)
}

// Scope boundary: a caller that supplies its own entity chain asserts its
// claims. A SUBJECT with the trusted marker and no agent marker is not gated.
// The KAS always sends the verified bearer, so its decisions cannot be
// forged this way; only trusted PEPs may call GetDecision with entity chains
// in arkavo deployments (documented; provenance-bound claims are a
// follow-up).
func TestAgentGate_SuppliedChainWithoutMarkersIsNotGated(t *testing.T) {
	checker := &fakeChecker{err: &agentstatus.DenialError{Reason: agentstatus.ReasonNotEligible}}
	svc, _ := gateSvc(t, trustedCfg(), checker)
	st, err := structpb.NewStruct(map[string]interface{}{
		"sub": testAgentDID, "iss": issuer, trustedMarker: true,
		"arkavo_entitlements": []interface{}{"https://arkavo.ai/attr/tdf/value/decrypt"},
	})
	require.NoError(t, err)
	claims, err := anypb.New(st)
	require.NoError(t, err)
	supplied := []*entity.Entity{{EntityType: &entity.Entity_Claims{Claims: claims}, EphemeralId: "arkavo-subject", Category: entity.Entity_CATEGORY_SUBJECT}}
	assert.Len(t, resolveSubject(t, svc, supplied).GetDirectEntitlements(), 1)
	assert.Equal(t, 0, checker.callCount())
}

func TestAgentGate_OwnerFromConfiguredClientIDClaim(t *testing.T) {
	checker := &fakeChecker{}
	cfg := trustedCfg()
	cfg.ClientIDClaim = "acct"
	svc, _ := gateSvc(t, cfg, checker)
	resolveSubject(t, svc, chainsFor(t, svc, agentToken(t, issuer)))
	assert.Equal(t, testOwner, checker.got.Owner)
}

func TestAgentGate_UntrustedIssuerNeverAsks(t *testing.T) {
	checker := &fakeChecker{}
	svc, _ := gateSvc(t, trustedCfg(), checker)
	rep := resolveSubject(t, svc, chainsFor(t, svc, agentToken(t, "https://evil.example.com")))
	assert.Empty(t, rep.GetDirectEntitlements())
	assert.Equal(t, 0, checker.callCount())
}

func TestAgentGate_CheckerFaults(t *testing.T) {
	t.Run("a panicking checker withholds, logged as an error", func(t *testing.T) {
		svc, buf := gateSvc(t, trustedCfg(), checkerFunc(func(context.Context, agentstatus.Subject) error {
			panic("checker bug")
		}))
		var rep *entityresolutionV2.EntityRepresentation
		require.NotPanics(t, func() { rep = resolveSubject(t, svc, chainsFor(t, svc, agentToken(t, issuer))) })
		assertWithheld(t, rep)
		rec := withheldRecord(t, buf)
		assert.Equal(t, "ERROR", rec["level"])
		assert.Equal(t, reasonCheckerPanicked, rec["reason"])
		assert.Contains(t, rec["cause"], "checker bug")
	})
	t.Run("an error that is not a DenialError still withholds", func(t *testing.T) {
		svc, buf := gateSvc(t, trustedCfg(), &fakeChecker{err: errors.New("checker broke")})
		assertWithheld(t, resolveSubject(t, svc, chainsFor(t, svc, agentToken(t, issuer))))
		assert.Equal(t, "checker broke", withheldRecord(t, buf)["reason"])
	})
	t.Run("misconfigured status client is logged as an error", func(t *testing.T) {
		svc, buf := gateSvc(t, trustedCfg(), &fakeChecker{err: &agentstatus.DenialError{Reason: agentstatus.ReasonStatusForbidden}})
		assertWithheld(t, resolveSubject(t, svc, chainsFor(t, svc, agentToken(t, issuer))))
		assert.Equal(t, "ERROR", withheldRecord(t, buf)["level"])
	})
	t.Run("Check gets the caller's context", func(t *testing.T) {
		type probe struct{}
		var got any
		svc, _ := gateSvc(t, trustedCfg(), checkerFunc(func(ctx context.Context, _ agentstatus.Subject) error {
			got = ctx.Value(probe{})
			return nil
		}))
		ents := chainsFor(t, svc, agentToken(t, issuer))
		ctx := context.WithValue(t.Context(), probe{}, "caller")
		_, err := svc.ResolveEntities(ctx, connect.NewRequest(&entityresolutionV2.ResolveEntitiesRequest{Entities: ents}))
		require.NoError(t, err)
		assert.Equal(t, "caller", got)
	})
}

// fakeIdentity is authnz-rs as the real agentstatus.Client sees it.
type fakeIdentity struct {
	calls  atomic.Int32
	mu     sync.Mutex
	status map[string]any
	hang   bool
}

func (f *fakeIdentity) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	f.calls.Add(1)
	switch {
	case r.Method == http.MethodPost && r.URL.Path == "/oauth/token":
		_ = json.NewEncoder(w).Encode(map[string]any{"access_token": statusServiceToken, "token_type": "Bearer", "expires_in": 3600})
	case r.Method == http.MethodGet && strings.HasPrefix(r.URL.Path, "/agents/workloads/"):
		if f.hang {
			<-r.Context().Done()
			return
		}
		f.mu.Lock()
		defer f.mu.Unlock()
		_ = json.NewEncoder(w).Encode(f.status)
	default:
		http.NotFound(w, r)
	}
}

func eligibleStatus() map[string]any {
	return map[string]any{
		"workload": testWorkload, "owner": testOwner, "current_did": testAgentDID, "swarm": testSwarm,
		"state": "eligible", "generation": 3, "incident": nil,
		"valid_until": time.Now().Add(5 * time.Second).Unix(),
	}
}

func realClient(t *testing.T, h http.Handler, timeout time.Duration) (*agentstatus.Client, *httptest.Server) {
	t.Helper()
	srv := httptest.NewServer(h)
	t.Cleanup(srv.Close)
	c, err := agentstatus.New(agentstatus.Config{URL: srv.URL, ClientID: "opentdf", ClientSecret: statusClientSecret, Timeout: timeout})
	require.NoError(t, err)
	return c, srv
}

func TestAgentGate_RealStatusClient(t *testing.T) {
	t.Run("eligible: one token and one status call, then the lease is reused", func(t *testing.T) {
		f := &fakeIdentity{status: eligibleStatus()}
		c, _ := realClient(t, f, time.Second)
		svc, _ := gateSvc(t, trustedCfg(), c)
		ents := chainsFor(t, svc, agentCWT(t, issuer))
		assert.Len(t, resolveSubject(t, svc, ents).GetDirectEntitlements(), 2)
		assert.Len(t, resolveSubject(t, svc, ents).GetDirectEntitlements(), 2)
		assert.Equal(t, int32(2), f.calls.Load())
	})
	t.Run("quarantined: withheld with generation and incident, no secret logged", func(t *testing.T) {
		st := eligibleStatus()
		st["state"], st["generation"], st["incident"] = "quarantined", 4, "inc-9"
		f := &fakeIdentity{status: st}
		c, _ := realClient(t, f, time.Second)
		svc, buf := gateSvc(t, trustedCfg(), c)
		tok := agentCWT(t, issuer)
		assertWithheld(t, resolveSubject(t, svc, chainsFor(t, svc, tok)))
		rec := withheldRecord(t, buf)
		assert.Equal(t, agentstatus.ReasonNotEligible, rec["reason"])
		assert.Equal(t, "inc-9", rec["incident"])
		for _, secret := range []string{tok, statusClientSecret, statusServiceToken} {
			assert.NotContains(t, buf.String(), secret)
		}
	})
	t.Run("identity unreachable: withheld, and the resolution still succeeds", func(t *testing.T) {
		c, srv := realClient(t, &fakeIdentity{status: eligibleStatus()}, time.Second)
		srv.Close()
		svc, buf := gateSvc(t, trustedCfg(), c)
		assertWithheld(t, resolveSubject(t, svc, chainsFor(t, svc, agentToken(t, issuer))))
		assert.Equal(t, agentstatus.ReasonUnreachable, withheldRecord(t, buf)["reason"])
	})
	t.Run("a hanging status endpoint is withheld within the client's bound", func(t *testing.T) {
		c, _ := realClient(t, &fakeIdentity{status: eligibleStatus(), hang: true}, 50*time.Millisecond)
		svc, buf := gateSvc(t, trustedCfg(), c)
		start := time.Now()
		assertWithheld(t, resolveSubject(t, svc, chainsFor(t, svc, agentToken(t, issuer))))
		assert.Less(t, time.Since(start), time.Second)
		assert.Equal(t, agentstatus.ReasonUnreachable, withheldRecord(t, buf)["reason"])
	})
	for name, tc := range map[string]struct {
		mutate func(map[string]interface{})
		reason string
	}{
		"pre-workload agent token":  {func(c map[string]interface{}) { delete(c, "arkavo_workload") }, agentstatus.ReasonMissingWorkload},
		"agent token without swarm": {func(c map[string]interface{}) { delete(c, "arkavo_swarm") }, agentstatus.ReasonMissingSwarm},
		"malformed workload id":     {func(c map[string]interface{}) { c["arkavo_workload"] = "wl-XYZ" }, agentstatus.ReasonMalformedWorkload},
	} {
		t.Run(name+": withheld without calling identity", func(t *testing.T) {
			f := &fakeIdentity{status: eligibleStatus()}
			c, _ := realClient(t, f, time.Second)
			svc, buf := gateSvc(t, trustedCfg(), c)
			assertWithheld(t, resolveSubject(t, svc, chainsFor(t, svc, tokenWith(t, tc.mutate))))
			assert.Equal(t, int32(0), f.calls.Load())
			assert.Equal(t, tc.reason, withheldRecord(t, buf)["reason"])
		})
	}
}
