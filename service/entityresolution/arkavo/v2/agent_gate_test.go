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

	"github.com/opentdf/platform/service/internal/agentstatus"
	"github.com/opentdf/platform/service/logger"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const (
	issuer           = "https://identity.arkavo.net"
	ownerClaim       = "arkavo_account_id"
	testAgentDID     = "did:key:z6Mkagent"
	testOwner        = "00000000-0000-0000-0000-000000000001"
	testStateVersion = 3
	testSwarm        = "kit-42"

	statusClientSecret = "status-client-secret-never-logged"
	statusServiceToken = "svc-cwt-never-logged"

	// testAgentX is the public half of an Ed25519 agent key (base64url).
	testAgentX = "11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo"
)

// testAgentJWK is the agent key as cnf.jwk.
func testAgentJWK() map[string]interface{} {
	return map[string]interface{}{"kty": "OKP", "crv": "Ed25519", "x": testAgentX}
}

// agentClaims is a contract v2 agent token's claims: state version, swarm and
// a cnf that carries the agent key (cnf.jwk), as the CWT verifier renders the
// COSE_Key cnf.
func agentClaims() map[string]interface{} {
	return map[string]interface{}{
		"iss": issuer, "sub": testAgentDID,
		"arkavo_account_id":    testOwner,
		"arkavo_roles":         []interface{}{"agent"},
		"arkavo_entitlements":  []interface{}{"https://arkavo.ai/attr/tdf/value/decrypt", "https://arkavo.ai/attr/action/value/read"},
		"arkavo_npe":           map[string]interface{}{"type": "agent", "delegation_id": testAgentDID, "depth": 0},
		"arkavo_state_version": testStateVersion,
		"arkavo_swarm":         testSwarm,
		"cnf":                  map[string]interface{}{"jwk": testAgentJWK()},
	}
}

func agentClaimsWith(mutate func(map[string]interface{})) map[string]interface{} {
	claims := agentClaims()
	mutate(claims)
	return claims
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

type checkerFunc func(context.Context, agentstatus.Subject) error

func (f checkerFunc) Check(ctx context.Context, s agentstatus.Subject) error { return f(ctx, s) }

func wantSubject() agentstatus.Subject {
	return agentstatus.Subject{DID: testAgentDID, Swarm: testSwarm, Owner: testOwner, StateVersion: testStateVersion}
}

// judge runs AgentDenial on claims and, as the composite does, logs a
// refusal with LogAgentDenial; the log is captured in the returned buffer.
func judge(t *testing.T, checker agentstatus.Checker, claims map[string]any) (*bytes.Buffer, error) {
	t.Helper()
	buf := &bytes.Buffer{}
	log := &logger.Logger{Logger: slog.New(slog.NewJSONHandler(buf, &slog.HandlerOptions{Level: slog.LevelDebug}))}
	subject, err := AgentDenial(t.Context(), checker, claims, ownerClaim)
	if err != nil {
		LogAgentDenial(t.Context(), log, subject, err)
	}
	return buf, err
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

func TestAgentDenial_PersonIsNeverGated(t *testing.T) {
	checker := &fakeChecker{}
	claims := map[string]any{"iss": issuer, "sub": "person", "arkavo_account_id": testOwner}
	_, err := AgentDenial(t.Context(), checker, claims, "arkavo_account_id")
	require.NoError(t, err)
	assert.Zero(t, checker.callCount(), "a person never reaches the status service")

	_, err = AgentDenial(t.Context(), nil, claims, "arkavo_account_id")
	require.NoError(t, err, "a nil checker does not withhold a person")
}

func TestAgentDenial_UnconfiguredWithholdsAgent(t *testing.T) {
	subject, err := AgentDenial(t.Context(), nil, agentClaims(), "arkavo_account_id")
	var d *agentstatus.DenialError
	require.ErrorAs(t, err, &d)
	assert.Equal(t, agentstatus.ReasonUnconfigured, d.Reason)
	assert.Equal(t, wantSubject(), subject)
}

func TestAgentDenial_EligibleAgentAsksTheChecker(t *testing.T) {
	checker := &fakeChecker{}
	subject, err := AgentDenial(t.Context(), checker, agentClaims(), "arkavo_account_id")
	require.NoError(t, err)
	assert.Equal(t, 1, checker.callCount())
	assert.Equal(t, wantSubject(), checker.got)
	assert.Equal(t, wantSubject(), subject)
}

func TestLogAgentDenial_UnconfiguredIsAnError(t *testing.T) {
	buf, err := judge(t, nil, agentClaims())
	require.Error(t, err)
	rec := withheldRecord(t, buf)
	assert.Equal(t, "ERROR", rec["level"])
	assert.Equal(t, agentstatus.ReasonUnconfigured, rec["reason"])
}

func TestLogAgentDenial_NotEligibleRecordsTheStatus(t *testing.T) {
	checker := &fakeChecker{err: &agentstatus.DenialError{Reason: agentstatus.ReasonNotEligible, Agent: testAgentDID, State: "quarantined", StateVersion: 4, Incident: "inc-9"}}
	buf, err := judge(t, checker, agentClaims())
	require.Error(t, err)
	rec := withheldRecord(t, buf)
	assert.Equal(t, "WARN", rec["level"])
	assert.Equal(t, agentstatus.ReasonNotEligible, rec["reason"])
	assert.Equal(t, "inc-9", rec["incident"])
	assert.InDelta(t, 4, rec["state_version"], 0)
	assert.Equal(t, "quarantined", rec["state"])
	assert.InDelta(t, testStateVersion, rec["token_state_version"], 0)
	assert.Equal(t, testAgentDID, rec["agent"])
	assert.Equal(t, testOwner, rec["owner"])
	assert.Equal(t, testSwarm, rec["swarm"])
}

func TestAgentDenial_AgentWithoutKeyCnfIsRefusedWithoutAsking(t *testing.T) {
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
			buf, err := judge(t, checker, agentClaimsWith(mutate))
			require.Error(t, err)
			assert.Equal(t, 0, checker.callCount())
			assert.Equal(t, reasonNotKeyBound, withheldRecord(t, buf)["reason"])
		})
	}
}

// A P-256 agent key (kty EC with x and y) is key-bound too.
func TestAgentDenial_ECKeyCnfIsKeyBound(t *testing.T) {
	checker := &fakeChecker{}
	_, err := judge(t, checker, agentClaimsWith(func(c map[string]interface{}) {
		c["cnf"] = map[string]interface{}{"jwk": map[string]interface{}{"kty": "EC", "crv": "P-256", "x": testAgentX, "y": testAgentX}}
	}))
	require.NoError(t, err)
	assert.Equal(t, 1, checker.callCount())
}

// A person or device subject never reaches the status service: an identity
// outage must not change their decisions.
func TestAgentDenial_PersonAndDeviceNeverAsk(t *testing.T) {
	down := &fakeChecker{err: &agentstatus.DenialError{Reason: agentstatus.ReasonUnreachable}}
	person := map[string]interface{}{
		"iss": issuer, "sub": testOwner,
		"arkavo_roles":        []interface{}{"user"},
		"arkavo_entitlements": []interface{}{"https://arkavo.ai/attr/tdf/value/decrypt"},
	}
	device := map[string]interface{}{
		"iss": issuer, "sub": testOwner,
		"arkavo_npe": map[string]interface{}{"type": "device", "class": "unverified", "device_id": "K1"},
	}
	for _, claims := range []map[string]interface{}{person, device} {
		buf, err := judge(t, down, claims)
		require.NoError(t, err)
		assert.NotContains(t, buf.String(), agentWithheldMsg)
	}
	assert.Equal(t, 0, down.callCount())
}

// Any agent marker gates a subject, and a gated subject that is not an
// arkavo_npe of type agent is refused without asking identity (#45's
// partial-shape fixtures). A subject that looks partly like an agent is
// never judged as a person.
func TestAgentDenial_PartialAgentShapesAreRefused(t *testing.T) {
	base := func() map[string]interface{} {
		return map[string]interface{}{
			"iss": issuer, "sub": testAgentDID,
			"arkavo_account_id":   testOwner,
			"arkavo_entitlements": []interface{}{"https://arkavo.ai/attr/tdf/value/decrypt"},
			"cnf":                 map[string]interface{}{"jwk": testAgentJWK()},
		}
	}
	for name, add := range map[string]map[string]interface{}{
		"arkavo_swarm alone":                         {"arkavo_swarm": testSwarm},
		"agent role without arkavo_npe":              {"arkavo_roles": []interface{}{"user", "agent"}},
		"agent role as a bare string":                {"arkavo_roles": "agent"},
		"device npe also carrying a swarm":           {"arkavo_npe": map[string]interface{}{"type": "device"}, "arkavo_swarm": testSwarm},
		"arkavo_npe that is not an object":           {"arkavo_npe": "agent"},
		"arkavo_npe without a type":                  {"arkavo_npe": map[string]interface{}{"delegation_id": testAgentDID}},
		"arkavo_npe with a non-string type":          {"arkavo_npe": map[string]interface{}{"type": 7}},
		"arkavo_npe with an unknown type":            {"arkavo_npe": map[string]interface{}{"type": "service"}},
		"swarm and state version without arkavo_npe": {"arkavo_state_version": testStateVersion, "arkavo_swarm": testSwarm},
		// arkavo_state_version alone is a marker, whatever its value, so a
		// person-shaped subject carrying it is never judged as a person.
		"arkavo_state_version alone":              {"arkavo_state_version": testStateVersion},
		"arkavo_state_version alone, null":        {"arkavo_state_version": nil},
		"arkavo_state_version alone, zero":        {"arkavo_state_version": 0},
		"arkavo_state_version alone, a string":    {"arkavo_state_version": "3"},
		"arkavo_state_version alone, negative":    {"arkavo_state_version": -1},
		"arkavo_state_version alone, a fraction":  {"arkavo_state_version": 3.5},
		"arkavo_state_version alone, beyond 2^53": {"arkavo_state_version": 1 << 54},
	} {
		t.Run(name, func(t *testing.T) {
			claims := base()
			for k, v := range add {
				claims[k] = v
			}
			checker := &fakeChecker{}
			buf, err := judge(t, checker, claims)
			require.Error(t, err)
			assert.Equal(t, 0, checker.callCount())
			assert.Equal(t, reasonNotAgentProfile, withheldRecord(t, buf)["reason"])
		})
	}
}

// The version reaches the checker from each number shape a subject's claims
// can hold it in: an integer from the CWT verifier, a float64 from structpb.
func TestAgentDenial_StateVersionReachesTheChecker(t *testing.T) {
	for name, v := range map[string]any{
		"int64":   int64(testStateVersion),
		"uint64":  uint64(testStateVersion),
		"float64": float64(testStateVersion),
	} {
		t.Run(name, func(t *testing.T) {
			checker := &fakeChecker{}
			_, err := judge(t, checker, agentClaimsWith(func(c map[string]interface{}) { c["arkavo_state_version"] = v }))
			require.NoError(t, err)
			assert.Equal(t, wantSubject(), checker.got)
		})
	}
}

// An agent whose arkavo_state_version is not a non-negative integer reaches
// the checker with StateVersion 0 (the fake checker is still called once,
// with that zero); checkSubject's own refusal of a zero state_version is
// pinned separately by agentstatus.TestCheckSubject.
func TestAgentDenial_StateVersionThatIsNotOneReachesTheCheckerAsZero(t *testing.T) {
	for name, bad := range map[string]interface{}{
		"a string":                   "3",
		"a fraction":                 3.5,
		"negative":                   -1,
		"2^53":                       1 << 53,
		"beyond 2^53":                1 << 54,
		"an object":                  map[string]interface{}{"v": 3},
		"null":                       nil,
		"zero":                       0,
		"an integer-valued fraction": json.Number("3.0"),
		"an exponent":                json.Number("3e0"),
	} {
		t.Run(name, func(t *testing.T) {
			checker := &fakeChecker{}
			_, _ = judge(t, checker, agentClaimsWith(func(c map[string]interface{}) { c["arkavo_state_version"] = bad }))
			require.Equal(t, 1, checker.callCount())
			assert.Zero(t, checker.got.StateVersion)
		})
	}
}

func TestAgentDenial_OwnerFromTheOwnerClaim(t *testing.T) {
	checker := &fakeChecker{}
	claims := agentClaimsWith(func(c map[string]interface{}) {
		delete(c, "arkavo_account_id")
		c["acct"] = testOwner
	})
	_, err := AgentDenial(t.Context(), checker, claims, "acct")
	require.NoError(t, err)
	assert.Equal(t, testOwner, checker.got.Owner)
}

func TestAgentDenial_CheckerFaults(t *testing.T) {
	t.Run("a panicking checker withholds, logged as an error", func(t *testing.T) {
		panicky := checkerFunc(func(context.Context, agentstatus.Subject) error { panic("checker bug") })
		var buf *bytes.Buffer
		var err error
		require.NotPanics(t, func() { buf, err = judge(t, panicky, agentClaims()) })
		require.Error(t, err)
		rec := withheldRecord(t, buf)
		assert.Equal(t, "ERROR", rec["level"])
		assert.Equal(t, reasonCheckerPanicked, rec["reason"])
		assert.Contains(t, rec["cause"], "checker bug")
	})
	t.Run("an error that is not a DenialError still withholds", func(t *testing.T) {
		buf, err := judge(t, &fakeChecker{err: errors.New("checker broke")}, agentClaims())
		require.Error(t, err)
		assert.Equal(t, "checker broke", withheldRecord(t, buf)["reason"])
	})
	t.Run("misconfigured status client is logged as an error", func(t *testing.T) {
		buf, err := judge(t, &fakeChecker{err: &agentstatus.DenialError{Reason: agentstatus.ReasonStatusForbidden}}, agentClaims())
		require.Error(t, err)
		assert.Equal(t, "ERROR", withheldRecord(t, buf)["level"])
	})
	t.Run("Check gets the caller's context", func(t *testing.T) {
		type probe struct{}
		var got any
		checker := checkerFunc(func(ctx context.Context, _ agentstatus.Subject) error {
			got = ctx.Value(probe{})
			return nil
		})
		ctx := context.WithValue(t.Context(), probe{}, "caller")
		_, err := AgentDenial(ctx, checker, agentClaims(), ownerClaim)
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
	case r.Method == http.MethodGet && strings.HasPrefix(r.URL.Path, "/agents/") && strings.HasSuffix(r.URL.Path, "/status"):
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
		"agent": testAgentDID, "owner": testOwner, "swarm": testSwarm,
		"state": "eligible", "state_version": testStateVersion, "incident": nil,
		"appraised_until": time.Now().Add(15 * time.Minute).Unix(), "appraised_by": "guardian",
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

func TestAgentDenial_RealStatusClient(t *testing.T) {
	t.Run("eligible: one token and one status call, then the lease is reused", func(t *testing.T) {
		f := &fakeIdentity{status: eligibleStatus()}
		c, _ := realClient(t, f, time.Second)
		_, err := judge(t, c, agentClaims())
		require.NoError(t, err)
		_, err = judge(t, c, agentClaims())
		require.NoError(t, err)
		assert.Equal(t, int32(2), f.calls.Load())
	})
	t.Run("quarantined: withheld with state version and incident, no secret logged", func(t *testing.T) {
		st := eligibleStatus()
		st["state"], st["state_version"], st["incident"] = "quarantined", 4, "inc-9"
		f := &fakeIdentity{status: st}
		c, _ := realClient(t, f, time.Second)
		buf, err := judge(t, c, agentClaims())
		require.Error(t, err)
		rec := withheldRecord(t, buf)
		assert.Equal(t, agentstatus.ReasonNotEligible, rec["reason"])
		assert.Equal(t, "inc-9", rec["incident"])
		for _, secret := range []string{statusClientSecret, statusServiceToken} {
			assert.NotContains(t, buf.String(), secret)
		}
	})
	t.Run("identity unreachable: withheld", func(t *testing.T) {
		c, srv := realClient(t, &fakeIdentity{status: eligibleStatus()}, time.Second)
		srv.Close()
		buf, err := judge(t, c, agentClaims())
		require.Error(t, err)
		assert.Equal(t, agentstatus.ReasonUnreachable, withheldRecord(t, buf)["reason"])
	})
	t.Run("a hanging status endpoint is withheld within the client's bound", func(t *testing.T) {
		c, _ := realClient(t, &fakeIdentity{status: eligibleStatus(), hang: true}, 50*time.Millisecond)
		start := time.Now()
		buf, err := judge(t, c, agentClaims())
		require.Error(t, err)
		assert.Less(t, time.Since(start), time.Second)
		assert.Equal(t, agentstatus.ReasonUnreachable, withheldRecord(t, buf)["reason"])
	})
	for name, tc := range map[string]struct {
		mutate func(map[string]interface{})
		reason string
	}{
		"agent token minted before contract v2": {func(c map[string]interface{}) { delete(c, "arkavo_state_version") }, agentstatus.ReasonMissingStateVersion},
		"agent token without swarm":             {func(c map[string]interface{}) { delete(c, "arkavo_swarm") }, agentstatus.ReasonMissingSwarm},
		"sub that is not a did:key":             {func(c map[string]interface{}) { c["sub"] = "did:key:z6Mk/../x" }, agentstatus.ReasonMalformedDID},
	} {
		t.Run(name+": withheld without calling identity", func(t *testing.T) {
			f := &fakeIdentity{status: eligibleStatus()}
			c, _ := realClient(t, f, time.Second)
			buf, err := judge(t, c, agentClaimsWith(tc.mutate))
			require.Error(t, err)
			assert.Equal(t, int32(0), f.calls.Load())
			assert.Equal(t, tc.reason, withheldRecord(t, buf)["reason"])
		})
	}
}
