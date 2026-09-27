package access

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"connectrpc.com/connect"
	"github.com/lestrrat-go/jwx/v2/jwk"
	"github.com/lestrrat-go/jwx/v2/jwt"
	"github.com/opentdf/platform/lib/ocrypto"
	kaspb "github.com/opentdf/platform/protocol/go/kas"
	"github.com/opentdf/platform/service/internal/agentstatus"
	"github.com/opentdf/platform/service/internal/security"
	"github.com/opentdf/platform/service/logger"
	"github.com/opentdf/platform/service/logger/audit"
	ctxAuth "github.com/opentdf/platform/service/pkg/auth"
	"github.com/opentdf/platform/service/trust"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const (
	agentDID      = "did:key:z6MkAgentExample"
	agentOwner    = "00000000-0000-0000-0000-000000000001"
	agentWorkload = "wl-00112233445566778899aabbccddeeff"
	agentSwarm    = "kit-42"
	agentRawCWT   = "raw-agent-cwt-must-never-be-logged"

	statusClientID     = "opentdf"
	statusClientSecret = "status-client-secret-never-logged"
	statusServiceToken = "svc-cwt-never-logged"

	kasTestKID = "r1"
)

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

func agentClaims() map[string]any {
	return map[string]any{
		jwt.SubjectKey:        agentDID,
		"arkavo_npe":          map[string]any{"type": "agent", "delegation_id": agentDID, "depth": 0, "chain": []any{}},
		"arkavo_roles":        []any{"agent"},
		"arkavo_account_id":   agentOwner,
		"arkavo_workload":     agentWorkload,
		"arkavo_swarm":        agentSwarm,
		"arkavo_entitlements": []any{"https://arkavo.ai/attr/tdf/value/decrypt"},
	}
}

func tokenWith(t *testing.T, claims map[string]any) jwt.Token {
	t.Helper()
	tok := jwt.New()
	for k, v := range claims {
		require.NoError(t, tok.Set(k, v))
	}
	return tok
}

func agentToken(t *testing.T) jwt.Token { t.Helper(); return tokenWith(t, agentClaims()) }

// wantSubject is what agentFromToken must read from agentToken.
func wantSubject() agentstatus.Subject {
	return agentstatus.Subject{DID: agentDID, Owner: agentOwner, Workload: agentWorkload, Swarm: agentSwarm}
}

func agentDPoPKey(t *testing.T) jwk.Key {
	t.Helper()
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	key, err := jwk.FromRaw(pub)
	require.NoError(t, err)
	return key
}

func newTestLogger() *logger.Logger { l, _ := newAuditBufferLogger(); return l }

// newAuditBufferLogger is newBufferLogger with an audit logger, so paths
// that audit a rewrap do not dereference a nil Audit.
func newAuditBufferLogger() (*logger.Logger, *bytes.Buffer) {
	buf := &bytes.Buffer{}
	base := slog.New(slog.NewJSONHandler(buf, &slog.HandlerOptions{Level: slog.LevelDebug}))
	return &logger.Logger{Logger: base, Audit: audit.CreateAuditLogger(*base)}, buf
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

// deniedRecord is the single gate denial the buffer holds.
func deniedRecord(t *testing.T, buf *bytes.Buffer) map[string]any {
	t.Helper()
	var found map[string]any
	for _, rec := range logRecords(t, buf) {
		if rec["msg"] == agentDeniedMsg {
			require.Nil(t, found, "more than one denial record")
			found = rec
		}
	}
	require.NotNil(t, found, "no denial record")
	return found
}

func TestAgentFromToken(t *testing.T) {
	with := func(mutate func(map[string]any)) map[string]any {
		c := agentClaims()
		mutate(c)
		return c
	}
	tests := []struct {
		name   string
		claims map[string]any
		want   *agentstatus.Subject
	}{
		{name: "agent token", claims: agentClaims(), want: func() *agentstatus.Subject { s := wantSubject(); return &s }()},
		{name: "human token", claims: map[string]any{jwt.SubjectKey: agentOwner, "arkavo_roles": []any{"user"}, "arkavo_account_id": agentOwner}},
		{name: "oidc token without arkavo claims", claims: map[string]any{jwt.SubjectKey: "testuser1"}},
		{name: "device token", claims: map[string]any{jwt.SubjectKey: agentOwner, "arkavo_npe": map[string]any{"type": "device", "class": "attested"}}},
		{
			name:   "agent markers without arkavo_workload (pre-workload token)",
			claims: with(func(c map[string]any) { delete(c, "arkavo_workload") }),
			want:   &agentstatus.Subject{DID: agentDID, Owner: agentOwner, Swarm: agentSwarm},
		},
		{
			name:   "agent markers without arkavo_swarm",
			claims: with(func(c map[string]any) { delete(c, "arkavo_swarm") }),
			want:   &agentstatus.Subject{DID: agentDID, Owner: agentOwner, Workload: agentWorkload},
		},
		{
			name:   "arkavo_workload alone",
			claims: map[string]any{jwt.SubjectKey: agentOwner, "arkavo_workload": agentWorkload},
			want:   &agentstatus.Subject{DID: agentOwner, Workload: agentWorkload},
		},
		{
			name:   "arkavo_swarm alone",
			claims: map[string]any{jwt.SubjectKey: agentOwner, "arkavo_swarm": agentSwarm},
			want:   &agentstatus.Subject{DID: agentOwner, Swarm: agentSwarm},
		},
		{
			name:   "agent role without arkavo_npe",
			claims: map[string]any{jwt.SubjectKey: agentDID, "arkavo_roles": []any{"user", "agent"}},
			want:   &agentstatus.Subject{DID: agentDID},
		},
		{
			name:   "agent role as a bare string",
			claims: map[string]any{jwt.SubjectKey: agentDID, "arkavo_roles": "agent"},
			want:   &agentstatus.Subject{DID: agentDID},
		},
		{
			name:   "device npe also carrying arkavo_workload",
			claims: map[string]any{jwt.SubjectKey: agentOwner, "arkavo_npe": map[string]any{"type": "device"}, "arkavo_workload": agentWorkload},
			want:   &agentstatus.Subject{DID: agentOwner, Workload: agentWorkload},
		},
		{
			name:   "arkavo_npe that is not a map",
			claims: map[string]any{jwt.SubjectKey: agentDID, "arkavo_npe": "agent"},
			want:   &agentstatus.Subject{DID: agentDID},
		},
		{
			name:   "arkavo_npe without a type",
			claims: map[string]any{jwt.SubjectKey: agentDID, "arkavo_npe": map[string]any{"delegation_id": agentDID}},
			want:   &agentstatus.Subject{DID: agentDID},
		},
		{
			name:   "arkavo_npe with a non-string type",
			claims: map[string]any{jwt.SubjectKey: agentDID, "arkavo_npe": map[string]any{"type": 7}},
			want:   &agentstatus.Subject{DID: agentDID},
		},
		{
			name:   "arkavo_npe with an unknown type",
			claims: map[string]any{jwt.SubjectKey: agentDID, "arkavo_npe": map[string]any{"type": "service"}},
			want:   &agentstatus.Subject{DID: agentDID},
		},
		{
			name: "non-string agent claims read as absent",
			claims: with(func(c map[string]any) {
				c["arkavo_workload"] = 12
				c["arkavo_swarm"] = []any{agentSwarm}
				c["arkavo_account_id"] = true
			}),
			want: &agentstatus.Subject{DID: agentDID},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := agentFromToken(tokenWith(t, tt.claims))
			if tt.want == nil {
				assert.Nil(t, got)
				return
			}
			require.NotNil(t, got, "a token carrying any agent marker must be gated")
			assert.Equal(t, *tt.want, *got)
		})
	}
}

func TestGetEntityInfo_RecognisesAgent(t *testing.T) {
	ctx := ctxAuth.ContextWithAuthNInfo(t.Context(), agentDPoPKey(t), agentToken(t), agentRawCWT)
	info, err := getEntityInfo(ctx, newTestLogger())
	require.NoError(t, err)
	require.NotNil(t, info.Agent)
	assert.Equal(t, wantSubject(), *info.Agent)

	human := tokenWith(t, map[string]any{jwt.SubjectKey: agentOwner})
	info, err = getEntityInfo(ctxAuth.ContextWithAuthNInfo(t.Context(), nil, human, "raw-human"), newTestLogger())
	require.NoError(t, err)
	assert.Nil(t, info.Agent)
}

func agentCtx(t *testing.T, key jwk.Key) context.Context {
	t.Helper()
	return ctxAuth.ContextWithAuthNInfo(t.Context(), key, agentToken(t), agentRawCWT)
}

func TestAgentReleaseDenied(t *testing.T) {
	t.Run("quarantined workload is denied and the incident logged", func(t *testing.T) {
		log, buf := newAuditBufferLogger()
		checker := &fakeChecker{err: &agentstatus.DenialError{Reason: agentstatus.ReasonNotEligible, Workload: agentWorkload, Generation: 4, Incident: "inc-9"}}
		p := &Provider{Logger: log, AgentStatus: checker}
		s := wantSubject()

		assert.True(t, p.agentReleaseDenied(agentCtx(t, agentDPoPKey(t)), &s))

		assert.Equal(t, 1, checker.callCount())
		assert.Equal(t, wantSubject(), checker.got)
		rec := deniedRecord(t, buf)
		assert.Equal(t, "WARN", rec["level"])
		assert.Equal(t, agentstatus.ReasonNotEligible, rec["reason"])
		assert.Equal(t, "inc-9", rec["incident"])
		assert.InDelta(t, 4, rec["generation"], 0)
		assert.Equal(t, agentWorkload, rec["workload"])
		assert.Equal(t, agentDID, rec["agent"])
		assert.Equal(t, agentOwner, rec["owner"])
		assert.Equal(t, agentSwarm, rec["swarm"])
		assert.NotContains(t, buf.String(), agentRawCWT)
	})

	t.Run("no DPoP key in context: denied without asking status", func(t *testing.T) {
		log, buf := newAuditBufferLogger()
		checker := &fakeChecker{}
		p := &Provider{Logger: log, AgentStatus: checker}
		s := wantSubject()
		assert.True(t, p.agentReleaseDenied(agentCtx(t, nil), &s))
		assert.Equal(t, 0, checker.callCount())
		assert.Equal(t, reasonNoProofOfPossession, deniedRecord(t, buf)["reason"])
	})

	t.Run("nil checker: denied as unconfigured, logged as an error", func(t *testing.T) {
		log, buf := newAuditBufferLogger()
		p := &Provider{Logger: log}
		s := wantSubject()
		assert.True(t, p.agentReleaseDenied(agentCtx(t, agentDPoPKey(t)), &s))
		rec := deniedRecord(t, buf)
		assert.Equal(t, "ERROR", rec["level"])
		assert.Equal(t, agentstatus.ReasonUnconfigured, rec["reason"])
	})

	t.Run("status client not allowlisted (403): denied and logged as a misconfiguration", func(t *testing.T) {
		log, buf := newAuditBufferLogger()
		checker := &fakeChecker{err: &agentstatus.DenialError{Reason: agentstatus.ReasonStatusForbidden, Workload: agentWorkload}}
		p := &Provider{Logger: log, AgentStatus: checker}
		s := wantSubject()
		assert.True(t, p.agentReleaseDenied(agentCtx(t, agentDPoPKey(t)), &s))
		rec := deniedRecord(t, buf)
		assert.Equal(t, "ERROR", rec["level"])
		assert.Equal(t, agentstatus.ReasonStatusForbidden, rec["reason"])
	})

	t.Run("an error that is not a DenialError still denies", func(t *testing.T) {
		log, buf := newAuditBufferLogger()
		p := &Provider{Logger: log, AgentStatus: &fakeChecker{err: errors.New("checker broke")}}
		s := wantSubject()
		assert.True(t, p.agentReleaseDenied(agentCtx(t, agentDPoPKey(t)), &s))
		assert.Equal(t, "checker broke", deniedRecord(t, buf)["reason"])
	})

	t.Run("eligible agent is not denied and nothing is logged", func(t *testing.T) {
		log, buf := newAuditBufferLogger()
		checker := &fakeChecker{}
		p := &Provider{Logger: log, AgentStatus: checker}
		s := wantSubject()
		assert.False(t, p.agentReleaseDenied(agentCtx(t, agentDPoPKey(t)), &s))
		assert.Equal(t, 1, checker.callCount())
		assert.NotContains(t, buf.String(), agentDeniedMsg)
	})

	t.Run("Check runs under a deadline no later than agentStatusDeadline", func(t *testing.T) {
		var deadline time.Time
		var had bool
		p := &Provider{Logger: newTestLogger(), AgentStatus: checkerFunc(func(ctx context.Context, _ agentstatus.Subject) error {
			deadline, had = ctx.Deadline()
			return nil
		})}
		s := wantSubject()
		start := time.Now()
		assert.False(t, p.agentReleaseDenied(agentCtx(t, agentDPoPKey(t)), &s))
		require.True(t, had)
		assert.WithinDuration(t, start.Add(agentStatusDeadline), deadline, time.Second)
	})
}

type checkerFunc func(context.Context, agentstatus.Subject) error

func (f checkerFunc) Check(ctx context.Context, s agentstatus.Subject) error { return f(ctx, s) }

// fakeIdentity is authnz-rs as the real agentstatus.Client sees it: the token
// and status bodies are written in authnz-rs's JSON shape.
type fakeIdentity struct {
	calls  atomic.Int32
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
		_ = json.NewEncoder(w).Encode(f.status)
	default:
		http.NotFound(w, r)
	}
}

func eligibleStatus() map[string]any {
	return map[string]any{
		"workload":    agentWorkload,
		"owner":       agentOwner,
		"current_did": agentDID,
		"swarm":       agentSwarm,
		"state":       "eligible",
		"generation":  3,
		"incident":    nil,
		"valid_until": time.Now().Add(5 * time.Second).Unix(),
	}
}

func realChecker(t *testing.T, f *fakeIdentity, timeout time.Duration) agentstatus.Checker {
	t.Helper()
	srv := httptest.NewServer(f)
	t.Cleanup(srv.Close)
	c, err := agentstatus.New(agentstatus.Config{URL: srv.URL, ClientID: statusClientID, ClientSecret: statusClientSecret, Timeout: timeout})
	require.NoError(t, err)
	return c
}

func TestAgentReleaseDenied_RealStatusClient(t *testing.T) {
	t.Run("pre-workload agent token is denied without calling identity", func(t *testing.T) {
		f := &fakeIdentity{status: eligibleStatus()}
		log, buf := newAuditBufferLogger()
		p := &Provider{Logger: log, AgentStatus: realChecker(t, f, time.Second)}
		s := wantSubject()
		s.Workload = ""
		assert.True(t, p.agentReleaseDenied(agentCtx(t, agentDPoPKey(t)), &s))
		assert.Equal(t, int32(0), f.calls.Load())
		assert.Equal(t, agentstatus.ReasonMissingWorkload, deniedRecord(t, buf)["reason"])
	})

	t.Run("agent token without arkavo_swarm is denied without calling identity", func(t *testing.T) {
		f := &fakeIdentity{status: eligibleStatus()}
		log, buf := newAuditBufferLogger()
		p := &Provider{Logger: log, AgentStatus: realChecker(t, f, time.Second)}
		s := wantSubject()
		s.Swarm = ""
		assert.True(t, p.agentReleaseDenied(agentCtx(t, agentDPoPKey(t)), &s))
		assert.Equal(t, int32(0), f.calls.Load())
		assert.Equal(t, agentstatus.ReasonMissingSwarm, deniedRecord(t, buf)["reason"])
	})

	t.Run("eligible status releases", func(t *testing.T) {
		f := &fakeIdentity{status: eligibleStatus()}
		p := &Provider{Logger: newTestLogger(), AgentStatus: realChecker(t, f, time.Second)}
		s := wantSubject()
		assert.False(t, p.agentReleaseDenied(agentCtx(t, agentDPoPKey(t)), &s))
		assert.Equal(t, int32(2), f.calls.Load(), "one token and one status call")
	})

	t.Run("quarantined status is denied with its generation and incident, secrets not logged", func(t *testing.T) {
		st := eligibleStatus()
		st["state"] = "quarantined"
		st["generation"] = 4
		st["incident"] = "inc-9"
		f := &fakeIdentity{status: st}
		log, buf := newAuditBufferLogger()
		p := &Provider{Logger: log, AgentStatus: realChecker(t, f, time.Second)}
		s := wantSubject()
		assert.True(t, p.agentReleaseDenied(agentCtx(t, agentDPoPKey(t)), &s))
		rec := deniedRecord(t, buf)
		assert.Equal(t, agentstatus.ReasonNotEligible, rec["reason"])
		assert.Equal(t, "inc-9", rec["incident"])
		assert.InDelta(t, 4, rec["generation"], 0)
		for _, secret := range []string{agentRawCWT, statusClientSecret, statusServiceToken} {
			assert.NotContains(t, buf.String(), secret)
		}
	})

	t.Run("a hanging status endpoint is denied within agentStatusDeadline", func(t *testing.T) {
		f := &fakeIdentity{status: eligibleStatus(), hang: true}
		log, buf := newAuditBufferLogger()
		// A per-call timeout far beyond the gate's bound, so only the gate's
		// own deadline can end the wait.
		p := &Provider{Logger: log, AgentStatus: realChecker(t, f, time.Minute)}
		s := wantSubject()
		start := time.Now()
		assert.True(t, p.agentReleaseDenied(agentCtx(t, agentDPoPKey(t)), &s))
		elapsed := time.Since(start)
		assert.GreaterOrEqual(t, elapsed, agentStatusDeadline-100*time.Millisecond)
		assert.Less(t, elapsed, agentStatusDeadline+time.Second)
		assert.Equal(t, agentstatus.ReasonUnreachable, deniedRecord(t, buf)["reason"])
	})
}

// countingKeyManager counts every unwrap of a KAO's key.
type countingKeyManager struct {
	trust.KeyService
	decrypts atomic.Int32
}

func (c *countingKeyManager) Decrypt(ctx context.Context, key trust.KeyDetails, ciphertext, ephemeral []byte) (ocrypto.ProtectedKey, error) {
	c.decrypts.Add(1)
	return c.KeyService.Decrypt(ctx, key, ciphertext, ephemeral)
}

// releasingProvider is a KAS that really unwraps and releases: an in-process
// RSA key, so a test can tell a released key from a refused one.
func releasingProvider(t *testing.T, checker agentstatus.Checker) (*Provider, *countingKeyManager, *bytes.Buffer) {
	t.Helper()
	dir := t.TempDir()
	private := filepath.Join(dir, "kas-private.pem")
	public := filepath.Join(dir, "kas-public.pem")
	require.NoError(t, os.WriteFile(private, []byte(rsaPrivate), 0o600))
	require.NoError(t, os.WriteFile(public, []byte(rsaPublic), 0o600))
	sc, err := security.NewStandardCrypto(security.StandardConfig{Keys: []security.KeyPairInfo{
		{Algorithm: security.AlgorithmRSA2048, KID: kasTestKID, Private: private, Certificate: public},
	}})
	require.NoError(t, err)
	svc := security.NewSecurityProviderAdapter(sc, []string{kasTestKID}, nil)
	km := &countingKeyManager{KeyService: svc}
	log, buf := newAuditBufferLogger()
	d := trust.NewDelegatingKeyService(svc, log, nil)
	d.RegisterKeyManagerCtx(svc.Name(), func(context.Context, *trust.KeyManagerFactoryOptions) (trust.KeyManager, error) { return km, nil })
	d.SetDefaultMode(svc.Name(), "", nil)
	return &Provider{Logger: log, KeyDelegator: d, AgentStatus: checker}, km, buf
}

// releasableRequest is a policy without data attributes (ABAC releases it
// without an SDK round trip) and KAOs wrapped to kasTestKID with a valid
// policy binding.
func releasableRequest(t *testing.T, policyID string, kaoIDs ...string) *kaspb.UnsignedRewrapRequest_WithPolicyRequest {
	t.Helper()
	policyBody := emptyPolicyBytes()
	asym, err := ocrypto.FromPublicPEM(rsaPublic)
	require.NoError(t, err)
	binding, err := generateHMACDigest(t.Context(), policyBody, []byte(plainKey), *logger.CreateTestLogger())
	require.NoError(t, err)
	req := &kaspb.UnsignedRewrapRequest_WithPolicyRequest{
		Policy:    &kaspb.UnsignedRewrapRequest_WithPolicy{Id: policyID, Body: string(policyBody)},
		Algorithm: kTDF3Algorithm,
	}
	for _, id := range kaoIDs {
		wrapped, err := asym.Encrypt([]byte(plainKey))
		require.NoError(t, err)
		req.KeyAccessObjects = append(req.KeyAccessObjects, &kaspb.UnsignedRewrapRequest_WithKeyAccessObject{
			KeyAccessObjectId: id,
			KeyAccessObject: &kaspb.KeyAccess{
				KeyType:       "wrapped",
				Kid:           kasTestKID,
				WrappedKey:    wrapped,
				PolicyBinding: &kaspb.PolicyBinding{Algorithm: "HS256", Hash: base64.StdEncoding.EncodeToString([]byte(hex.EncodeToString(binding)))},
			},
		})
	}
	return req
}

func twoPolicyRequests(t *testing.T) []*kaspb.UnsignedRewrapRequest_WithPolicyRequest {
	t.Helper()
	return []*kaspb.UnsignedRewrapRequest_WithPolicyRequest{
		releasableRequest(t, "policy-a", "kao-a1", "kao-a2"),
		releasableRequest(t, "policy-b", "kao-b1", "kao-b2"),
	}
}

// rewrapAudited runs tdf3Rewrap inside the audit interceptor, so the audit
// events it records are flushed to the provider's log.
func rewrapAudited(t *testing.T, p *Provider, key jwk.Key, bearer jwt.Token, reqs []*kaspb.UnsignedRewrapRequest_WithPolicyRequest) policyKAOResults {
	t.Helper()
	ctx := ctxAuth.ContextWithAuthNInfo(t.Context(), key, bearer, agentRawCWT)
	info, err := getEntityInfo(ctx, p.Logger)
	require.NoError(t, err)
	var results policyKAOResults
	next := func(ctx context.Context, _ connect.AnyRequest) (connect.AnyResponse, error) {
		_, results, err = p.tdf3Rewrap(ctx, reqs, rsaPublic, info, &AdditionalRewrapContext{})
		return nil, err
	}
	_, callErr := audit.ContextServerInterceptor(p.Logger.Logger)(next)(ctx, connect.NewRequest(&kaspb.RewrapRequest{}))
	require.NoError(t, callErr)
	return results
}

func allKAOs(t *testing.T, results policyKAOResults) []kaoResult {
	t.Helper()
	var out []kaoResult
	for _, byKAO := range results {
		for _, r := range byKAO {
			out = append(out, r)
		}
	}
	require.Len(t, out, 4, "every KAO of both policies has a result")
	return out
}

func assertAllForbidden(t *testing.T, results policyKAOResults) {
	t.Helper()
	for _, r := range allKAOs(t, results) {
		require.Error(t, r.Error, r.ID)
		assert.Equal(t, connect.CodePermissionDenied, connect.CodeOf(r.Error), r.ID)
		assert.Contains(t, r.Error.Error(), "forbidden", r.ID)
		assert.Empty(t, r.Encapped, r.ID)
	}
}

func assertAllReleased(t *testing.T, results policyKAOResults) {
	t.Helper()
	for _, r := range allKAOs(t, results) {
		require.NoError(t, r.Error, r.ID)
		assert.NotEmpty(t, r.Encapped, r.ID)
	}
}

func rewrapAuditResults(t *testing.T, buf *bytes.Buffer) []any {
	t.Helper()
	var out []any
	for _, rec := range logRecords(t, buf) {
		if rec["msg"] != string(audit.VerbRewrap) {
			continue
		}
		a, ok := rec["audit"].(map[string]any)
		require.True(t, ok)
		action, ok := a["action"].(map[string]any)
		require.True(t, ok)
		out = append(out, action["result"])
	}
	return out
}

func TestTDF3Rewrap_AgentGate(t *testing.T) {
	t.Run("denied agent: every KAO forbidden, no key unwrapped, each KAO audited", func(t *testing.T) {
		checker := &fakeChecker{err: &agentstatus.DenialError{Reason: agentstatus.ReasonNotEligible, Workload: agentWorkload, Generation: 4, Incident: "inc-9"}}
		p, km, buf := releasingProvider(t, checker)

		results := rewrapAudited(t, p, agentDPoPKey(t), agentToken(t), twoPolicyRequests(t))

		assertAllForbidden(t, results)
		assert.Equal(t, int32(0), km.decrypts.Load(), "the gate must run before any key is unwrapped")
		assert.Equal(t, 1, checker.callCount(), "one status check per rewrap request")
		audits := rewrapAuditResults(t, buf)
		assert.Len(t, audits, 4)
		for _, r := range audits {
			assert.Equal(t, audit.ActionResultError.String(), r)
		}
		assert.NotContains(t, buf.String(), agentRawCWT)
	})

	t.Run("agent with status unconfigured: every KAO forbidden, no key unwrapped", func(t *testing.T) {
		p, km, buf := releasingProvider(t, nil)
		results := rewrapAudited(t, p, agentDPoPKey(t), agentToken(t), twoPolicyRequests(t))
		assertAllForbidden(t, results)
		assert.Equal(t, int32(0), km.decrypts.Load())
		assert.Equal(t, agentstatus.ReasonUnconfigured, deniedRecord(t, buf)["reason"])
	})

	t.Run("denied agent gets 403 even for a KAO that would fail verification", func(t *testing.T) {
		p, km, _ := releasingProvider(t, &fakeChecker{err: &agentstatus.DenialError{Reason: agentstatus.ReasonNotEligible}})
		reqs := twoPolicyRequests(t)
		reqs[0].KeyAccessObjects[0].KeyAccessObject.PolicyBinding.Hash = base64.StdEncoding.EncodeToString([]byte("tampered"))
		reqs[1].Policy.Body = "not base64 json"
		results := rewrapAudited(t, p, agentDPoPKey(t), agentToken(t), reqs)
		assertAllForbidden(t, results)
		assert.Equal(t, int32(0), km.decrypts.Load())
	})

	t.Run("eligible agent: keys released after one status check", func(t *testing.T) {
		checker := &fakeChecker{}
		p, km, _ := releasingProvider(t, checker)
		results := rewrapAudited(t, p, agentDPoPKey(t), agentToken(t), twoPolicyRequests(t))
		assertAllReleased(t, results)
		assert.Equal(t, int32(4), km.decrypts.Load())
		assert.Equal(t, 1, checker.callCount())
		assert.Equal(t, wantSubject(), checker.got)
	})

	t.Run("non-agent bearer never consults status and is released as before", func(t *testing.T) {
		checker := &fakeChecker{err: &agentstatus.DenialError{Reason: agentstatus.ReasonNotEligible}}
		p, km, buf := releasingProvider(t, checker)
		human := tokenWith(t, map[string]any{jwt.SubjectKey: agentOwner, "arkavo_roles": []any{"user"}})
		results := rewrapAudited(t, p, nil, human, twoPolicyRequests(t))
		assertAllReleased(t, results)
		assert.Equal(t, 0, checker.callCount())
		assert.Equal(t, int32(4), km.decrypts.Load())
		assert.NotContains(t, buf.String(), agentDeniedMsg)
	})

	t.Run("non-agent bearer with status unconfigured is released as before", func(t *testing.T) {
		p, _, _ := releasingProvider(t, nil)
		device := tokenWith(t, map[string]any{jwt.SubjectKey: agentOwner, "arkavo_npe": map[string]any{"type": "device"}})
		assertAllReleased(t, rewrapAudited(t, p, agentDPoPKey(t), device, twoPolicyRequests(t)))
	})

	t.Run("partial agent token (arkavo_workload only) is gated, not treated as human", func(t *testing.T) {
		p, km, _ := releasingProvider(t, nil)
		partial := tokenWith(t, map[string]any{jwt.SubjectKey: agentOwner, "arkavo_workload": agentWorkload})
		assertAllForbidden(t, rewrapAudited(t, p, agentDPoPKey(t), partial, twoPolicyRequests(t)))
		assert.Equal(t, int32(0), km.decrypts.Load())
	})
}
