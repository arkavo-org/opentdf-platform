package access

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"

	"connectrpc.com/connect"
	"github.com/google/uuid"
	"github.com/lestrrat-go/jwx/v2/jwt"
	"github.com/opentdf/platform/lib/ocrypto"
	kaspb "github.com/opentdf/platform/protocol/go/kas"
	"github.com/opentdf/platform/service/internal/security"
	"github.com/opentdf/platform/service/logger"
	"github.com/opentdf/platform/service/logger/audit"
	ctxAuth "github.com/opentdf/platform/service/pkg/auth"
	"github.com/opentdf/platform/service/trust"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const (
	sharedPolicyID = "policy-shared"
	kasTestKID     = "r1"
)

// countingKeyManager counts every unwrap of a KAO's key.
type countingKeyManager struct {
	trust.KeyService
	decrypts atomic.Int32
}

func (c *countingKeyManager) Decrypt(ctx context.Context, key trust.KeyDetails, ciphertext, ephemeral []byte) (ocrypto.ProtectedKey, error) {
	c.decrypts.Add(1)
	return c.KeyService.Decrypt(ctx, key, ciphertext, ephemeral)
}

// newAuditBufferLogger is newBufferLogger with an audit logger, so paths
// that audit a rewrap do not dereference a nil Audit.
func newAuditBufferLogger() (*logger.Logger, *bytes.Buffer) {
	buf := &bytes.Buffer{}
	base := slog.New(slog.NewJSONHandler(buf, &slog.HandlerOptions{Level: slog.LevelDebug}))
	return &logger.Logger{Logger: base, Audit: audit.CreateAuditLogger(*base)}, buf
}

// releasingProvider is a KAS that really unwraps and releases: an in-process
// RSA key, so a test can tell a released key from a refused one.
func releasingProvider(t *testing.T) (*Provider, *countingKeyManager, *bytes.Buffer) {
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
	return &Provider{Logger: log, KeyDelegator: d}, km, buf
}

func policyBytes(t *testing.T, pol *Policy) []byte {
	t.Helper()
	data, err := json.Marshal(pol)
	require.NoError(t, err)
	return []byte(base64.StdEncoding.EncodeToString(data))
}

// releasableRequest carries a policy without data attributes (released
// without an authorization round trip) and KAOs wrapped to kasTestKID with a
// valid policy binding.
func releasableRequest(t *testing.T, policyID string, kaoIDs ...string) *kaspb.UnsignedRewrapRequest_WithPolicyRequest {
	t.Helper()
	return requestWithBody(t, policyBytes(t, &Policy{UUID: uuid.New()}), policyID, kaoIDs...)
}

// requestWithBody is releasableRequest for a given base64 policy body; the
// binding is computed over that body.
func requestWithBody(t *testing.T, policyBody []byte, policyID string, kaoIDs ...string) *kaspb.UnsignedRewrapRequest_WithPolicyRequest {
	t.Helper()
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

// rewrapAudited runs tdf3Rewrap for a bearer with sub inside the audit
// interceptor, so the audit events it records are flushed to the log.
func rewrapAudited(t *testing.T, p *Provider, sub string, reqs []*kaspb.UnsignedRewrapRequest_WithPolicyRequest) policyKAOResults {
	t.Helper()
	bearer := jwt.New()
	require.NoError(t, bearer.Set(jwt.SubjectKey, sub))
	ctx := ctxAuth.ContextWithAuthNInfo(t.Context(), nil, bearer, "raw-bearer")
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

// rewrapAuditCounts counts the rewrap audit records by outcome.
func rewrapAuditCounts(t *testing.T, buf *bytes.Buffer) (int, int) {
	t.Helper()
	var success, failure int
	for _, line := range strings.Split(strings.TrimSpace(buf.String()), "\n") {
		if line == "" {
			continue
		}
		var rec map[string]any
		require.NoError(t, json.Unmarshal([]byte(line), &rec))
		if rec["msg"] != string(audit.VerbRewrap) {
			continue
		}
		a, ok := rec["audit"].(map[string]any)
		require.True(t, ok)
		action, ok := a["action"].(map[string]any)
		require.True(t, ok)
		switch action["result"] {
		case audit.ActionResultSuccess.String():
			success++
		case audit.ActionResultError.String():
			failure++
		}
	}
	return success, failure
}

// assertBadRequest checks every KAO result under policyID is the generic 400
// and carries no key.
func assertBadRequest(t *testing.T, results policyKAOResults, policyID string, wantKAOs int) {
	t.Helper()
	byKAO, ok := results[policyID]
	require.True(t, ok, "policy %s has results", policyID)
	require.Len(t, byKAO, wantKAOs)
	for id, r := range byKAO {
		require.Error(t, r.Error, id)
		assert.Equal(t, connect.CodeInvalidArgument, connect.CodeOf(r.Error), id)
		assert.Contains(t, r.Error.Error(), "bad request", id)
		assert.Empty(t, r.Encapped, id)
	}
}

// Two requests share a policy Id with different bodies. Results are keyed by
// policy Id, so the KAS cannot answer both; every KAO of both is refused
// before any unwrap, in either order and whether or not the KAO ids collide.
func TestTDF3Rewrap_DuplicatePolicyIDRefused(t *testing.T) {
	first := policyBytes(t, &Policy{UUID: uuid.New()})
	second := policyBytes(t, &Policy{UUID: uuid.New(), Body: PolicyBody{Dissem: []string{"someone-else"}}})
	for _, tt := range []struct {
		name     string
		a, b     []byte
		kaoIDs   [2]string
		wantKAOs int
	}{
		{"first body first, distinct KAO ids", first, second, [2]string{"kao-1", "kao-2"}, 2},
		{"second body first, distinct KAO ids", second, first, [2]string{"kao-1", "kao-2"}, 2},
		{"first body first, same KAO id", first, second, [2]string{"kao-1", "kao-1"}, 1},
		{"second body first, same KAO id", second, first, [2]string{"kao-1", "kao-1"}, 1},
	} {
		t.Run(tt.name, func(t *testing.T) {
			p, km, buf := releasingProvider(t)
			reqs := []*kaspb.UnsignedRewrapRequest_WithPolicyRequest{
				requestWithBody(t, tt.a, sharedPolicyID, tt.kaoIDs[0]),
				requestWithBody(t, tt.b, sharedPolicyID, tt.kaoIDs[1]),
			}
			var results policyKAOResults
			require.NotPanics(t, func() { results = rewrapAudited(t, p, "user-1", reqs) })
			require.Len(t, results, 1)
			assertBadRequest(t, results, sharedPolicyID, tt.wantKAOs)
			assert.Equal(t, int32(0), km.decrypts.Load(), "a duplicate policy Id must be refused before unwrap")
			success, failure := rewrapAuditCounts(t, buf)
			assert.Equal(t, 0, success)
			assert.Equal(t, 2, failure, "each refused KAO is audited")
		})
	}
}

// Only the requests that share an Id are refused; a unique one alongside
// them is released as usual.
func TestTDF3Rewrap_DuplicatePolicyIDDoesNotAffectUniqueIDs(t *testing.T) {
	p, km, _ := releasingProvider(t)
	reqs := []*kaspb.UnsignedRewrapRequest_WithPolicyRequest{
		releasableRequest(t, sharedPolicyID, "kao-d1"),
		releasableRequest(t, "policy-unique", "kao-u1", "kao-u2"),
		releasableRequest(t, sharedPolicyID, "kao-d2"),
	}
	var results policyKAOResults
	require.NotPanics(t, func() { results = rewrapAudited(t, p, "user-1", reqs) })
	require.Len(t, results, 2)
	assertBadRequest(t, results, sharedPolicyID, 2)
	require.Len(t, results["policy-unique"], 2)
	for id, r := range results["policy-unique"] {
		require.NoError(t, r.Error, id)
		assert.NotEmpty(t, r.Encapped, id)
	}
	assert.Equal(t, int32(2), km.decrypts.Load(), "only the unique policy's KAOs are unwrapped")
}

// Requests without a policy Id are not duplicates of each other: they pass
// through to tdf3Rewrap's own handling, as before.
func TestRefuseDuplicatePolicyIDs_EmptyIDsPassThrough(t *testing.T) {
	p, _, _ := releasingProvider(t)
	reqs := []*kaspb.UnsignedRewrapRequest_WithPolicyRequest{
		releasableRequest(t, "", "kao-1"),
		releasableRequest(t, "", "kao-2"),
		releasableRequest(t, "policy-a", "kao-3"),
	}
	results := make(policyKAOResults)
	assert.Equal(t, reqs, p.refuseDuplicatePolicyIDs(t.Context(), reqs, results))
	assert.Empty(t, results)
}
