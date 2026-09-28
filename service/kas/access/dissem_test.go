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
	"strconv"
	"strings"
	"sync"
	"testing"

	"connectrpc.com/connect"
	"github.com/google/uuid"
	"github.com/lestrrat-go/jwx/v2/jwt"
	"github.com/opentdf/platform/lib/ocrypto"
	authzV2 "github.com/opentdf/platform/protocol/go/authorization/v2"
	"github.com/opentdf/platform/protocol/go/entity"
	kaspb "github.com/opentdf/platform/protocol/go/kas"
	otdf "github.com/opentdf/platform/sdk"
	"github.com/opentdf/platform/sdk/sdkconnect"
	"github.com/opentdf/platform/service/internal/security"
	"github.com/opentdf/platform/service/logger"
	"github.com/opentdf/platform/service/logger/audit"
	ctxAuth "github.com/opentdf/platform/service/pkg/auth"
	"github.com/opentdf/platform/service/pkg/config"
	"github.com/opentdf/platform/service/trust"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/otel/trace/noop"
)

const (
	listedDID   = "did:key:z6MkListedAgent"
	otherDID    = "did:key:z6MkOtherAgent"
	personSub   = "00000000-0000-0000-0000-000000000001"
	dissemKASID = "dissem-r1"
)

func noAttrPolicy() *Policy { return &Policy{UUID: uuid.New()} }

func attrPolicy() *Policy {
	pol := fauxPolicy()
	pol.UUID = uuid.New()
	return pol
}

func dissemPolicy(attrs bool, dissem ...string) *Policy {
	pol := noAttrPolicy()
	if attrs {
		pol = attrPolicy()
	}
	pol.Body.Dissem = dissem
	return pol
}

// permittingAuthz is an authorization service that permits every resource
// and records which ones it was asked about.
type permittingAuthz struct {
	sdkconnect.AuthorizationServiceClientV2
	mu    sync.Mutex
	asked []*authzV2.Resource
}

func (a *permittingAuthz) GetDecision(_ context.Context, req *authzV2.GetDecisionRequest) (*authzV2.GetDecisionResponse, error) {
	return &authzV2.GetDecisionResponse{Decision: a.permit(req.GetResource())}, nil
}

func (a *permittingAuthz) GetDecisionMultiResource(_ context.Context, req *authzV2.GetDecisionMultiResourceRequest) (*authzV2.GetDecisionMultiResourceResponse, error) {
	out := &authzV2.GetDecisionMultiResourceResponse{}
	for _, r := range req.GetResources() {
		out.ResourceDecisions = append(out.ResourceDecisions, a.permit(r))
	}
	return out, nil
}

func (a *permittingAuthz) permit(r *authzV2.Resource) *authzV2.ResourceDecision {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.asked = append(a.asked, r)
	return &authzV2.ResourceDecision{EphemeralResourceId: r.GetEphemeralId(), Decision: authzV2.Decision_DECISION_PERMIT}
}

func (a *permittingAuthz) askedFQNs() [][]string {
	a.mu.Lock()
	defer a.mu.Unlock()
	var out [][]string
	for _, r := range a.asked {
		out = append(out, r.GetAttributeValues().GetFqns())
	}
	return out
}

// abacProvider can reach an (always permitting) authorization service, so a
// policy with data attributes is released unless dissem denies it.
func abacProvider(enforce bool) (*Provider, *permittingAuthz, *bytes.Buffer) {
	log, buf := newBufferLogger()
	authz := &permittingAuthz{}
	p := &Provider{Logger: log, SDK: &otdf.SDK{AuthorizationV2: authz}, Tracer: noop.NewTracerProvider().Tracer("")}
	p.EnforceDissem = enforce
	return p, authz, buf
}

func accessByPolicy(t *testing.T, res []PDPAccessResult) map[*Policy]bool {
	t.Helper()
	out := make(map[*Policy]bool)
	for _, r := range res {
		_, dup := out[r.Policy]
		require.False(t, dup, "one result per policy")
		out[r.Policy] = r.Access
	}
	return out
}

func TestDissemAllows(t *testing.T) {
	tests := []struct {
		name      string
		dissem    []string
		requester string
		want      bool
	}{
		{"listed", []string{otherDID, listedDID}, listedDID, true},
		{"listed person", []string{personSub}, personSub, true},
		{"empty list defers to ABAC", nil, listedDID, true},
		{"empty (non-nil) list defers to ABAC", []string{}, listedDID, true},
		{"not listed", []string{otherDID}, listedDID, false},
		{"case differs", []string{strings.ToLower(listedDID)}, listedDID, false},
		{"listed entry is a prefix of the requester", []string{listedDID[:len(listedDID)-1]}, listedDID, false},
		{"requester is a prefix of the listed entry", []string{listedDID + "x"}, listedDID, false},
		{"listed entry has surrounding space", []string{" " + listedDID + " "}, listedDID, false},
		{"empty requester never matches an empty entry", []string{""}, "", false},
		{"empty requester never matches a listed id", []string{listedDID}, "", false},
		{"empty entry does not admit a real requester", []string{""}, listedDID, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, dissemAllows(tt.dissem, tt.requester))
		})
	}
}

func TestCanAccess_EnforcedDissem(t *testing.T) {
	tok := &entity.Token{EphemeralId: "rewrap-token", Jwt: "raw"}
	tests := []struct {
		name      string
		policy    *Policy
		requester string
		want      bool
	}{
		{"requester named in dissem is released", dissemPolicy(false, otherDID, listedDID), listedDID, true},
		{"a person named in dissem is released", dissemPolicy(false, personSub), personSub, true},
		{"requester outside dissem is denied", dissemPolicy(false, otherDID), listedDID, false},
		{"a person outside dissem is denied", dissemPolicy(false, listedDID), personSub, false},
		{"match is exact", dissemPolicy(false, strings.ToLower(listedDID)), listedDID, false},
		{"an empty dissem entry admits nobody", dissemPolicy(false, ""), listedDID, false},
		{"a requester without sub is denied by a non-empty list", dissemPolicy(false, listedDID), "", false},
		{"empty dissem defers to ABAC", dissemPolicy(false), listedDID, true},
		{"requester named in dissem still needs ABAC for data attributes", dissemPolicy(true, listedDID), listedDID, true},
		{"denied by dissem never reaches the authorization service", dissemPolicy(true, otherDID), listedDID, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p, authz, _ := abacProvider(true)
			res, err := p.canAccess(t.Context(), tok, []*Policy{tt.policy}, nil, tt.requester)
			require.NoError(t, err)
			require.Len(t, res, 1)
			assert.Same(t, tt.policy, res[0].Policy)
			assert.Equal(t, tt.want, res[0].Access)
			if len(tt.policy.Body.DataAttributes) > 0 {
				if tt.want {
					assert.Len(t, authz.askedFQNs(), 1, "a listed requester still needs ABAC for data attributes")
				} else {
					assert.Empty(t, authz.askedFQNs(), "a dissem denial must not be sent for an ABAC decision")
				}
			}
		})
	}
}

// With enforce_dissem off (the default), upstream's behaviour is unchanged:
// dissem is logged as not enforced and ABAC alone decides.
func TestCanAccess_DissemOffKeepsUpstreamBehaviour(t *testing.T) {
	tok := &entity.Token{EphemeralId: "rewrap-token", Jwt: "raw"}
	for _, pol := range []*Policy{dissemPolicy(false, otherDID), dissemPolicy(false, ""), dissemPolicy(true, otherDID)} {
		p, authz, buf := abacProvider(false)
		res, err := p.canAccess(t.Context(), tok, []*Policy{pol}, nil, listedDID)
		require.NoError(t, err)
		require.Len(t, res, 1)
		assert.True(t, res[0].Access, pol.Body)
		assert.Contains(t, buf.String(), "dissems check is not enabled in v2 platform kas")
		if len(pol.Body.DataAttributes) > 0 {
			assert.Len(t, authz.askedFQNs(), 1, "ABAC still decides")
		}
	}
}

// Each policy is judged on its own: a dissem denial of one policy neither
// releases it through another policy's ABAC permit nor blocks the other.
func TestCanAccess_DissemJudgedPerPolicy(t *testing.T) {
	tok := &entity.Token{EphemeralId: "rewrap-token", Jwt: "raw"}
	listed := dissemPolicy(true, listedDID)
	listed.Body.DataAttributes = []Attribute{{URI: "https://example.com/attr/Listed/value/A"}}
	unlisted := dissemPolicy(true, otherDID)
	unlisted.Body.DataAttributes = []Attribute{{URI: "https://example.com/attr/Unlisted/value/B"}}
	unlistedNoAttrs := dissemPolicy(false, otherDID)
	open := dissemPolicy(false)

	for _, order := range [][]*Policy{
		{listed, unlisted, unlistedNoAttrs, open},
		{unlisted, unlistedNoAttrs, open, listed},
	} {
		p, authz, _ := abacProvider(true)
		res, err := p.canAccess(t.Context(), tok, order, nil, listedDID)
		require.NoError(t, err)
		require.Len(t, res, len(order))
		got := accessByPolicy(t, res)
		assert.True(t, got[listed])
		assert.False(t, got[unlisted])
		assert.False(t, got[unlistedNoAttrs])
		assert.True(t, got[open])
		assert.Equal(t, [][]string{{"https://example.com/attr/Listed/value/A"}}, authz.askedFQNs(),
			"only the listed policy's attributes reach the authorization service")
	}
}

// kasConfigFrom loads a platform config file with the server's default
// loaders (legacy, then default settings; environment prefix TEST_) and
// decodes services.kas the way the KAS registers it.
func kasConfigFrom(t *testing.T, kasBlock string) (KASConfig, error) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "opentdf.yaml")
	require.NoError(t, os.WriteFile(path, []byte("services:\n  kas:\n    root_key: x\n"+kasBlock), 0o600))
	legacy, err := config.NewLegacyLoader("test", path)
	require.NoError(t, err)
	defaults, err := config.NewDefaultSettingsLoader()
	require.NoError(t, err)
	cfg, err := config.Load(t.Context(), legacy, defaults)
	require.NoError(t, err)
	return DecodeKASConfig(cfg.Services["kas"])
}

func TestDecodeKASConfig_EnforceDissem(t *testing.T) {
	t.Run("from YAML", func(t *testing.T) {
		cfg, err := kasConfigFrom(t, "    enforce_dissem: true\n")
		require.NoError(t, err)
		assert.True(t, cfg.EnforceDissem)
	})
	t.Run("unset is off", func(t *testing.T) {
		cfg, err := kasConfigFrom(t, "")
		require.NoError(t, err)
		assert.False(t, cfg.EnforceDissem)
	})
	t.Run("the environment alone has no effect without the YAML key", func(t *testing.T) {
		t.Setenv("TEST_SERVICES_KAS_ENFORCE_DISSEM", "true")
		cfg, err := kasConfigFrom(t, "")
		require.NoError(t, err)
		assert.False(t, cfg.EnforceDissem)
	})
	for env, want := range map[string]bool{"true": true, "false": false} {
		t.Run("environment "+env+" overrides the YAML key", func(t *testing.T) {
			t.Setenv("TEST_SERVICES_KAS_ENFORCE_DISSEM", env)
			cfg, err := kasConfigFrom(t, "    enforce_dissem: "+strconv.FormatBool(!want)+"\n")
			require.NoError(t, err)
			assert.Equal(t, want, cfg.EnforceDissem)
		})
	}
	t.Run("an invalid environment value fails", func(t *testing.T) {
		t.Setenv("TEST_SERVICES_KAS_ENFORCE_DISSEM", "invalid")
		_, err := kasConfigFrom(t, "    enforce_dissem: false\n")
		require.Error(t, err)
	})
}

// dissemKAS is a KAS that really unwraps, so a test can tell a released key
// from a refused one.
func dissemKAS(t *testing.T, enforce bool) *Provider {
	t.Helper()
	dir := t.TempDir()
	private := filepath.Join(dir, "kas-private.pem")
	public := filepath.Join(dir, "kas-public.pem")
	require.NoError(t, os.WriteFile(private, []byte(rsaPrivate), 0o600))
	require.NoError(t, os.WriteFile(public, []byte(rsaPublic), 0o600))
	sc, err := security.NewStandardCrypto(security.StandardConfig{Keys: []security.KeyPairInfo{
		{Algorithm: security.AlgorithmRSA2048, KID: dissemKASID, Private: private, Certificate: public},
	}})
	require.NoError(t, err)
	svc := security.NewSecurityProviderAdapter(sc, []string{dissemKASID}, nil)
	buf := &bytes.Buffer{}
	base := slog.New(slog.NewJSONHandler(buf, &slog.HandlerOptions{Level: slog.LevelDebug}))
	log := &logger.Logger{Logger: base, Audit: audit.CreateAuditLogger(*base)}
	d := trust.NewDelegatingKeyService(svc, log, nil)
	d.RegisterKeyManagerCtx(svc.Name(), func(context.Context, *trust.KeyManagerFactoryOptions) (trust.KeyManager, error) { return svc, nil })
	d.SetDefaultMode(svc.Name(), "", nil)
	p := &Provider{Logger: log, KeyDelegator: d}
	p.EnforceDissem = enforce
	return p
}

// dissemRequest wraps a KAO to dissemKASID under pol with a valid binding.
func dissemRequest(t *testing.T, pol *Policy, policyID string, kaoIDs ...string) *kaspb.UnsignedRewrapRequest_WithPolicyRequest {
	t.Helper()
	data, err := json.Marshal(pol)
	require.NoError(t, err)
	body := []byte(base64.StdEncoding.EncodeToString(data))
	asym, err := ocrypto.FromPublicPEM(rsaPublic)
	require.NoError(t, err)
	binding, err := generateHMACDigest(t.Context(), body, []byte(plainKey), *logger.CreateTestLogger())
	require.NoError(t, err)
	req := &kaspb.UnsignedRewrapRequest_WithPolicyRequest{
		Policy:    &kaspb.UnsignedRewrapRequest_WithPolicy{Id: policyID, Body: string(body)},
		Algorithm: kTDF3Algorithm,
	}
	for _, id := range kaoIDs {
		wrapped, err := asym.Encrypt([]byte(plainKey))
		require.NoError(t, err)
		req.KeyAccessObjects = append(req.KeyAccessObjects, &kaspb.UnsignedRewrapRequest_WithKeyAccessObject{
			KeyAccessObjectId: id,
			KeyAccessObject: &kaspb.KeyAccess{
				KeyType:       "wrapped",
				Kid:           dissemKASID,
				WrappedKey:    wrapped,
				PolicyBinding: &kaspb.PolicyBinding{Algorithm: "HS256", Hash: base64.StdEncoding.EncodeToString([]byte(hex.EncodeToString(binding)))},
			},
		})
	}
	return req
}

// rewrapAs runs tdf3Rewrap for a verified bearer whose sub is sub.
func rewrapAs(t *testing.T, p *Provider, sub string, reqs []*kaspb.UnsignedRewrapRequest_WithPolicyRequest) policyKAOResults {
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

// The requester is the verified token's sub, for any kind of caller.
func TestTDF3Rewrap_EnforcedDissemJudgesTheTokenSub(t *testing.T) {
	for _, sub := range []string{listedDID, personSub} {
		t.Run(sub, func(t *testing.T) {
			p := dissemKAS(t, true)
			results := rewrapAs(t, p, sub, []*kaspb.UnsignedRewrapRequest_WithPolicyRequest{
				dissemRequest(t, dissemPolicy(false, otherDID, sub), "policy-listed", "kao-a1", "kao-a2"),
				dissemRequest(t, dissemPolicy(false, otherDID), "policy-unlisted", "kao-b1", "kao-b2"),
			})
			require.Len(t, results["policy-listed"], 2)
			for id, r := range results["policy-listed"] {
				require.NoError(t, r.Error, id)
				assert.NotEmpty(t, r.Encapped, id)
			}
			require.Len(t, results["policy-unlisted"], 2)
			for id, r := range results["policy-unlisted"] {
				require.Error(t, r.Error, id)
				assert.Equal(t, connect.CodePermissionDenied, connect.CodeOf(r.Error), id)
				assert.Contains(t, r.Error.Error(), "forbidden", id)
				assert.Empty(t, r.Encapped, id)
			}
		})
	}
}

func TestTDF3Rewrap_DissemOffReleasesAsUpstream(t *testing.T) {
	p := dissemKAS(t, false)
	results := rewrapAs(t, p, listedDID, []*kaspb.UnsignedRewrapRequest_WithPolicyRequest{
		dissemRequest(t, dissemPolicy(false, otherDID), "policy-unlisted", "kao-b1"),
	})
	require.Len(t, results["policy-unlisted"], 1)
	for id, r := range results["policy-unlisted"] {
		require.NoError(t, r.Error, id)
		assert.NotEmpty(t, r.Encapped, id)
	}
}
