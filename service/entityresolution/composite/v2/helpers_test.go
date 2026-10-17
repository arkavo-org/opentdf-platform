package composite

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/base64"
	"log/slog"
	"sync/atomic"
	"testing"
	"time"

	"connectrpc.com/connect"
	"github.com/fxamacker/cbor/v2"
	authzV2 "github.com/opentdf/platform/protocol/go/authorization/v2"
	"github.com/opentdf/platform/protocol/go/entity"
	entityresolutionV2 "github.com/opentdf/platform/protocol/go/entityresolution/v2"
	patreon "github.com/opentdf/platform/service/entityresolution/patreon/v2"
	"github.com/opentdf/platform/service/entityresolution/source"
	"github.com/opentdf/platform/service/internal/agentstatus"
	"github.com/opentdf/platform/service/internal/auth"
	"github.com/opentdf/platform/service/logger"
	ctxAuth "github.com/opentdf/platform/service/pkg/auth"
	"github.com/stretchr/testify/require"
	"github.com/veraison/go-cose"
	"go.opentelemetry.io/otel/trace/noop"
	"google.golang.org/grpc/metadata"
	"google.golang.org/protobuf/types/known/anypb"
	"google.golang.org/protobuf/types/known/structpb"
)

const (
	creatorDef     = "https://patreon.arkavo.com/attr/arkavo-creator"
	publishValue   = "https://patreon.arkavo.com/attr/arkavo-creator/value/publish"
	decryptValue   = "https://arkavo.ai/attr/tdf/value/decrypt"
	creatorSub     = "did:key:z6Mkcreator"
	creatorAccount = "00000000-0000-0000-0000-00000000c0de"

	creatorCampaign  = "https://patreon.arkavo.com/attr/campaign/value/13167240"
	creatorSupporter = "https://patreon.arkavo.com/attr/campaign-tier/value/13167240_supporter"
	creatorFree      = "https://patreon.arkavo.com/attr/campaign-tier/value/13167240_free"
	creatorTier555   = "https://patreon.arkavo.com/attr/campaign-tier/value/13167240_tier-555"
)

func testLogger(t *testing.T) *logger.Logger {
	t.Helper()
	l, err := logger.NewLogger(logger.Config{Level: "error", Output: "stderr", Type: "text"})
	require.NoError(t, err)
	return l
}

// bufferLogger records every level as JSON lines, for asserting log records.
func bufferLogger() (*logger.Logger, *bytes.Buffer) {
	buf := &bytes.Buffer{}
	return &logger.Logger{Logger: slog.New(slog.NewJSONHandler(buf, &slog.HandlerOptions{Level: slog.LevelDebug}))}, buf
}

func testConfig() Config {
	return Config{
		Deadline: 300 * time.Millisecond,
		Evidence: EvidenceConfig{SealKey: testSealKey, PreviousSealKeys: []string{oldSealKey}},
	}
}

// newTestService builds the service as New does and pins its clock, so
// evidence expiries can be asserted exactly.
func newTestService(t *testing.T, cfg Config, verifiers map[string]claimsVerifier, sources []configuredSource, checker agentstatus.Checker) *Service {
	t.Helper()
	svc, err := New(cfg, verifiers, sources, checker, testLogger(t))
	require.NoError(t, err)
	svc.Tracer = noop.NewTracerProvider().Tracer("test")
	now := time.Now().Truncate(time.Second)
	svc.now = func() time.Time { return now }
	return svc
}

// verifiersFor configures v as the testIssuer's verifier.
func verifiersFor(v claimsVerifier) map[string]claimsVerifier {
	return map[string]claimsVerifier{testIssuer: v}
}

// fakeVerifier stands in for *auth.CWTVerifier. With err set it refuses
// every token; with claims set it returns them for any token it is handed;
// otherwise it returns the token's own claims, unverified.
type fakeVerifier struct {
	claims map[string]any
	err    error
	calls  atomic.Int32
}

func (f *fakeVerifier) VerifyCWTClaims(_ context.Context, token string) (map[string]any, error) {
	f.calls.Add(1)
	if f.err != nil {
		return nil, f.err
	}
	if f.claims != nil {
		return f.claims, nil
	}
	return auth.DecodeCWTClaimsFromToken(token)
}

// signCWT mints a COSE_Sign1 CWT. iss, sub and exp (a time.Time) go under
// their RFC 8392 labels; every other claim keeps its name. The fake verifier
// never checks the signature, but the token route decodes the token to read
// its issuer, so it must be a real CWT.
func signCWT(t *testing.T, claims map[string]any) string {
	t.Helper()
	labels := map[string]int{"iss": 1, "sub": 2, "exp": 4}
	payload := map[any]any{}
	for k, v := range claims {
		if label, ok := labels[k]; ok {
			if exp, isTime := v.(time.Time); isTime {
				v = exp.Unix()
			}
			payload[label] = v
			continue
		}
		payload[k] = v
	}
	body, err := cbor.Marshal(payload)
	require.NoError(t, err)
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	signer, err := cose.NewSigner(cose.AlgorithmES256, priv)
	require.NoError(t, err)
	msg := cose.Sign1Message{
		Headers: cose.Headers{Protected: cose.ProtectedHeader{cose.HeaderLabelAlgorithm: cose.AlgorithmES256}},
		Payload: body,
	}
	require.NoError(t, msg.Sign(rand.Reader, nil, signer))
	raw, err := msg.MarshalCBOR()
	require.NoError(t, err)
	return base64.RawURLEncoding.EncodeToString(raw)
}

// creatorClaims is the Task 4 creator: owner of campaign 13167240, whose
// arkavo_entitlements also carry another namespace's value and the
// arkavo-creator publish entitlement.
func creatorClaims(exp time.Time) map[string]any {
	return map[string]any{
		"iss":               testIssuer,
		"sub":               creatorSub,
		"exp":               exp,
		"arkavo_account_id": creatorAccount,
		"arkavo_patreon":    map[string]any{"role": "creator", "campaign_id": "13167240", "memberships": []any{}},
		"arkavo_entitlements": []any{
			creatorCampaign, creatorSupporter, creatorFree, creatorTier555,
			decryptValue, publishValue,
		},
	}
}

// fakeSource answers with res after sleep, or with err, or panics. The sleep
// ignores the deadline, as a misbehaving source would.
type fakeSource struct {
	res    source.Resolution
	err    error
	panics bool
	sleep  time.Duration
}

func (f fakeSource) Resolve(context.Context, source.Subject, source.Query) (source.Resolution, error) {
	time.Sleep(f.sleep)
	if f.panics {
		panic("fake source panicked")
	}
	return f.res, f.err
}

// sourceFunc adapts a function to source.Source.
type sourceFunc func(context.Context, source.Subject, source.Query) (source.Resolution, error)

func (f sourceFunc) Resolve(ctx context.Context, s source.Subject, q source.Query) (source.Resolution, error) {
	return f(ctx, s, q)
}

// granting is a complete resolution of fqns with no actions, so the
// resolver gives them the source's own.
func granting(fqns ...string) source.Resolution {
	res := source.Resolution{Outcome: source.OutcomeComplete}
	for _, f := range fqns {
		res.Grants = append(res.Grants, source.Grant{FQN: f})
	}
	return res
}

// sourceOf puts src under sc's capability, as Task 9 will from config.
func sourceOf(sc SourceConfig, src source.Source) configuredSource {
	return configuredSource{id: sc.ID, propsKey: sc.PropertiesKey, cap: newCapability(sc), src: src}
}

func patreonSource() configuredSource {
	return sourceOf(SourceConfig{
		ID: "patreon", Issuer: testIssuer,
		Grants:        []string{campaignDef, tierDef},
		PropertiesKey: "patreon",
	}, patreon.NewTokenSource(patreon.SourceConfig{}))
}

// pepPatreonSource is the patreon source as production configures it:
// pep_assertable, so an allowlisted PEP's claims count, and
// infer_unknown_as_free, so a subject with no Patreon claim gets the free
// view.
func pepPatreonSource() configuredSource {
	return sourceOf(SourceConfig{
		ID: "patreon", Issuer: testIssuer,
		Grants:        []string{campaignDef, tierDef},
		PEPAssertable: true,
		PropertiesKey: "patreon",
	}, patreon.NewTokenSource(patreon.SourceConfig{InferUnknownAsFree: true}))
}

func identityCoreSource() configuredSource {
	sc := SourceConfig{
		ID: "identity-core", Issuer: testIssuer,
		Grants:  []string{creatorDef},
		Actions: []string{"publish"},
	}
	return sourceOf(sc, newTokenClaimsSource("arkavo_entitlements", sc.Grants))
}

// fakeSourceOwning puts a fake source under a capability owning defs.
func fakeSourceOwning(id string, src source.Source, defs ...string) configuredSource {
	return sourceOf(SourceConfig{ID: id, Issuer: testIssuer, Grants: defs}, src)
}

// chainsFor runs the token route and returns its chains.
func chainsFor(t *testing.T, svc *Service, tokens []*entity.Token, resources ...*authzV2.Resource) []*entity.EntityChain {
	t.Helper()
	resp, err := svc.CreateEntityChainsFromTokens(t.Context(), connect.NewRequest(&entityresolutionV2.CreateEntityChainsFromTokensRequest{
		Tokens:    tokens,
		Resources: resources,
	}))
	require.NoError(t, err, "the token route never fails a decision over a token")
	chains := resp.Msg.GetEntityChains()
	require.Len(t, chains, len(tokens))
	return chains
}

// tokenEvidence runs the token route for one token and opens the evidence
// its chain carries.
func tokenEvidence(t *testing.T, svc *Service, token string, resources ...*authzV2.Resource) evidence {
	t.Helper()
	chain := chainsFor(t, svc, []*entity.Token{{EphemeralId: "t0", Jwt: token}}, resources...)[0]
	require.Equal(t, "t0", chain.GetEphemeralId())
	require.Len(t, chain.GetEntities(), 1)
	return openEntity(t, svc, chain.GetEntities()[0])
}

// openEntity checks the shape of a chain's subject entity and opens the
// evidence sealed in it.
func openEntity(t *testing.T, svc *Service, e *entity.Entity) evidence {
	t.Helper()
	require.Equal(t, "composite-subject", e.GetEphemeralId())
	require.Equal(t, entity.Entity_CATEGORY_SUBJECT, e.GetCategory())
	claims, ok := e.GetEntityType().(*entity.Entity_Claims)
	require.True(t, ok, "subject entity is %T, want claims", e.GetEntityType())
	var st structpb.Struct
	require.NoError(t, claims.Claims.UnmarshalTo(&st))
	m := st.AsMap()
	require.Len(t, m, 1, "the subject carries only the sealed evidence: %v", m)
	sealed, ok := m[evidenceClaim].(string)
	require.True(t, ok, "%s is %T, want string", evidenceClaim, m[evidenceClaim])
	ev, err := openEvidence(svc.sealKeys, sealed, svc.now())
	require.NoError(t, err)
	return ev
}

func grantFQNs(ev evidence) []string {
	out := make([]string, 0, len(ev.Grants))
	for _, g := range ev.Grants {
		out = append(out, g.FQN)
	}
	return out
}

func grantFor(t *testing.T, ev evidence, fqn string) sealedGrant {
	t.Helper()
	for _, g := range ev.Grants {
		if g.FQN == fqn {
			return g
		}
	}
	require.Failf(t, "grant missing", "%s not in %v", fqn, grantFQNs(ev))
	return sealedGrant{}
}

// testPEP is the allowlisted PEP: the catalog node's client ID.
const testPEP = "arks-test"

// pepConfig allowlists testPEP.
func pepConfig() Config {
	cfg := testConfig()
	cfg.Evidence.ClaimsChainPEPs = []string{testPEP}
	return cfg
}

// callerContext carries clientIDs as the platform records the caller's
// client ID; with none it carries no metadata at all.
func callerContext(ctx context.Context, clientIDs ...string) context.Context {
	if len(clientIDs) == 0 {
		return ctx
	}
	pairs := make([]string, 0, 2*len(clientIDs))
	for _, id := range clientIDs {
		pairs = append(pairs, ctxAuth.ClientIDKey, id)
	}
	return metadata.NewIncomingContext(ctx, metadata.Pairs(pairs...))
}

// claimsEntity is a SUBJECT claims entity, as a PEP sends it in a chain.
func claimsEntity(t *testing.T, id string, claims map[string]any) *entity.Entity {
	t.Helper()
	st, err := structpb.NewStruct(claims)
	require.NoError(t, err)
	packed, err := anypb.New(st)
	require.NoError(t, err)
	return &entity.Entity{
		EntityType:  &entity.Entity_Claims{Claims: packed},
		EphemeralId: id,
		Category:    entity.Entity_CATEGORY_SUBJECT,
	}
}

// catalogCreatorClaims are the creator's claims as the catalog node forwards
// them once it has verified the creator's CWT.
func catalogCreatorClaims() map[string]any {
	return map[string]any{
		"iss":                 testIssuer,
		"sub":                 creatorSub,
		"arkavo_patreon":      map[string]any{"role": "creator", "campaign_id": "13167240", "memberships": []any{}},
		"arkavo_entitlements": []any{creatorCampaign, creatorSupporter, publishValue},
	}
}

// resolveAs runs ResolveEntities on entities as the caller ctx carries.
func resolveAs(ctx context.Context, t *testing.T, svc *Service, entities ...*entity.Entity) []*entityresolutionV2.EntityRepresentation {
	t.Helper()
	resp, err := svc.ResolveEntities(ctx, connect.NewRequest(&entityresolutionV2.ResolveEntitiesRequest{Entities: entities}))
	require.NoError(t, err)
	reps := resp.Msg.GetEntityRepresentations()
	require.Len(t, reps, len(entities))
	return reps
}

// entitlements maps a representation's direct entitlements to their actions.
func entitlements(rep *entityresolutionV2.EntityRepresentation) map[string][]string {
	out := map[string][]string{}
	for _, de := range rep.GetDirectEntitlements() {
		out[de.GetAttributeValueFqn()] = de.GetActions()
	}
	return out
}

// statusAnswer is a status checker that always gives the same answer.
type statusAnswer struct{ err error }

func (s statusAnswer) Check(context.Context, agentstatus.Subject) error { return s.err }
