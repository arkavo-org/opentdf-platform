package composite

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"maps"
	"slices"
	"strings"
	"testing"
	"time"

	"connectrpc.com/connect"
	"github.com/opentdf/platform/protocol/go/entity"
	entityresolutionV2 "github.com/opentdf/platform/protocol/go/entityresolution/v2"
	"github.com/opentdf/platform/service/entityresolution/source"
	ctxAuth "github.com/opentdf/platform/service/pkg/auth"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/metadata"
	"google.golang.org/protobuf/types/known/anypb"
	"google.golang.org/protobuf/types/known/structpb"
)

// patreonView returns the .patreon properties of rep, its only properties.
func patreonView(t *testing.T, rep *entityresolutionV2.EntityRepresentation) map[string]any {
	t.Helper()
	require.Len(t, rep.GetAdditionalProps(), 1)
	props := rep.GetAdditionalProps()[0].AsMap()
	view, ok := props["patreon"].(map[string]any)
	require.True(t, ok, "no patreon properties in %v", props)
	return view
}

// logRecord returns the one log record with message msg.
func logRecord(t *testing.T, buf *bytes.Buffer, msg string) map[string]any {
	t.Helper()
	var found []map[string]any
	lines := bufio.NewScanner(bytes.NewReader(buf.Bytes()))
	for lines.Scan() {
		var rec map[string]any
		require.NoError(t, json.Unmarshal(lines.Bytes(), &rec))
		if rec["msg"] == msg {
			found = append(found, rec)
		}
	}
	require.Len(t, found, 1, "want one %q record in:\n%s", msg, buf)
	return found[0]
}

// The token route's evidence is the representation in the second call,
// whoever makes it: on the licence route that is arks-media, which is not on
// claims_chain_peps.
func TestResolve_SealedEvidenceBecomesRepresentation(t *testing.T) {
	svc := newTestService(t, pepConfig(), verifiersFor(&fakeVerifier{}),
		[]configuredSource{pepPatreonSource(), identityCoreSource()}, nil)
	chain := chainsFor(t, svc, []*entity.Token{{EphemeralId: "t0", Jwt: signCWT(t, creatorClaims(time.Now().Add(time.Hour)))}})[0]

	rep := resolveAs(callerContext(t.Context(), "arks-media"), t, svc, chain.GetEntities()...)[0]

	assert.Equal(t, "composite-subject", rep.GetOriginalId())
	assert.Equal(t, map[string][]string{
		creatorCampaign:  {"read"},
		creatorSupporter: {"read"},
		creatorFree:      {"read"},
		creatorTier555:   {"read"},
		publishValue:     {"publish"},
	}, entitlements(rep))
	require.Len(t, rep.GetAdditionalProps(), 1)
	props := rep.GetAdditionalProps()[0].AsMap()
	assert.Equal(t, []string{"patreon"}, slices.Sorted(maps.Keys(props)),
		"only the sources' properties, under their keys; never the sealed claim")
	assert.Equal(t, []any{"13167240"}, patreonView(t, rep)["campaign_ids"])
}

// A sealed evidence is the whole answer. Claims a caller puts around it add
// nothing, even from an allowlisted PEP.
func TestResolve_SealedEvidenceIgnoresClaimsAroundIt(t *testing.T) {
	svc := newTestService(t, pepConfig(), nil, []configuredSource{pepPatreonSource(), identityCoreSource()}, nil)
	sealed, err := sealEvidence(svc.sealKeys[0], evidence{
		V:      evidenceVersion,
		Exp:    svc.now().Add(time.Minute).Unix(),
		Grants: []sealedGrant{{FQN: creatorCampaign, Actions: []string{"read"}, Source: "patreon"}},
	})
	require.NoError(t, err)
	claims := catalogCreatorClaims()
	claims[evidenceClaim] = sealed

	rep := resolveAs(callerContext(t.Context(), testPEP), t, svc, claimsEntity(t, "sealed", claims))[0]

	assert.Equal(t, "sealed", rep.GetOriginalId())
	assert.Equal(t, map[string][]string{creatorCampaign: {"read"}}, entitlements(rep),
		"the evidence's grant only; not the supporter tier the claims around it carry")
	assert.Empty(t, rep.GetAdditionalProps(), "the evidence has no properties, and arkavo_patreon around it is not read")
}

// An evidence that does not open grants nothing and has no properties. It is
// never read as a PEP's claims instead, nor as an anonymous subject's.
func TestResolve_ForgedSealGrantsNothing(t *testing.T) {
	svc := newTestService(t, pepConfig(), nil, []configuredSource{pepPatreonSource(), identityCoreSource()}, nil)
	granted := evidence{
		V:      evidenceVersion,
		Exp:    svc.now().Add(time.Hour).Unix(),
		Grants: []sealedGrant{{FQN: creatorCampaign, Actions: []string{"read"}, Source: "patreon"}},
		Props:  map[string]map[string]any{"patreon": {"status": "active"}},
	}
	genuine, err := sealEvidence(svc.sealKeys[0], granted)
	require.NoError(t, err)
	forged, err := sealEvidence([]byte(strings.Repeat("f", minSealKeyBytes)), granted)
	require.NoError(t, err)
	expiredEvidence := granted
	expiredEvidence.Exp = svc.now().Unix()
	expired, err := sealEvidence(svc.sealKeys[0], expiredEvidence)
	require.NoError(t, err)
	genuinePayload, _, _ := strings.Cut(genuine, ".")
	_, forgedMAC, _ := strings.Cut(forged, ".")

	entityFor := func(t *testing.T, seal any) *entity.Entity {
		t.Helper()
		claims := catalogCreatorClaims()
		claims[evidenceClaim] = seal
		return claimsEntity(t, "subject", claims)
	}
	ctx := callerContext(t.Context(), testPEP)
	require.Equal(t, map[string][]string{creatorCampaign: {"read"}}, entitlements(resolveAs(ctx, t, svc, entityFor(t, genuine))[0]),
		"the genuine seal opens, so the cases below fail on their seal alone")

	for name, seal := range map[string]any{
		"sealed under a key the ERS does not hold": forged,
		"expired":                             expired,
		"a genuine payload under another MAC": genuinePayload + "." + forgedMAC,
		"not a seal":                          "not-a-seal",
		"not a string":                        42.0,
	} {
		t.Run(name, func(t *testing.T) {
			log, buf := bufferLogger()
			svc.logger = log

			rep := resolveAs(ctx, t, svc, entityFor(t, seal))[0]

			assert.Equal(t, "subject", rep.GetOriginalId())
			assert.Empty(t, rep.GetDirectEntitlements(), "neither the evidence's grants nor the PEP's claims around it")
			assert.Empty(t, rep.GetAdditionalProps(), "no properties, not even the free view")
			assert.Equal(t, "WARN", logRecord(t, buf, "composite: arkavo_evidence does not open; it grants nothing")["level"])
		})
	}
}

// The catalog route: the catalog node verified the creator's CWT and sends
// the claims unsealed. Only pep_assertable sources read them.
func TestResolve_PEPChainFromAllowlistedClient(t *testing.T) {
	svc := newTestService(t, pepConfig(), nil, []configuredSource{pepPatreonSource(), identityCoreSource()}, nil)
	ctx := metadata.NewIncomingContext(t.Context(), metadata.Pairs(ctxAuth.ClientIDKey, "arks-test"))

	rep := resolveAs(ctx, t, svc, claimsEntity(t, "catalog-subject", catalogCreatorClaims()))[0]

	assert.Equal(t, "catalog-subject", rep.GetOriginalId())
	assert.Equal(t, map[string][]string{creatorCampaign: {"read"}, creatorSupporter: {"read"}}, entitlements(rep),
		"the Patreon grants; publish is absent because identity-core is not pep_assertable")
	assert.Equal(t, []any{"13167240"}, patreonView(t, rep)["campaign_ids"])
}

// An unsealed chain from any other caller is an anonymous subject: its
// claims are discarded, and the refusal names the client ID it saw.
func TestResolve_PEPChainFromOtherClientGrantsNothing(t *testing.T) {
	for name, tc := range map[string]struct {
		callers []string
		logged  string
	}{
		"another client ID":                {callers: []string{"arks-media"}, logged: "arks-media"},
		"no metadata":                      {logged: "none"},
		"two conflicting client_id values": {callers: []string{testPEP, "arks-media"}, logged: "conflict"},
	} {
		t.Run(name, func(t *testing.T) {
			log, buf := bufferLogger()
			svc := newTestService(t, pepConfig(), nil, []configuredSource{pepPatreonSource(), identityCoreSource()}, nil)
			svc.logger = log

			rep := resolveAs(callerContext(t.Context(), tc.callers...), t, svc, claimsEntity(t, "catalog-subject", catalogCreatorClaims()))[0]

			assert.Empty(t, rep.GetDirectEntitlements())
			view := patreonView(t, rep)
			assert.Equal(t, "free", view["tier_slug"], "the claims were discarded: the anonymous free view")
			assert.Empty(t, view["campaign_ids"])
			rec := logRecord(t, buf, "composite: unsealed claims chain from a caller not on claims_chain_peps")
			assert.Equal(t, "WARN", rec["level"])
			assert.Equal(t, tc.logged, rec["client_id"])
		})
	}
}

func TestCallerClientID(t *testing.T) {
	// "none" and "conflict" are allowlisted too, to show the labels for a
	// missing or conflicting client ID never are.
	peps := map[string]bool{testPEP: true, "none": true, "conflict": true}
	withIDs := func(ids ...string) func(context.Context) context.Context {
		return func(ctx context.Context) context.Context { return callerContext(ctx, ids...) }
	}
	tests := []struct {
		name            string
		ctx             func(context.Context) context.Context
		wantID          string
		wantAllowlisted bool
	}{
		{"an allowlisted ID", withIDs(testPEP), testPEP, true},
		{"another ID", withIDs("arks-media"), "arks-media", false},
		{"no metadata", withIDs(), "none", false},
		{"metadata without a client ID", func(ctx context.Context) context.Context {
			return metadata.NewIncomingContext(ctx, metadata.Pairs("x-request-id", "1"))
		}, "none", false},
		{"two values", withIDs(testPEP, testPEP), "conflict", false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			id, allowlisted := callerClientID(tc.ctx(t.Context()), peps)
			assert.Equal(t, tc.wantID, id)
			assert.Equal(t, tc.wantAllowlisted, allowlisted)
		})
	}
}

// A PEP's claims count only under the issuer a source is configured for, so
// claims with no iss, or another's, reach no source.
func TestResolve_PEPChainWithoutIssGrantsNothing(t *testing.T) {
	svc := newTestService(t, pepConfig(), nil, []configuredSource{pepPatreonSource(), identityCoreSource()}, nil)
	for name, iss := range map[string]any{"no iss": nil, "another issuer": "https://identity.example"} {
		t.Run(name, func(t *testing.T) {
			claims := catalogCreatorClaims()
			delete(claims, "iss")
			if iss != nil {
				claims["iss"] = iss
			}

			rep := resolveAs(callerContext(t.Context(), testPEP), t, svc, claimsEntity(t, "catalog-subject", claims))[0]

			assert.Empty(t, rep.GetDirectEntitlements())
			assert.Empty(t, rep.GetAdditionalProps(), "no source admitted the subject")
		})
	}
}

// An entity that is not a claims entity carries nothing to believe: it is
// anonymous, and gets the free view. With no ephemeral ID it is named by its
// index.
func TestResolve_NonClaimsEntityGetsFreeView(t *testing.T) {
	svc := newTestService(t, pepConfig(), nil, []configuredSource{pepPatreonSource(), identityCoreSource()}, nil)

	reps := resolveAs(callerContext(t.Context(), testPEP), t, svc,
		&entity.Entity{EntityType: &entity.Entity_UserName{UserName: "creator"}, EphemeralId: "user", Category: entity.Entity_CATEGORY_SUBJECT},
		&entity.Entity{EntityType: &entity.Entity_UserName{UserName: "creator"}, Category: entity.Entity_CATEGORY_SUBJECT},
	)

	assert.Equal(t, "user", reps[0].GetOriginalId())
	assert.Equal(t, "entity_idx_1", reps[1].GetOriginalId())
	for _, rep := range reps {
		assert.Empty(t, rep.GetDirectEntitlements())
		assert.Equal(t, "former", patreonView(t, rep)["status"])
	}
}

// The unsealed routes never grant what a source says has expired: neither on
// an allowlisted PEP's chain nor for an anonymous subject.
func TestResolve_ExpiredSourceGrantIsAbsent(t *testing.T) {
	now := time.Now().Truncate(time.Second)
	sc := SourceConfig{ID: "leased", Issuer: testIssuer, Grants: []string{exampleDef}, PEPAssertable: true}
	svc := newTestService(t, pepConfig(), nil, []configuredSource{sourceOf(sc, fakeSource{res: expiringGrants(now)})}, nil)
	svc.now = func() time.Time { return now }

	for name, e := range map[string]*entity.Entity{
		"allowlisted PEP chain": claimsEntity(t, "subject", map[string]any{"iss": testIssuer}),
		"anonymous subject": {
			EntityType: &entity.Entity_UserName{UserName: "viewer"}, EphemeralId: "subject", Category: entity.Entity_CATEGORY_SUBJECT,
		},
	} {
		t.Run(name, func(t *testing.T) {
			rep := resolveAs(callerContext(t.Context(), testPEP), t, svc, e)[0]

			assert.Equal(t, map[string][]string{liveValue: {"read"}, outlivesValue: {"read"}}, entitlements(rep),
				"the expired and expiring-now grants are absent")
		})
	}
}

// Claims that do not unpack are a malformed request, as in every other
// resolver.
func TestResolve_UnreadableClaimsAreInvalidArgument(t *testing.T) {
	svc := newTestService(t, pepConfig(), nil, []configuredSource{pepPatreonSource()}, nil)
	notAStruct, err := anypb.New(structpb.NewStringValue("claims"))
	require.NoError(t, err)

	_, err = svc.ResolveEntities(callerContext(t.Context(), testPEP), connect.NewRequest(&entityresolutionV2.ResolveEntitiesRequest{
		Entities: []*entity.Entity{{EntityType: &entity.Entity_Claims{Claims: notAStruct}, EphemeralId: "subject"}},
	}))

	require.Error(t, err)
	assert.Equal(t, connect.CodeInvalidArgument, connect.CodeOf(err))
}

// The kind is read from the claims the sources see, never taken from the
// caller: a PEP subject whose claims describe a device is a device, so the
// device-class source serves it and its class's cap binds it.
func TestResolveSubject_KindComesFromClaims(t *testing.T) {
	cfg := pepConfig()
	cfg.Constraints.DeviceClassCaps = map[string][]string{managedClass: {classInternal}}
	devices := SourceConfig{
		ID: "device-class", Issuer: testIssuer, Grants: []string{classifyDef},
		Subjects: []source.Kind{source.KindDevice}, PEPAssertable: true,
	}
	tdf := SourceConfig{ID: "identity-core", Issuer: testIssuer, Grants: []string{tdfDef}, PEPAssertable: true}
	svc := newTestService(t, cfg, nil, []configuredSource{
		sourceOf(devices, newDeviceClassSource(map[string][]string{managedClass: {classInternal, classConfidential}})),
		sourceOf(tdf, newTokenClaimsSource("arkavo_entitlements", tdf.Grants)),
	}, nil)
	claims := map[string]any{
		"iss":                 testIssuer,
		"arkavo_entitlements": []any{decryptValue},
		"arkavo_npe":          map[string]any{"type": "device", "class": managedClass},
	}

	ev := svc.resolveSubject(t.Context(), source.Subject{Claims: claims, Kind: source.KindPerson, Trust: source.TrustPEP},
		source.Query{Action: "read"}, svc.now().Add(time.Minute))

	assert.Equal(t, source.OutcomeComplete, ev.Outcomes["device-class"], "the device-class source serves it as a device")
	assert.Equal(t, []string{classInternal}, grantFQNs(ev),
		"the managed cap keeps internal and removes confidential and decrypt")
}
