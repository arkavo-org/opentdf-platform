package composite

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"connectrpc.com/connect"
	authzV2 "github.com/opentdf/platform/protocol/go/authorization/v2"
	"github.com/opentdf/platform/protocol/go/policy"
	"github.com/opentdf/platform/service/entityresolution/source"
	"github.com/opentdf/platform/service/internal/publishingstatus"
	"github.com/opentdf/platform/service/logger"
	"github.com/opentdf/platform/service/logger/audit"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/types/known/emptypb"
)

const (
	creatorProDef   = "https://patreon.arkavo.com/attr/arkavo-creator-pro"
	creatorAdmin    = creatorDef + "/value/admin"
	creatorProValue = creatorProDef + "/value/x"
	perCreatorDef   = "https://arkavo.net/attr/creator"
	perCreatorValue = perCreatorDef + "/value/6f1c2d3e-0000-4000-8000-000000000001"
)

// fakePublishing answers every check with err. A nil err means not
// suspended.
type fakePublishing struct {
	err    error
	panics bool
	calls  *int
	gotSub *string
}

func (f fakePublishing) Check(_ context.Context, sub string) error {
	if f.calls != nil {
		*f.calls++
	}
	if f.gotSub != nil {
		*f.gotSub = sub
	}
	if f.panics {
		panic("publishing checker panicked")
	}
	return f.err
}

func suspended() error {
	return &publishingstatus.DenialError{
		Reason: publishingstatus.ReasonSuspended, Subject: creatorSub,
		Since: "2026-10-25T00:00:00Z", ReportID: "r1",
	}
}

func denied(reason string) error {
	return &publishingstatus.DenialError{Reason: reason, Subject: creatorSub, Cause: errors.New("upstream detail")}
}

func publishingService(t *testing.T, checker publishingstatus.Checker) *Service {
	t.Helper()
	svc := newTestService(t, testConfig(), verifiersFor(&fakeVerifier{}),
		[]configuredSource{identityCoreSource(), patreonSource()}, nil)
	svc.publishing = checker
	return svc
}

func creatorEvidence(t *testing.T, svc *Service) evidence {
	t.Helper()
	return tokenEvidence(t, svc, signCWT(t, creatorClaims(time.Now().Add(time.Hour))))
}

func TestPublishing_SuspendedLosesOnlyCreator(t *testing.T) {
	svc := publishingService(t, fakePublishing{err: suspended()})
	ev := creatorEvidence(t, svc)
	got := grantFQNs(ev)
	assert.NotContains(t, got, publishValue)
	assert.Contains(t, got, creatorCampaign)
}

func TestPublishing_OutageWithholdsOnlyCreator(t *testing.T) {
	svc := publishingService(t, fakePublishing{err: denied(publishingstatus.ReasonUnreachable)})
	got := grantFQNs(creatorEvidence(t, svc))
	assert.NotContains(t, got, publishValue)
	assert.Contains(t, got, creatorCampaign)
}

func TestPublishing_NoGrantNoCall(t *testing.T) {
	var calls int
	svc := publishingService(t, fakePublishing{err: suspended(), calls: &calls})
	claims := creatorClaims(time.Now().Add(time.Hour))
	claims["arkavo_entitlements"] = []any{creatorCampaign}
	ev := tokenEvidence(t, svc, signCWT(t, claims))
	assert.Equal(t, []string{creatorCampaign}, grantFQNs(ev))
	assert.Zero(t, calls)
}

func TestPublishing_NotSuspendedKeeps(t *testing.T) {
	var gotSub string
	svc := publishingService(t, fakePublishing{gotSub: &gotSub})
	got := grantFQNs(creatorEvidence(t, svc))
	assert.Contains(t, got, publishValue)
	assert.Contains(t, got, creatorCampaign)
	assert.Equal(t, creatorSub, gotSub)
}

func TestPublishing_PEPChainSendsPrefixedSub(t *testing.T) {
	var gotSub string
	sc := SourceConfig{ID: "identity-core", Issuer: testIssuer, Grants: []string{creatorDef}, Actions: []string{"publish"}, PEPAssertable: true}
	svc := newTestService(t, pepConfig(), verifiersFor(&fakeVerifier{}),
		[]configuredSource{sourceOf(sc, newTokenClaimsSource("arkavo_entitlements", sc.Grants))}, nil)
	svc.publishing = fakePublishing{err: suspended(), gotSub: &gotSub}

	claims := catalogCreatorClaims()
	claims["sub"] = "arkavo:abc"
	claims["arkavo_account_id"] = creatorAccount
	reps := resolveAs(callerContext(t.Context(), testPEP), t, svc, claimsEntity(t, "catalog-subject", claims))

	assert.Equal(t, "arkavo:abc", gotSub, "sub is sent as carried, never arkavo_account_id")
	assert.NotContains(t, entitlements(reps[0]), publishValue)
}

func TestPublishing_AllValuesOfDefinition(t *testing.T) {
	creator := fakeSourceOwning("creator", fakeSource{res: granting(publishValue, creatorAdmin)}, creatorDef)
	pro := fakeSourceOwning("pro", fakeSource{res: granting(creatorProValue)}, creatorProDef)
	per := fakeSourceOwning("per", fakeSource{res: granting(perCreatorValue)}, perCreatorDef)
	svc := newTestService(t, testConfig(), verifiersFor(&fakeVerifier{}), []configuredSource{creator, pro, per}, nil)
	svc.publishing = fakePublishing{err: suspended()}

	got := grantFQNs(creatorEvidence(t, svc))
	assert.ElementsMatch(t, []string{creatorProValue, perCreatorValue}, got)
}

func TestPublishing_CancelledContext(t *testing.T) {
	var hits atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { hits.Add(1) }))
	t.Cleanup(srv.Close)
	client, err := publishingstatus.New(publishingstatus.Config{
		URL: srv.URL, IdentityURL: srv.URL, ClientID: "opentdf", ClientSecret: "s",
	})
	require.NoError(t, err)
	svc := publishingService(t, client)

	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	subj := source.Subject{Claims: map[string]any{"sub": creatorSub}}
	grants := []sealedGrant{{FQN: creatorCampaign}, {FQN: publishValue}}
	var kept []sealedGrant
	require.NotPanics(t, func() { kept = svc.withholdSuspendedPublishing(ctx, subj, grants) })
	assert.Equal(t, []sealedGrant{{FQN: creatorCampaign}}, kept)
	assert.Zero(t, hits.Load(), "a cancelled context never reaches arks")
}

func TestPublishing_UnsetKeepsGrant(t *testing.T) {
	svc := publishingService(t, nil)
	assert.Contains(t, grantFQNs(creatorEvidence(t, svc)), publishValue)
}

func TestPublishing_PanicWithholds(t *testing.T) {
	log, buf := bufferLogger()
	svc := publishingService(t, fakePublishing{panics: true})
	svc.logger = log
	got := grantFQNs(creatorEvidence(t, svc))
	assert.NotContains(t, got, publishValue)
	assert.Contains(t, got, creatorCampaign)
	rec := logRecord(t, buf, publishingWithheldMsg)
	assert.Equal(t, "ERROR", rec["level"])
	assert.Equal(t, reasonPublishingCheckerPanicked, rec["reason"])
}

func TestPublishing_LogLevels(t *testing.T) {
	for reason, level := range map[string]string{
		publishingstatus.ReasonSuspended:           "WARN",
		publishingstatus.ReasonUnreachable:         "WARN",
		publishingstatus.ReasonMalformedAnswer:     "WARN",
		publishingstatus.ReasonMissingSubject:      "WARN",
		publishingstatus.ReasonForbidden:           "ERROR",
		publishingstatus.ReasonUnauthorized:        "ERROR",
		publishingstatus.ReasonCredentialsRejected: "ERROR",
	} {
		log, buf := bufferLogger()
		svc := publishingService(t, fakePublishing{err: denied(reason)})
		svc.logger = log
		creatorEvidence(t, svc)
		assert.Equal(t, level, logRecord(t, buf, publishingWithheldMsg)["level"], reason)
	}
}

// TestPublishing_LogsWithoutSecret drives a real client against a fake
// identity and arks, and checks neither the client secret nor the service
// CWT reaches the service log or the AUDIT output.
func TestPublishing_LogsWithoutSecret(t *testing.T) {
	const (
		secret = "s3cret-client-value"
		token  = "svc-cwt-known-token-value"
	)
	identity := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if _, pw, ok := r.BasicAuth(); !ok || pw != secret {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"access_token": token, "token_type": "Bearer", "expires_in": 3600})
	}))
	t.Cleanup(identity.Close)

	for name, tc := range map[string]struct {
		arks   http.HandlerFunc
		reason string
	}{
		"arks unavailable": {
			arks:   func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusServiceUnavailable) },
			reason: publishingstatus.ReasonUnreachable,
		},
		"suspended": {
			arks: func(w http.ResponseWriter, _ *http.Request) {
				_, _ = w.Write([]byte(`{"subject":"` + creatorSub + `","suspended":true,"since":"2026-10-25T00:00:00Z","reportId":"r1"}`))
			},
			reason: publishingstatus.ReasonSuspended,
		},
	} {
		t.Run(name, func(t *testing.T) {
			arks := httptest.NewServer(tc.arks)
			t.Cleanup(arks.Close)
			client, err := publishingstatus.New(publishingstatus.Config{
				URL: arks.URL, IdentityURL: identity.URL, ClientID: "opentdf", ClientSecret: secret,
			})
			require.NoError(t, err)
			svc := publishingService(t, client)
			log, buf := bufferLogger()
			svc.logger = &logger.Logger{Logger: log.Logger, Audit: svc.logger.Audit}
			svc.cfg.Constraints.PublishingStatus = publishingstatus.Config{URL: arks.URL, ClientID: "opentdf", ClientSecret: secret}

			_, rawAudit := auditedDecision(t, svc)

			rec := logRecord(t, buf, publishingWithheldMsg)
			assert.Equal(t, creatorSub, rec["sub"])
			assert.Equal(t, tc.reason, rec["reason"])
			assert.Equal(t, []any{publishValue}, rec["withheld"])
			assert.Contains(t, rawAudit, "entitlementWithheld-publishing_status")
			for _, out := range []string{buf.String(), rawAudit, svc.cfg.LogValue().String(), fmt.Sprintf("%+v %#v", svc.cfg, svc.cfg)} {
				assert.NotContains(t, out, secret)
				assert.NotContains(t, out, token)
			}
		})
	}
}

func TestPublishing_TypedNilDenialWithholds(t *testing.T) {
	svc := publishingService(t, fakePublishing{err: (*publishingstatus.DenialError)(nil)})
	var got []string
	require.NotPanics(t, func() { got = grantFQNs(creatorEvidence(t, svc)) })
	assert.NotContains(t, got, publishValue)
	assert.Contains(t, got, creatorCampaign)
}

// auditedDecision runs one PDP decision for a creator token inside an audit
// transaction opened and closed by the server's real interceptor, and returns
// the AUDIT records it wrote.
func auditedDecision(t *testing.T, svc *Service) ([]map[string]any, string) {
	t.Helper()
	return auditedDecisionFor(t, svc, creatorClaims(time.Now().Add(time.Hour)))
}

func auditedDecisionFor(t *testing.T, svc *Service, claims map[string]any) ([]map[string]any, string) {
	t.Helper()
	pdp := pdpFor(t, svc, patreonPolicy)
	var out bytes.Buffer
	interceptor := audit.ContextServerInterceptor(slog.New(slog.NewJSONHandler(&out, &slog.HandlerOptions{
		Level: audit.LevelAudit, ReplaceAttr: audit.ReplaceAttrAuditLevel,
	})))
	next := connect.UnaryFunc(func(ctx context.Context, _ connect.AnyRequest) (connect.AnyResponse, error) {
		// The creator holds publishValue: only the constraint can deny it.
		_, err := pdp.GetDecision(callerContext(ctx, "arks-media"), tokenIdentifier(signCWT(t, claims)),
			&policy.Action{Name: "publish"},
			[]*authzV2.Resource{{EphemeralId: "r0", Resource: &authzV2.Resource_AttributeValues_{
				AttributeValues: &authzV2.Resource_AttributeValues{Fqns: []string{publishValue}},
			}}}, nil, nil)
		return connect.NewResponse(&emptypb.Empty{}), err
	})
	_, err := interceptor(next)(t.Context(), connect.NewRequest(&emptypb.Empty{}))
	require.NoError(t, err)

	raw := out.String()
	var recs []map[string]any
	sc := bufio.NewScanner(&out)
	sc.Buffer(nil, 1<<20)
	for sc.Scan() {
		var rec map[string]any
		require.NoError(t, json.Unmarshal(sc.Bytes(), &rec))
		recs = append(recs, rec)
	}
	return recs, raw
}

// field returns m[key] as an object.
func field(t *testing.T, m map[string]any, key string) map[string]any {
	t.Helper()
	v, ok := m[key].(map[string]any)
	require.True(t, ok, "%s is %T", key, m[key])
	return v
}

func auditEvents(t *testing.T, recs []map[string]any, name string) []map[string]any {
	t.Helper()
	var out []map[string]any
	for _, rec := range recs {
		ev, ok := rec["audit"].(map[string]any)
		require.True(t, ok)
		obj, _ := ev["object"].(map[string]any)
		if obj["name"] == name {
			out = append(out, ev)
		}
	}
	return out
}

func TestPublishing_AuditEventOnWithhold(t *testing.T) {
	svc := publishingService(t, fakePublishing{err: suspended()})
	recs, _ := auditedDecision(t, svc)

	for _, rec := range recs {
		assert.Equal(t, "AUDIT", rec["level"])
		assert.Equal(t, "decision", rec["msg"])
	}
	withheld := auditEvents(t, recs, "entitlementWithheld-publishing_status")
	require.Len(t, withheld, 1)
	decision := auditEvents(t, recs, "decisionRequest-publish")
	require.Len(t, decision, 1)
	assert.Equal(t, "failure", field(t, decision[0], "action")["result"], "the decision is a deny")

	meta := field(t, withheld[0], "eventMetaData")
	assert.Equal(t, publishingstatus.ReasonSuspended, meta["reason"])
	assert.Equal(t, "r1", meta["report_id"])
	assert.Equal(t, "publishing_status", meta["constraint"])
	assert.Equal(t, []any{publishValue}, meta["withheld_fqns"])
	assert.NotContains(t, meta, "cause")
	assert.Equal(t, creatorSub, field(t, withheld[0], "actor")["id"])

	assert.NotEmpty(t, withheld[0]["requestID"])
	assert.NotEqual(t, "00000000-0000-0000-0000-000000000000", withheld[0]["requestID"])
	assert.Equal(t, decision[0]["requestID"], withheld[0]["requestID"], "both events share the request's id")
}

func TestPublishing_NoAuditWhenKept(t *testing.T) {
	svc := publishingService(t, fakePublishing{})
	recs, _ := auditedDecision(t, svc)
	assert.Empty(t, auditEvents(t, recs, "entitlementWithheld-publishing_status"))
	assert.NotEmpty(t, auditEvents(t, recs, "decisionRequest-publish"))
}

// A creator with no sub is withheld and audited under a placeholder; arks
// is never asked (the client denies an empty sub itself).
func TestPublishing_MissingSubAuditPlaceholder(t *testing.T) {
	var gotSub string
	svc := publishingService(t, fakePublishing{err: denied(publishingstatus.ReasonMissingSubject), gotSub: &gotSub})
	claims := creatorClaims(time.Now().Add(time.Hour))
	delete(claims, "sub")
	recs, _ := auditedDecisionFor(t, svc, claims)

	withheld := auditEvents(t, recs, "entitlementWithheld-publishing_status")
	require.Len(t, withheld, 1)
	assert.Equal(t, "(none)", field(t, withheld[0], "actor")["id"])
	assert.Equal(t, "(none)-publishing_status", field(t, withheld[0], "object")["id"])
	assert.Empty(t, gotSub, "the checker still receives the empty sub")
}

// Not suspended is logged at DEBUG with the sub, and is neither a warning,
// an error nor an audit event.
func TestPublishing_NotSuspendedLogsDebug(t *testing.T) {
	log, buf := bufferLogger()
	svc := publishingService(t, fakePublishing{})
	svc.logger = log
	recs, _ := auditedDecision(t, svc)

	rec := logRecord(t, buf, "composite: publishing status not suspended")
	assert.Equal(t, "DEBUG", rec["level"])
	assert.Equal(t, creatorSub, rec["sub"])
	for _, line := range bytes.Split(buf.Bytes(), []byte("\n")) {
		assert.NotContains(t, string(line), `"level":"WARN"`)
		assert.NotContains(t, string(line), `"level":"ERROR"`)
	}
	assert.Empty(t, auditEvents(t, recs, "entitlementWithheld-publishing_status"))
}
