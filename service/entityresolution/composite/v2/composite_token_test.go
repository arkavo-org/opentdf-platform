package composite

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/fxamacker/cbor/v2"
	authzV2 "github.com/opentdf/platform/protocol/go/authorization/v2"
	"github.com/opentdf/platform/protocol/go/entity"
	"github.com/opentdf/platform/service/entityresolution/source"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const (
	exampleDef   = "https://example.com/attr/a"
	exampleValue = "https://example.com/attr/a/value/ok"
	otherDef     = "https://example.com/attr/b"
	otherValue   = "https://example.com/attr/b/value/ok"
)

func TestTokenRoute_CreatorGetsOwnCampaignTiers(t *testing.T) {
	svc := newTestService(t, testConfig(), verifiersFor(&fakeVerifier{}),
		[]configuredSource{patreonSource(), identityCoreSource()}, nil)
	exp := time.Now().Add(time.Hour).Truncate(time.Second)

	ev := tokenEvidence(t, svc, signCWT(t, creatorClaims(exp)))

	assert.ElementsMatch(t, []string{creatorCampaign, creatorSupporter, creatorFree, creatorTier555, publishValue}, grantFQNs(ev),
		"the creator's own campaign and tiers, and publish; arkavo.ai has no owner")
	for _, fqn := range []string{creatorCampaign, creatorSupporter, creatorFree, creatorTier555} {
		g := grantFor(t, ev, fqn)
		assert.Equal(t, []string{"read"}, g.Actions, fqn)
		assert.Equal(t, "patreon", g.Source, fqn)
	}
	publish := grantFor(t, ev, publishValue)
	assert.Equal(t, []string{"publish"}, publish.Actions)
	assert.Equal(t, "identity-core", publish.Source)

	require.Contains(t, ev.Props, "patreon")
	assert.Equal(t, []any{"13167240"}, ev.Props["patreon"]["campaign_ids"])
	assert.Equal(t, map[string]source.Outcome{
		"_token":        source.OutcomeComplete,
		"patreon":       source.OutcomeComplete,
		"identity-core": source.OutcomeComplete,
	}, ev.Outcomes)
	assert.Equal(t, evidenceVersion, ev.V)
	assert.Equal(t, creatorSub, ev.Sub)
}

// token-claims and device-class grants carry no actions; they take the
// source's configured ones, not read.
func TestTokenRoute_ActionlessGrantTakesSourceActions(t *testing.T) {
	defaulted := SourceConfig{ID: "defaulted", Issuer: testIssuer, Grants: []string{exampleDef}}
	svc := newTestService(t, testConfig(), verifiersFor(&fakeVerifier{}), []configuredSource{
		identityCoreSource(), // actions: [publish]
		sourceOf(defaulted, newTokenClaimsSource("example_entitlements", defaulted.Grants)),
	}, nil)
	claims := creatorClaims(time.Now().Add(time.Hour))
	claims["arkavo_entitlements"] = []any{publishValue}
	claims["example_entitlements"] = []any{exampleValue}

	ev := tokenEvidence(t, svc, signCWT(t, claims))

	assert.Equal(t, []string{"publish"}, grantFor(t, ev, publishValue).Actions)
	assert.Equal(t, []string{"read"}, grantFor(t, ev, exampleValue).Actions)
}

func TestTokenRoute_SourceCannotGrantOutsideCapability(t *testing.T) {
	log, buf := bufferLogger()
	rogue := fakeSourceOwning("rogue", fakeSource{res: source.Resolution{
		Outcome: source.OutcomeComplete,
		Grants: []source.Grant{
			{FQN: "https://patreon.arkavo.com/attr/campaign/value/1"}, // another source's definition
			{FQN: exampleValue, Actions: []string{"read", "publish"}}, // an action it may not grant
			{FQN: "not an fqn"},                                           // not a value FQN
			{FQN: "https://example.com/attr/a/value/kept"},                // its own
			{FQN: "HTTPS://EXAMPLE.COM/attr/a/value/Upper", Actions: nil}, // its own, lowercased
		},
	}}, exampleDef)
	svc := newTestService(t, testConfig(), verifiersFor(&fakeVerifier{}), []configuredSource{rogue}, nil)
	svc.logger = log

	ev := tokenEvidence(t, svc, signCWT(t, creatorClaims(time.Now().Add(time.Hour))))

	assert.ElementsMatch(t, []string{"https://example.com/attr/a/value/kept", "https://example.com/attr/a/value/upper"}, grantFQNs(ev))
	logs := buf.String()
	assert.Contains(t, logs, `"source_id":"rogue"`)
	assert.Contains(t, logs, "https://patreon.arkavo.com/attr/campaign/value/1")
	assert.Equal(t, 3, strings.Count(logs, "outside its capability"), logs)
}

func TestTokenRoute_SlowSourceIsUnavailable(t *testing.T) {
	cfg := testConfig()
	cfg.Deadline = 50 * time.Millisecond
	slow := fakeSourceOwning("slow", fakeSource{sleep: time.Second, res: granting(exampleValue)}, exampleDef)
	svc := newTestService(t, cfg, verifiersFor(&fakeVerifier{}), []configuredSource{slow, patreonSource()}, nil)
	token := signCWT(t, creatorClaims(time.Now().Add(time.Hour)))

	start := time.Now()
	ev := tokenEvidence(t, svc, token)
	elapsed := time.Since(start)

	assert.Less(t, elapsed, 500*time.Millisecond, "the slow source must not hold up the decision")
	assert.Equal(t, source.OutcomeUnavailable, ev.Outcomes["slow"])
	assert.Equal(t, source.OutcomeComplete, ev.Outcomes["patreon"])
	assert.NotContains(t, grantFQNs(ev), exampleValue)
	assert.Contains(t, grantFQNs(ev), creatorCampaign)
}

func TestTokenRoute_SourceErrorAndPanicAreUnavailable(t *testing.T) {
	broken := fakeSourceOwning("broken", fakeSource{res: granting(exampleValue), err: errors.New("upstream 500")}, exampleDef)
	panicky := fakeSourceOwning("panicky", fakeSource{panics: true}, otherDef)
	svc := newTestService(t, testConfig(), verifiersFor(&fakeVerifier{}), []configuredSource{broken, panicky, patreonSource()}, nil)

	ev := tokenEvidence(t, svc, signCWT(t, creatorClaims(time.Now().Add(time.Hour))))

	assert.Equal(t, source.OutcomeUnavailable, ev.Outcomes["broken"])
	assert.Equal(t, source.OutcomeUnavailable, ev.Outcomes["panicky"])
	assert.NotContains(t, grantFQNs(ev), exampleValue, "an erroring source contributes nothing, even what it returned")
	assert.Contains(t, grantFQNs(ev), creatorCampaign, "a failing source costs only its own grants")
}

// Only a complete resolution contributes: a source that reports itself
// unavailable or invalid, or answers with an outcome nobody defined, adds no
// grants and no properties.
func TestTokenRoute_OnlyCompleteOutcomesContribute(t *testing.T) {
	answering := func(id, def, value string, outcome source.Outcome) configuredSource {
		res := granting(value)
		res.Outcome = outcome
		res.Properties = map[string]any{"from": id}
		sc := SourceConfig{ID: id, Issuer: testIssuer, Grants: []string{def}, PropertiesKey: id}
		return sourceOf(sc, fakeSource{res: res})
	}
	svc := newTestService(t, testConfig(), verifiersFor(&fakeVerifier{}), []configuredSource{
		answering("unavailable", "https://example.com/attr/u", "https://example.com/attr/u/value/x", source.OutcomeUnavailable),
		answering("invalid", "https://example.com/attr/i", "https://example.com/attr/i/value/x", source.OutcomeInvalid),
		answering("not-applicable", "https://example.com/attr/n", "https://example.com/attr/n/value/x", source.OutcomeNotApplicable),
		answering("unknown", "https://example.com/attr/k", "https://example.com/attr/k/value/x", ""),
		answering("complete", exampleDef, exampleValue, source.OutcomeComplete),
	}, nil)

	ev := tokenEvidence(t, svc, signCWT(t, creatorClaims(time.Now().Add(time.Hour))))

	assert.Equal(t, []string{exampleValue}, grantFQNs(ev))
	assert.Equal(t, map[string]map[string]any{"complete": {"from": "complete"}}, ev.Props)
	assert.Equal(t, source.OutcomeUnavailable, ev.Outcomes["unavailable"])
	assert.Equal(t, source.OutcomeInvalid, ev.Outcomes["invalid"])
	assert.Equal(t, source.OutcomeNotApplicable, ev.Outcomes["not-applicable"])
	assert.Equal(t, source.OutcomeUnavailable, ev.Outcomes["unknown"])
}

// assertInvalidEvidence: an invalid token seals no grants, no properties and
// only the token's own outcome, for a minute.
func assertInvalidEvidence(t *testing.T, svc *Service, ev evidence) {
	t.Helper()
	assert.Empty(t, ev.Grants)
	assert.Empty(t, ev.Props)
	assert.Equal(t, map[string]source.Outcome{"_token": source.OutcomeInvalid}, ev.Outcomes)
	expiry := ev.Exp
	assert.Equal(t, svc.now().Add(60*time.Second).Unix(), expiry)
	assert.Equal(t, evidenceVersion, ev.V)
}

func TestTokenRoute_InvalidTokenSealsNoGrants(t *testing.T) {
	t.Run("verifier refuses", func(t *testing.T) {
		svc := newTestService(t, testConfig(), verifiersFor(&fakeVerifier{err: errors.New("cwt: signature does not verify")}),
			[]configuredSource{patreonSource(), identityCoreSource()}, nil)
		assertInvalidEvidence(t, svc, tokenEvidence(t, svc, signCWT(t, creatorClaims(time.Now().Add(time.Hour)))))
	})
	t.Run("not a token", func(t *testing.T) {
		svc := newTestService(t, testConfig(), verifiersFor(&fakeVerifier{claims: creatorClaims(time.Now().Add(time.Hour))}),
			[]configuredSource{patreonSource()}, nil)
		assertInvalidEvidence(t, svc, tokenEvidence(t, svc, "definitely-not-a-token"))
	})
}

func TestTokenRoute_MissingExpIsInvalid(t *testing.T) {
	for name, exp := range map[string]any{
		"absent":       nil,
		"not a number": "tomorrow",
		"in the past":  time.Now().Add(-time.Minute).Unix(),
	} {
		t.Run(name, func(t *testing.T) {
			claims := creatorClaims(time.Time{})
			if exp == nil {
				delete(claims, "exp")
			} else {
				claims["exp"] = exp
			}
			svc := newTestService(t, testConfig(), verifiersFor(&fakeVerifier{}), []configuredSource{patreonSource()}, nil)
			assertInvalidEvidence(t, svc, tokenEvidence(t, svc, signCWT(t, claims)))
		})
	}
}

func TestTokenRoute_UnknownIssuerIsInvalid(t *testing.T) {
	t.Run("no verifier for the issuer", func(t *testing.T) {
		// This verifier would accept anything: only the issuer lookup stands
		// between the forged token and the creator's grants.
		permissive := &fakeVerifier{claims: creatorClaims(time.Now().Add(time.Hour))}
		svc := newTestService(t, testConfig(), verifiersFor(permissive), []configuredSource{patreonSource()}, nil)
		claims := creatorClaims(time.Now().Add(time.Hour))
		claims["iss"] = "https://evil.example.com"

		assertInvalidEvidence(t, svc, tokenEvidence(t, svc, signCWT(t, claims)))
		assert.Zero(t, permissive.calls.Load(), "no verifier may be asked about another issuer's token")
	})
	t.Run("verified claims name another issuer", func(t *testing.T) {
		verified := creatorClaims(time.Now().Add(time.Hour))
		verified["iss"] = "https://evil.example.com"
		svc := newTestService(t, testConfig(), verifiersFor(&fakeVerifier{claims: verified}), []configuredSource{patreonSource()}, nil)

		assertInvalidEvidence(t, svc, tokenEvidence(t, svc, signCWT(t, creatorClaims(time.Now().Add(time.Hour)))))
	})
}

// An unsigned JOSE JWT (alg=none), the RAR bridge's format, is not a CWT, so
// it never reaches a verifier, whatever entitlements it carries.
func TestTokenRoute_UnsignedJWTIsInvalid(t *testing.T) {
	claims := creatorClaims(time.Time{})
	claims["exp"] = time.Now().Add(time.Hour).Unix()
	body, err := json.Marshal(claims)
	require.NoError(t, err)
	header := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"none","typ":"JWT"}`))
	unsigned := header + "." + base64.RawURLEncoding.EncodeToString(body) + "."

	permissive := &fakeVerifier{claims: creatorClaims(time.Now().Add(time.Hour))}
	svc := newTestService(t, testConfig(), verifiersFor(permissive), []configuredSource{patreonSource(), identityCoreSource()}, nil)

	assertInvalidEvidence(t, svc, tokenEvidence(t, svc, unsigned))
	assert.Zero(t, permissive.calls.Load())
}

// Ported from patreon/v2/cwt_token_test.go: a verified CWT may carry
// CBOR-native values (a tag-1 timestamp decodes to time.Time, an unknown tag
// to cbor.Tag). They must neither break the seal nor cost the grants.
func TestTokenRoute_CBORNativeClaimValues(t *testing.T) {
	arkavoPatreon := map[string]any{
		"role":            "consumer",
		"patreon_user_id": "p-77",
		"last_charge_at":  time.Unix(1700000000, 0),
		"attestation":     []byte{0xde, 0xad, 0xbe, 0xef},
		"unknown_tag":     cbor.Tag{Number: 999, Content: "opaque"},
		"memberships": []any{map[string]any{
			"campaign_id":   "11111111",
			"patron_status": "active_patron",
			"tier_slugs":    []any{"gold-tier"},
			"pledge_start":  time.Unix(1700000000, 0),
		}},
	}
	verified := map[string]any{
		"iss": testIssuer, "sub": "did:key:z6Mkconsumer",
		"exp":            time.Now().Add(time.Hour).Unix(),
		"arkavo_patreon": arkavoPatreon,
		"arkavo_entitlements": []any{
			"https://patreon.arkavo.com/attr/campaign/value/11111111",
			"https://patreon.arkavo.com/attr/campaign-tier/value/11111111_gold-tier",
		},
	}
	// echo hands the raw claim back as its properties, so the seal has to
	// cope with whatever a source puts there.
	echo := sourceOf(SourceConfig{ID: "echo", Issuer: testIssuer, Grants: []string{exampleDef}, PropertiesKey: "raw"},
		sourceFunc(func(_ context.Context, s source.Subject, _ source.Query) (source.Resolution, error) {
			raw, _ := s.Claims["arkavo_patreon"].(map[string]any)
			return source.Resolution{Properties: raw, Outcome: source.OutcomeComplete}, nil
		}))
	svc := newTestService(t, testConfig(), verifiersFor(&fakeVerifier{claims: verified}), []configuredSource{patreonSource(), echo}, nil)

	ev := tokenEvidence(t, svc, signCWT(t, map[string]any{"iss": testIssuer}))

	assert.ElementsMatch(t, []string{
		"https://patreon.arkavo.com/attr/campaign/value/11111111",
		"https://patreon.arkavo.com/attr/campaign-tier/value/11111111_gold-tier",
	}, grantFQNs(ev))
	assert.Equal(t, "active", ev.Props["patreon"]["status"])
	raw := ev.Props["raw"]
	assert.InDelta(t, 1700000000, raw["last_charge_at"], 0, "timestamps travel as epoch seconds")
	assert.Equal(t, "3q2-7w", raw["attestation"], "byte strings travel as base64url")
	assert.NotContains(t, raw, "unknown_tag", "a value with no representation is dropped")
}

func TestTokenRoute_EvidenceExpiryIsTokenExpiry(t *testing.T) {
	exp := time.Now().Add(17 * time.Minute).Truncate(time.Second)
	grantExp := time.Now().Add(5 * time.Minute).Truncate(time.Second)
	leased := fakeSourceOwning("leased", fakeSource{res: source.Resolution{
		Outcome: source.OutcomeComplete,
		Grants:  []source.Grant{{FQN: exampleValue, ExpiresAt: grantExp}},
	}}, exampleDef)
	svc := newTestService(t, testConfig(), verifiersFor(&fakeVerifier{}), []configuredSource{patreonSource(), leased}, nil)

	ev := tokenEvidence(t, svc, signCWT(t, creatorClaims(exp)))

	expiry := ev.Exp
	assert.Equal(t, exp.Unix(), expiry)
	assert.Zero(t, grantFor(t, ev, creatorCampaign).Exp, "a token-carried grant expires with the evidence")
	leasedExpiry := grantFor(t, ev, exampleValue).Exp
	assert.Equal(t, grantExp.Unix(), leasedExpiry)
}

// Expiring grants, relative to a pinned now, and the FQNs of those still live.
const (
	expiredValue  = exampleDef + "/value/expired"
	expiringNow   = exampleDef + "/value/expiring-now"
	liveValue     = exampleDef + "/value/live"
	outlivesValue = exampleDef + "/value/outlives-evidence"
)

func expiringGrants(now time.Time) source.Resolution {
	return source.Resolution{
		Outcome: source.OutcomeComplete,
		Grants: []source.Grant{
			{FQN: expiredValue, ExpiresAt: now.Add(-time.Hour)},
			{FQN: expiringNow, ExpiresAt: now},
			{FQN: liveValue, ExpiresAt: now.Add(time.Minute)},
			{FQN: outlivesValue, ExpiresAt: now.Add(24 * time.Hour)},
		},
	}
}

// A source grant whose own expiry has passed is never sealed, and one that
// outlives the token is sealed to expire with the evidence. resolveToken is
// asserted directly: openEvidence drops expired grants as well, which would
// hide what the seal carries.
func TestTokenRoute_ExpiredSourceGrantIsNotSealed(t *testing.T) {
	now := time.Now().Truncate(time.Second)
	leased := fakeSourceOwning("leased", fakeSource{res: expiringGrants(now)}, exampleDef)
	svc := newTestService(t, testConfig(), verifiersFor(&fakeVerifier{}), []configuredSource{leased}, nil)
	svc.now = func() time.Time { return now }
	exp := now.Add(10 * time.Minute)

	ev := svc.resolveToken(t.Context(), signCWT(t, creatorClaims(exp)), source.Query{Action: "read"})

	assert.ElementsMatch(t, []string{liveValue, outlivesValue}, grantFQNs(ev), "expired and expiring-now grants are dropped")
	liveExpiry, outlivesExpiry := grantFor(t, ev, liveValue).Exp, grantFor(t, ev, outlivesValue).Exp
	assert.Equal(t, now.Add(time.Minute).Unix(), liveExpiry)
	assert.Equal(t, exp.Unix(), outlivesExpiry, "clamped to the evidence expiry")
	assert.Equal(t, ev, tokenEvidence(t, svc, signCWT(t, creatorClaims(exp))), "the seal carries exactly this")
}

func TestTokenRoute_SourceOrderIsIrrelevant(t *testing.T) {
	extra := fakeSourceOwning("extra", fakeSource{res: granting(exampleValue)}, exampleDef)
	sources := []configuredSource{patreonSource(), identityCoreSource(), extra}
	reversed := []configuredSource{extra, identityCoreSource(), patreonSource()}
	token := signCWT(t, creatorClaims(time.Now().Add(time.Hour)))

	forward := newTestService(t, testConfig(), verifiersFor(&fakeVerifier{}), sources, nil)
	backward := newTestService(t, testConfig(), verifiersFor(&fakeVerifier{}), reversed, nil)
	backward.now = forward.now

	assert.Equal(t, tokenEvidence(t, forward, token), tokenEvidence(t, backward, token))
}

// Two sources granting one FQN (only possible when New is handed sources
// that bypassed Validate) merge into one grant whose provenance is the first
// source in configured order, however the goroutines finish.
func TestTokenRoute_UnionKeepsFirstConfiguredSource(t *testing.T) {
	first := sourceOf(SourceConfig{ID: "first", Issuer: testIssuer, Grants: []string{exampleDef}},
		fakeSource{sleep: 20 * time.Millisecond, res: granting(exampleValue)})
	second := sourceOf(SourceConfig{ID: "second", Issuer: testIssuer, Grants: []string{exampleDef}, Actions: []string{"read", "publish"}},
		fakeSource{res: source.Resolution{Outcome: source.OutcomeComplete, Grants: []source.Grant{{FQN: exampleValue, Actions: []string{"publish", "read"}}}}})
	svc := newTestService(t, testConfig(), verifiersFor(&fakeVerifier{}), []configuredSource{first, second}, nil)
	token := signCWT(t, creatorClaims(time.Now().Add(time.Hour)))

	want := tokenEvidence(t, svc, token)
	require.Len(t, want.Grants, 1)
	assert.Equal(t, sealedGrant{FQN: exampleValue, Actions: []string{"publish", "read"}, Source: "first"}, want.Grants[0])
	for range 10 {
		assert.Equal(t, want, tokenEvidence(t, svc, token))
	}
}

func TestTokenRoute_QueryCarriesRequestedResources(t *testing.T) {
	var seen source.Query
	recorder := fakeSourceOwning("recorder", sourceFunc(func(_ context.Context, _ source.Subject, q source.Query) (source.Resolution, error) {
		seen = q
		return source.Resolution{Outcome: source.OutcomeNotApplicable}, nil
	}), exampleDef)
	svc := newTestService(t, testConfig(), verifiersFor(&fakeVerifier{}), []configuredSource{recorder}, nil)

	tokenEvidence(t, svc, signCWT(t, creatorClaims(time.Now().Add(time.Hour))),
		&authzV2.Resource{Resource: &authzV2.Resource_AttributeValues_{AttributeValues: &authzV2.Resource_AttributeValues{
			Fqns: []string{"https://Patreon.arkavo.com/attr/campaign/value/13167240", creatorSupporter},
		}}},
		&authzV2.Resource{Resource: &authzV2.Resource_RegisteredResourceValueFqn{RegisteredResourceValueFqn: "https://reg.example/reg_res/r/value/v"}},
	)

	assert.Equal(t, source.Query{Action: "read", Resources: []string{creatorCampaign, creatorSupporter}}, seen)
}

func TestTokenRoute_OneChainPerToken(t *testing.T) {
	svc := newTestService(t, testConfig(), verifiersFor(&fakeVerifier{}), []configuredSource{patreonSource()}, nil)
	chains := chainsFor(t, svc, []*entity.Token{
		{EphemeralId: "creator", Jwt: signCWT(t, creatorClaims(time.Now().Add(time.Hour)))},
		{EphemeralId: "garbage", Jwt: "definitely-not-a-token"},
	})

	require.Equal(t, "creator", chains[0].GetEphemeralId())
	require.Len(t, chains[0].GetEntities(), 1)
	assert.Contains(t, grantFQNs(openEntity(t, svc, chains[0].GetEntities()[0])), creatorCampaign)
	require.Equal(t, "garbage", chains[1].GetEphemeralId())
	require.Len(t, chains[1].GetEntities(), 1)
	assertInvalidEvidence(t, svc, openEntity(t, svc, chains[1].GetEntities()[0]))
}

// The subject entity's ephemeral ID becomes the representation's original ID,
// which decision audits record, so it names the viewer: the verified sub, or
// anonymous when there is none.
func TestTokenRoute_SubjectEphemeralIDNamesTheViewer(t *testing.T) {
	svc := newTestService(t, testConfig(), verifiersFor(&fakeVerifier{}), []configuredSource{patreonSource()}, nil)
	noSub := creatorClaims(time.Now().Add(time.Hour))
	delete(noSub, "sub")

	chains := chainsFor(t, svc, []*entity.Token{
		{EphemeralId: "creator", Jwt: signCWT(t, creatorClaims(time.Now().Add(time.Hour)))},
		{EphemeralId: "no-sub", Jwt: signCWT(t, noSub)},
		{EphemeralId: "garbage", Jwt: "definitely-not-a-token"},
	})

	assert.Equal(t, "composite-subject-did:key:z6Mkcreator", chains[0].GetEntities()[0].GetEphemeralId())
	assert.Equal(t, "composite-subject-anonymous", chains[1].GetEntities()[0].GetEphemeralId())
	assert.Equal(t, "composite-subject-anonymous", chains[2].GetEntities()[0].GetEphemeralId())
}

// A subject with no trust keeps no claims, so claims that were discarded
// cannot make it a device and earn it device-class grants (Task 8 routes
// such subjects here).
func TestResolveSubject_TrustNoneNeverGetsDeviceClassGrants(t *testing.T) {
	devices := SourceConfig{ID: "device-class", Issuer: testIssuer, Grants: []string{"https://arkavo.ai/attr/classification"}}
	svc := newTestService(t, testConfig(), nil, []configuredSource{
		sourceOf(devices, newDeviceClassSource(map[string][]string{
			"unverified": {classInternal},
			"managed":    {classConfidential},
		})),
	}, nil)
	discarded := map[string]any{"iss": testIssuer, "arkavo_npe": map[string]any{"type": "device", "class": "managed"}}

	for name, subj := range map[string]source.Subject{
		"empty claims":                      {Trust: source.TrustNone, Kind: source.KindPerson, Claims: map[string]any{}},
		"discarded device claims":           {Trust: source.TrustNone, Kind: source.KindDevice, Claims: discarded},
		"discarded claims, device kind set": {Trust: source.TrustNone, Kind: source.KindDevice},
	} {
		t.Run(name, func(t *testing.T) {
			ev := svc.resolveSubject(t.Context(), subj, source.Query{Action: "read"}, svc.now().Add(time.Minute))
			assert.Empty(t, ev.Grants)
		})
	}
}

func TestNew_SealKeys(t *testing.T) {
	t.Run("the first key seals, every key opens", func(t *testing.T) {
		svc := newTestService(t, testConfig(), nil, nil, nil)
		current, err := decodeKey(testSealKey)
		require.NoError(t, err)
		previous, err := decodeKey(oldSealKey)
		require.NoError(t, err)
		assert.Equal(t, [][]byte{current, previous}, svc.sealKeys)
		assert.Nil(t, svc.agentStatus, "no checker is a nil interface, so every agent is withheld")
	})
	for name, mutate := range map[string]func(*Config){
		"missing seal key":  func(c *Config) { c.Evidence.SealKey = "" },
		"short seal key":    func(c *Config) { c.Evidence.SealKey = base64.StdEncoding.EncodeToString([]byte("short")) },
		"unpadded seal key": func(c *Config) { c.Evidence.SealKey = strings.TrimRight(oldSealKey, "=") },
		"bad previous key":  func(c *Config) { c.Evidence.PreviousSealKeys = []string{"%%%"} },
		"short previous key": func(c *Config) {
			c.Evidence.PreviousSealKeys = []string{base64.StdEncoding.EncodeToString([]byte("short"))}
		},
	} {
		t.Run(name, func(t *testing.T) {
			cfg := testConfig()
			mutate(&cfg)
			_, err := New(cfg, nil, nil, nil, testLogger(t))
			require.Error(t, err)
			for _, key := range append([]string{cfg.Evidence.SealKey}, cfg.Evidence.PreviousSealKeys...) {
				if key != "" {
					assert.NotContains(t, err.Error(), key, "never echo a key")
				}
			}
		})
	}
}
