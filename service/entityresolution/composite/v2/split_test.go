package composite

import (
	"context"
	"testing"
	"time"

	"github.com/opentdf/platform/protocol/go/entity"
	"github.com/opentdf/platform/service/entityresolution/source"
	"github.com/opentdf/platform/service/internal/agentstatus"
	"github.com/opentdf/platform/service/internal/chaindevice"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const platformAudience = "https://platform.arkavo.net"

// iosDevice is the device splitTokenClaims(exp) describes, as it is sealed.
func iosDevice(exp time.Time) *sealedDevice {
	return &sealedDevice{
		Class: chaindevice.ClassAttested, AppIDHash: iosAppHash, AppEnv: chaindevice.EnvProduction,
		AttestationExpiry: exp.Unix(),
	}
}

// splitTokenClaims are a DeviceCheck token used as the subject, as iOS
// presents it at KAS rewrap: the creator's claims, and the creator's device,
// attested until the token expires, running the production iOS app, its key
// bound by cnf.
func splitTokenClaims(exp time.Time) map[string]any {
	claims := creatorClaims(exp)
	claims["aud"] = []any{source.DeviceCheckAudience, platformAudience}
	claims["cnf"] = map[string]any{"jwk": map[string]any{
		"kty": "EC", "crv": "P-256",
		"x": "f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU",
		"y": "x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0",
	}}
	claims["arkavo_npe"] = map[string]any{
		"type":               "device",
		"class":              chaindevice.ClassAttested,
		"device_id":          "d1",
		"app_id_hash":        iosAppHash,
		"app_env":            chaindevice.EnvProduction,
		"attestation_expiry": exp.Unix(),
	}
	return claims
}

// splitService resolves with the patreon source, identity-core serving
// persons alone, so publish is granted only to a subject judged a person,
// and a recorder of the subject the sources are asked about.
func splitService(t *testing.T, checker agentstatus.Checker) (*Service, *source.Subject) {
	t.Helper()
	seen := &source.Subject{}
	identity := SourceConfig{
		ID: "identity-core", Issuer: testIssuer,
		Grants:   []string{creatorDef},
		Actions:  []string{"publish"},
		Subjects: []source.Kind{source.KindPerson},
	}
	recorder := fakeSourceOwning("recorder", sourceFunc(func(_ context.Context, s source.Subject, _ source.Query) (source.Resolution, error) {
		*seen = s
		return source.Resolution{Outcome: source.OutcomeNotApplicable}, nil
	}), exampleDef)
	svc := newTestService(t, testConfig(), verifiersFor(&fakeVerifier{}), []configuredSource{
		patreonSource(),
		sourceOf(identity, newTokenClaimsSource("arkavo_entitlements", identity.Grants)),
		recorder,
	}, checker)
	return svc, seen
}

// A DeviceCheck token used as the subject is split: the sources resolve its
// person, as any person token, and its device is sealed beside the person's
// grants.
func TestSplit_PersonResolvesAsPerson(t *testing.T) {
	svc, seen := splitService(t, nil)

	exp := svc.now().Add(time.Hour)

	ev := tokenEvidence(t, svc, signCWT(t, splitTokenClaims(exp)))

	assert.Contains(t, grantFQNs(ev), publishValue, "identity-core serves persons alone")
	assert.Contains(t, grantFQNs(ev), creatorCampaign)
	assert.Equal(t, iosDevice(exp), ev.Device)
	assert.Equal(t, creatorAccount, ev.AccountID)
	assert.Equal(t, testIssuer, ev.Iss)
	assert.Equal(t, creatorSub, ev.Sub)

	assert.Equal(t, source.KindPerson, seen.Kind)
	assert.Equal(t, source.TrustVerified, seen.Trust)
	assert.Equal(t, creatorAccount, seen.AccountID)
	assert.NotContains(t, seen.Claims, agentstatus.ClaimNpe, "the device's claims are not the person's")
	assert.NotContains(t, seen.Claims, "cnf")
	assert.Equal(t, []any{platformAudience}, seen.Claims["aud"])
}

// A token whose only audience is DeviceCheck's splits alike, and its person
// has no audience left.
func TestSplit_StringAudience(t *testing.T) {
	svc, seen := splitService(t, nil)
	exp := svc.now().Add(time.Hour)
	claims := splitTokenClaims(exp)
	claims["aud"] = source.DeviceCheckAudience

	ev := tokenEvidence(t, svc, signCWT(t, claims))

	assert.Contains(t, grantFQNs(ev), publishValue)
	assert.Contains(t, grantFQNs(ev), creatorCampaign)
	assert.Equal(t, iosDevice(exp), ev.Device)
	assert.Equal(t, creatorAccount, ev.AccountID)
	assert.Equal(t, source.KindPerson, seen.Kind)
	assert.NotContains(t, seen.Claims, "aud")
	assert.NotContains(t, personClaims(claims), "aud")
}

// The sealed device is what deviceFromClaims reads from the verified token,
// so its class is always one the PDP knows: anything else reads unverified.
func TestSplit_DeviceIsWhatTheTokenSays(t *testing.T) {
	for name, tc := range map[string]struct {
		npe  any // nil removes arkavo_npe; the aud still makes it a device token
		want *sealedDevice
	}{
		"managed, development": {
			map[string]any{"type": "device", "class": chaindevice.ClassManaged, "app_id_hash": iosAppHash, "app_env": chaindevice.EnvDevelopment},
			&sealedDevice{Class: chaindevice.ClassManaged, AppIDHash: iosAppHash, AppEnv: chaindevice.EnvDevelopment},
		},
		"an unknown class and environment": {
			map[string]any{"type": "device", "class": "Attested", "app_id_hash": iosAppHash, "app_env": "staging"},
			&sealedDevice{Class: chaindevice.ClassUnverified, AppIDHash: iosAppHash},
		},
		"no arkavo_npe": {nil, &sealedDevice{Class: chaindevice.ClassUnverified}},
	} {
		t.Run(name, func(t *testing.T) {
			svc, seen := splitService(t, nil)
			claims := splitTokenClaims(svc.now().Add(time.Hour))
			delete(claims, agentstatus.ClaimNpe)
			if tc.npe != nil {
				claims[agentstatus.ClaimNpe] = tc.npe
			}
			require.Equal(t, source.KindDevice, source.KindOf(claims))

			ev := tokenEvidence(t, svc, signCWT(t, claims))

			assert.Equal(t, tc.want, ev.Device)
			assert.Equal(t, source.KindPerson, seen.Kind)
			assert.Contains(t, grantFQNs(ev), publishValue)
		})
	}
}

// The token route's subject carries its device into the second call, whoever
// makes it: the marker reads verified and bound, the device being the
// subject's own, and the person keeps its direct entitlements.
func TestSplit_RepresentationCarriesBoundDevice(t *testing.T) {
	svc, _ := splitService(t, nil)
	chain := chainsFor(t, svc, []*entity.Token{{EphemeralId: "t0", Jwt: signCWT(t, splitTokenClaims(svc.now().Add(time.Hour)))}})[0]

	rep := resolveAs(callerContext(t.Context(), "arks-media"), t, svc, chain.GetEntities()...)[0]

	assert.Equal(t, attestedIOS(true), deviceOf(t, rep))
	assert.Equal(t, map[string][]string{
		creatorCampaign:  {"read"},
		creatorSupporter: {"read"},
		creatorFree:      {"read"},
		creatorTier555:   {"read"},
		publishValue:     {"publish"},
	}, entitlements(rep))
}

// An agent marker wins in KindOf, so a device token carrying one is an agent:
// it is never split, and the agent gate judges it as before. Its arkavo_npe
// is a device's, not an agent profile, so the gate withholds it before the
// status service is asked.
func TestSplit_AgentMarkerNotSplit(t *testing.T) {
	checker := &countingChecker{} // finds every agent it is asked about eligible
	svc, seen := splitService(t, checker)
	log, buf := bufferLogger()
	svc.logger = log
	claims := splitTokenClaims(svc.now().Add(time.Hour))
	claims[agentstatus.ClaimSwarm] = "kit-42"
	require.Equal(t, source.KindAgent, source.KindOf(claims))

	chain := chainsFor(t, svc, []*entity.Token{{EphemeralId: "t0", Jwt: signCWT(t, claims)}})[0]
	ev := openEntity(t, svc, chain.GetEntities()[0])

	assert.Nil(t, ev.Device, "an agent is never split")
	assert.Empty(t, ev.Grants)
	assert.Empty(t, ev.Props)
	assert.Zero(t, *seen, "no source is asked about a withheld agent")
	assert.Zero(t, checker.calls.Load())
	assert.Contains(t, buf.String(), "agent entitlements withheld")
	assert.Contains(t, buf.String(), "arkavo_npe.type is not agent")

	rep := resolveAs(callerContext(t.Context(), "arks-media"), t, svc, chain.GetEntities()...)[0]
	_, isDevice := chaindevice.FromRepresentation(rep)
	assert.False(t, isDevice, "the representation carries no device")
	assert.Empty(t, rep.GetDirectEntitlements())
}

// personClaims drops what is the device's, and KindOf judges what is left a
// person's, whatever form aud takes.
func TestPersonClaims(t *testing.T) {
	for name, tc := range map[string]struct {
		aud     any // nil: no aud
		wantAud any // nil: no aud
	}{
		"a list":                         {[]any{source.DeviceCheckAudience, platformAudience}, []any{platformAudience}},
		"a list of DeviceCheck alone":    {[]any{source.DeviceCheckAudience}, nil},
		"a list keeps other entries":     {[]any{platformAudience, 7.0, source.DeviceCheckAudience}, []any{platformAudience, 7.0}},
		"a string list":                  {[]string{platformAudience, source.DeviceCheckAudience}, []string{platformAudience}},
		"a string list of DeviceCheck":   {[]string{source.DeviceCheckAudience}, nil},
		"the DeviceCheck string":         {source.DeviceCheckAudience, nil},
		"another string":                 {platformAudience, platformAudience},
		"no aud":                         {nil, nil},
		"an aud of another type is kept": {42.0, 42.0},
	} {
		t.Run(name, func(t *testing.T) {
			exp := time.Now().Add(time.Hour)
			claims := splitTokenClaims(exp)
			delete(claims, "aud")
			if tc.aud != nil {
				claims["aud"] = tc.aud
			}

			person := personClaims(claims)

			want := creatorClaims(exp)
			if tc.wantAud != nil {
				want["aud"] = tc.wantAud
			}
			assert.Equal(t, want, person, "the creator's claims, without arkavo_npe and cnf")
			assert.Equal(t, source.KindPerson, source.KindOf(person))
		})
	}
}

// personClaims copies: neither the claims nor the aud list they hold change.
func TestPersonClaims_DoesNotMutate(t *testing.T) {
	exp := time.Now().Add(time.Hour)
	for name, aud := range map[string]func() any{
		"a list":        func() any { return []any{source.DeviceCheckAudience, platformAudience} },
		"a string list": func() any { return []string{source.DeviceCheckAudience, platformAudience} },
		"a string":      func() any { return source.DeviceCheckAudience },
	} {
		t.Run(name, func(t *testing.T) {
			fixture := func() map[string]any {
				claims := splitTokenClaims(exp)
				claims["aud"] = aud()
				return claims
			}
			claims := fixture()

			personClaims(claims)

			assert.Equal(t, fixture(), claims)
		})
	}
}

// A DeviceCheck token used as the subject seals its class when the token
// route resolves it, and the evidence lasts until the token expires, an hour.
// attested still lapses at the token's attestation_expiry: the device reads
// managed once that has passed when the evidence is opened, even if it was
// attested when sealed.
func TestSplit_AttestationLapsesAfterSeal(t *testing.T) {
	for name, tc := range map[string]struct {
		expiry  func(now time.Time) any // nil: no attestation_expiry
		openAt  time.Duration           // after sealing
		want    string
		comment string
	}{
		"attested when opened": {func(now time.Time) any { return now.Add(15 * time.Minute).Unix() }, 10 * time.Minute, chaindevice.ClassAttested, ""},
		"lapses between seal and open": {
			func(now time.Time) any { return now.Add(15 * time.Minute).Unix() }, 16 * time.Minute, chaindevice.ClassManaged,
			"the evidence is still valid, the attestation is not",
		},
		"already lapsed when sealed": {func(now time.Time) any { return now.Add(-time.Second).Unix() }, 0, chaindevice.ClassManaged, ""},
		"no attestation_expiry":      {nil, 0, chaindevice.ClassManaged, ""},
	} {
		t.Run(name, func(t *testing.T) {
			svc, _ := splitService(t, nil)
			sealedAt := svc.now()
			claims := splitTokenClaims(sealedAt.Add(time.Hour))
			npe, ok := claims["arkavo_npe"].(map[string]any)
			require.True(t, ok)
			delete(npe, "attestation_expiry")
			if tc.expiry != nil {
				npe["attestation_expiry"] = tc.expiry(sealedAt)
			}
			chain := chainsFor(t, svc, []*entity.Token{{EphemeralId: "t0", Jwt: signCWT(t, claims)}})[0]

			openedAt := sealedAt.Add(tc.openAt)
			svc.now = func() time.Time { return openedAt }
			rep := resolveAs(callerContext(t.Context(), "arks-media"), t, svc, chain.GetEntities()...)[0]

			want := attestedIOS(true)
			want.Class = tc.want
			assert.Equal(t, want, deviceOf(t, rep), tc.comment)
			assert.Contains(t, entitlements(rep), publishValue, "the person keeps its grants; the rules decide what a managed device leaves")
		})
	}
}
