package composite

import (
	"bytes"
	"encoding/json"
	"errors"
	"maps"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/opentdf/platform/protocol/go/entity"
	entityresolutionV2 "github.com/opentdf/platform/protocol/go/entityresolution/v2"
	"github.com/opentdf/platform/service/entityresolution/source"
	"github.com/opentdf/platform/service/internal/chaindevice"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const (
	otherAccount = "00000000-0000-0000-0000-00000000beef"
	unboundMsg   = "composite: device is not bound to the request's subjects; the chain is denied"
)

// attestedIOS is the device deviceTokenClaims describes.
func attestedIOS(bound bool) chaindevice.Device {
	return chaindevice.Device{
		Class:     chaindevice.ClassAttested,
		Verified:  true,
		Bound:     bound,
		AppIDHash: iosAppHash,
		AppEnv:    chaindevice.EnvProduction,
	}
}

// deviceService is the composite as production configures it, with verifier
// for the test issuer, logging every record into the returned buffer.
func deviceService(t *testing.T, verifier *fakeVerifier) (*Service, *bytes.Buffer) {
	t.Helper()
	svc := newTestService(t, pepConfig(), verifiersFor(verifier),
		[]configuredSource{pepPatreonSource(), identityCoreSource()}, nil)
	log, buf := bufferLogger()
	svc.logger = log
	return svc, buf
}

// markerProps returns the device marker rep carries, as the composite wrote
// it, before chaindevice reads it.
func markerProps(t *testing.T, rep *entityresolutionV2.EntityRepresentation) map[string]any {
	t.Helper()
	for _, props := range rep.GetAdditionalProps() {
		if m, ok := props.AsMap()[chaindevice.PropKey].(map[string]any); ok {
			return m
		}
	}
	require.Failf(t, "no device marker", "representation %q", rep.GetOriginalId())
	return nil
}

// deviceOf reads the device marker of rep, which must carry one.
func deviceOf(t *testing.T, rep *entityresolutionV2.EntityRepresentation) chaindevice.Device {
	t.Helper()
	d, ok := chaindevice.FromRepresentation(rep)
	require.True(t, ok, "representation %q carries no device marker", rep.GetOriginalId())
	return d
}

// requireMarkerOnly asserts rep is a device token's: no grants and no
// properties but the marker. The Patreon source infers a free view for any
// subject it sees, so its absence shows no source resolved the token.
func requireMarkerOnly(t *testing.T, rep *entityresolutionV2.EntityRepresentation) {
	t.Helper()
	assert.Empty(t, rep.GetDirectEntitlements(), "a device token holds no grants")
	require.Len(t, rep.GetAdditionalProps(), 1)
	assert.Equal(t, []string{chaindevice.PropKey}, slices.Sorted(maps.Keys(rep.GetAdditionalProps()[0].AsMap())),
		"no source resolved the device token")
}

// A device token in a PEP's chain is verified with its issuer's verifier and
// bound to the person by iss and arkavo_account_id. It says what the device
// is and holds no grants; the person keeps its own.
func TestDeviceToken_VerifiedAndBound(t *testing.T) {
	svc, buf := deviceService(t, &fakeVerifier{})
	token := signCWT(t, deviceTokenClaims(svc.now().Add(time.Hour)))

	reps := resolveAs(callerContext(t.Context(), testPEP), t, svc,
		claimsEntity(t, "e0", catalogCreatorClaims()), deviceTokenEnv(t, "e1", token))

	assert.Equal(t, "e1", reps[1].GetOriginalId())
	assert.Equal(t, attestedIOS(true), deviceOf(t, reps[1]))
	assert.Equal(t, attestedIOS(true).Props(), markerProps(t, reps[1]), "the marker has the fixed shape")
	requireMarkerOnly(t, reps[1])

	_, isDevice := chaindevice.FromRepresentation(reps[0])
	assert.False(t, isDevice, "the person carries no marker")
	assert.Equal(t, map[string][]string{creatorCampaign: {"read"}, creatorSupporter: {"read"}}, entitlements(reps[0]),
		"the person keeps its own grants")
	assert.NotContains(t, buf.String(), token, "the raw token is never logged")
}

// A device token for another account is verified but does not bind, and the
// refusal is logged with its reason.
func TestDeviceToken_AccountMismatchUnbound(t *testing.T) {
	svc, buf := deviceService(t, &fakeVerifier{})
	claims := deviceTokenClaims(svc.now().Add(time.Hour))
	claims[claimAccountID] = otherAccount
	token := signCWT(t, claims)

	reps := resolveAs(callerContext(t.Context(), testPEP), t, svc,
		claimsEntity(t, "e0", catalogCreatorClaims()), deviceTokenEnv(t, "e1", token))

	assert.Equal(t, attestedIOS(false), deviceOf(t, reps[1]))
	rec := logRecord(t, buf, unboundMsg)
	assert.Equal(t, "WARN", rec["level"])
	assert.Equal(t, "e1", rec["entity_id"])
	assert.Equal(t, "account mismatch", rec["reason"])
	assert.Equal(t, "e0", rec["subject_id"])
	assert.NotContains(t, buf.String(), token, "the raw token is never logged")
	assert.NotContains(t, buf.String(), otherAccount, "nor the accounts compared")
}

// The signature, not the caller, is what a device token is trusted for, so a
// caller not on claims_chain_peps still gets a verified device. Its person's
// claims are discarded, and an anonymous person binds no device.
func TestDeviceToken_FromAnyCaller(t *testing.T) {
	svc, _ := deviceService(t, &fakeVerifier{})
	token := signCWT(t, deviceTokenClaims(svc.now().Add(time.Hour)))

	reps := resolveAs(callerContext(t.Context(), "arks-media"), t, svc,
		claimsEntity(t, "e0", catalogCreatorClaims()), deviceTokenEnv(t, "e1", token))

	assert.Equal(t, attestedIOS(false), deviceOf(t, reps[1]))
	requireMarkerOnly(t, reps[1])
	assert.Empty(t, reps[0].GetDirectEntitlements())
}

// A device token is a device whatever the category of the entity it comes
// in. Sent as a subject it still holds no grants, so the PDP, which needs
// every subject entitled, denies the chain.
func TestDeviceToken_AsSubjectHoldsNoGrants(t *testing.T) {
	svc, _ := deviceService(t, &fakeVerifier{})
	token := signCWT(t, deviceTokenClaims(svc.now().Add(time.Hour)))

	reps := resolveAs(callerContext(t.Context(), testPEP), t, svc,
		claimsEntity(t, "e0", catalogCreatorClaims()), claimsEntity(t, "e1", map[string]any{chaindevice.TokenClaim: token}))

	assert.Equal(t, attestedIOS(true), deviceOf(t, reps[1]))
	requireMarkerOnly(t, reps[1])
}

// A device token that does not verify, has expired or is not a device's is a
// device of class unverified with no app. It still carries a marker, so the
// PDP denies rather than skipping the device.
func TestDeviceToken_InvalidIsUnverified(t *testing.T) {
	exp := time.Now().Add(time.Hour)
	notADevice := deviceTokenClaims(exp)
	delete(notADevice, "arkavo_npe")
	notADevice["aud"] = "x"
	expired := deviceTokenClaims(time.Now().Add(-time.Minute))
	agent := deviceTokenClaims(exp)
	agent["arkavo_swarm"] = map[string]any{"swarm_id": "s"}
	otherIssuer := deviceTokenClaims(exp)
	otherIssuer["iss"] = "https://identity.example"

	for name, tc := range map[string]struct {
		verifier *fakeVerifier
		token    any
	}{
		"signature does not verify": {&fakeVerifier{err: errors.New("bad signature")}, signCWT(t, deviceTokenClaims(exp))},
		"expired":                   {&fakeVerifier{}, signCWT(t, expired)},
		"not a device token":        {&fakeVerifier{}, signCWT(t, notADevice)},
		"agent marker wins":         {&fakeVerifier{}, signCWT(t, agent)},
		"issuer not configured":     {&fakeVerifier{}, signCWT(t, otherIssuer)},
		"not a CWT":                 {&fakeVerifier{}, "not-a-token"},
		"not a string":              {&fakeVerifier{}, 42.0},
	} {
		t.Run(name, func(t *testing.T) {
			svc, buf := deviceService(t, tc.verifier)

			reps := resolveAs(callerContext(t.Context(), testPEP), t, svc,
				claimsEntity(t, "e0", catalogCreatorClaims()),
				environmentEntity(t, "e1", map[string]any{chaindevice.TokenClaim: tc.token}))

			assert.Equal(t, chaindevice.Device{Class: chaindevice.ClassUnverified}.Props(), markerProps(t, reps[1]))
			assert.Equal(t, chaindevice.Device{Class: chaindevice.ClassUnverified}, deviceOf(t, reps[1]))
			requireMarkerOnly(t, reps[1])
			rec := logRecord(t, buf, "composite: device token is not a verified device token; the device is unverified")
			assert.Equal(t, "WARN", rec["level"])
			assert.Equal(t, "e1", rec["entity_id"])
			if token, isString := tc.token.(string); isString {
				assert.NotContains(t, buf.String(), token, "the raw token is never logged")
			}
		})
	}
}

// A verified device token whose class is not one chaindevice knows reads as
// unverified. It was verified, so it binds as any verified token does.
func TestDeviceToken_UnknownClassIsUnverified(t *testing.T) {
	svc, _ := deviceService(t, &fakeVerifier{})
	claims := deviceTokenClaims(svc.now().Add(time.Hour))
	npe, ok := claims["arkavo_npe"].(map[string]any)
	require.True(t, ok)
	npe["class"] = "gold"

	reps := resolveAs(callerContext(t.Context(), testPEP), t, svc,
		claimsEntity(t, "e0", catalogCreatorClaims()), deviceTokenEnv(t, "e1", signCWT(t, claims)))

	want := attestedIOS(true)
	want.Class = chaindevice.ClassUnverified
	assert.Equal(t, want.Props(), markerProps(t, reps[1]))
	assert.Equal(t, want, deviceOf(t, reps[1]))
}

// A device sent as plain PEP claims is still a device, but its class is
// unverified, it has no app and it is never bound, whatever its claims say.
// Claims a caller not on claims_chain_peps sends are discarded, so they
// cannot make a device at all.
func TestPEPClaimsDevice_Unbound(t *testing.T) {
	svc, _ := deviceService(t, &fakeVerifier{})
	claims := deviceClaims("phone", chaindevice.ClassAttested)
	claims[claimAccountID] = creatorAccount
	npe, ok := claims["arkavo_npe"].(map[string]any)
	require.True(t, ok)
	npe["app_id_hash"] = iosAppHash
	npe["app_env"] = chaindevice.EnvProduction
	person := claimsEntity(t, "e0", catalogCreatorClaims())

	reps := resolveAs(callerContext(t.Context(), testPEP), t, svc, person, environmentEntity(t, "e1", claims))

	assert.Equal(t, chaindevice.Device{Class: chaindevice.ClassUnverified}.Props(), markerProps(t, reps[1]))
	_, isDevice := chaindevice.FromRepresentation(reps[0])
	assert.False(t, isDevice, "the person carries no marker")

	reps = resolveAs(callerContext(t.Context(), "arks-media"), t, svc, person, environmentEntity(t, "e1", claims))
	_, isDevice = chaindevice.FromRepresentation(reps[1])
	assert.False(t, isDevice, "discarded claims cannot make a device")
}

// One unbound device among bound ones is still unbound, and an unbound device
// keeps no grant of the chain.
func TestBind_OneUnboundDeviceDeniesAll(t *testing.T) {
	svc, _ := deviceService(t, &fakeVerifier{})
	exp := svc.now().Add(time.Hour)
	mismatched := deviceTokenClaims(exp)
	mismatched[claimAccountID] = otherAccount

	reps := resolveAs(callerContext(t.Context(), testPEP), t, svc,
		claimsEntity(t, "e0", catalogCreatorClaims()),
		deviceTokenEnv(t, "e1", signCWT(t, deviceTokenClaims(exp))),
		deviceTokenEnv(t, "e2", signCWT(t, mismatched)))

	devices := []chaindevice.Device{deviceOf(t, reps[1]), deviceOf(t, reps[2])}
	assert.Equal(t, []chaindevice.Device{attestedIOS(true), attestedIOS(false)}, devices)
	var noRules *chaindevice.Rules
	for fqn := range entitlements(reps[0]) {
		assert.False(t, noRules.Keeps(devices, fqn), "%s survives an unbound device", fqn)
	}
}

// A device binds only when every subject of the request has its iss and
// arkavo_account_id. Each refusal is logged with the device, the reason and,
// for a mismatch, the subject.
func TestBind_UnboundReasons(t *testing.T) {
	exp := time.Now().Add(time.Hour)
	token := signCWT(t, deviceTokenClaims(exp))
	noAccount := deviceTokenClaims(exp)
	delete(noAccount, claimAccountID)
	otherIssuer := catalogCreatorClaims()
	otherIssuer["iss"] = "https://identity.example"
	personNoAccount := catalogCreatorClaims()
	delete(personNoAccount, claimAccountID)
	anonymous := &entity.Entity{
		EntityType: &entity.Entity_UserName{UserName: "viewer"}, EphemeralId: "e0", Category: entity.Entity_CATEGORY_SUBJECT,
	}

	for name, tc := range map[string]struct {
		entities  func(t *testing.T) []*entity.Entity
		reason    string
		subjectID string
	}{
		"no subject in the request": {func(t *testing.T) []*entity.Entity {
			return []*entity.Entity{deviceTokenEnv(t, "e1", token)}
		}, "no subjects", ""},
		"device not verified": {func(t *testing.T) []*entity.Entity {
			return []*entity.Entity{claimsEntity(t, "e0", catalogCreatorClaims()), deviceTokenEnv(t, "e1", "not-a-token")}
		}, "not verified", ""},
		"person under another issuer": {func(t *testing.T) []*entity.Entity {
			return []*entity.Entity{claimsEntity(t, "e0", otherIssuer), deviceTokenEnv(t, "e1", token)}
		}, "iss mismatch", "e0"},
		"anonymous person": {func(t *testing.T) []*entity.Entity {
			return []*entity.Entity{anonymous, deviceTokenEnv(t, "e1", token)}
		}, "iss mismatch", "e0"},
		"person with no account": {func(t *testing.T) []*entity.Entity {
			return []*entity.Entity{claimsEntity(t, "e0", personNoAccount), deviceTokenEnv(t, "e1", token)}
		}, "account mismatch", "e0"},
		"device with no account": {func(t *testing.T) []*entity.Entity {
			return []*entity.Entity{claimsEntity(t, "e0", catalogCreatorClaims()), deviceTokenEnv(t, "e1", signCWT(t, noAccount))}
		}, "account mismatch", "e0"},
		"second person of another account": {func(t *testing.T) []*entity.Entity {
			return []*entity.Entity{
				claimsEntity(t, "e0", catalogCreatorClaims()),
				deviceTokenEnv(t, "e1", token),
				claimsEntity(t, "e2", patronClaims("13167240", "active_patron")),
			}
		}, "account mismatch", "e2"},
	} {
		t.Run(name, func(t *testing.T) {
			svc, buf := deviceService(t, &fakeVerifier{})
			reps := resolveAs(callerContext(t.Context(), testPEP), t, svc, tc.entities(t)...)

			var device *entityresolutionV2.EntityRepresentation
			for _, rep := range reps {
				if rep.GetOriginalId() == "e1" {
					device = rep
				}
			}
			require.NotNil(t, device)
			assert.False(t, deviceOf(t, device).Bound)
			rec := logRecord(t, buf, unboundMsg)
			assert.Equal(t, "WARN", rec["level"])
			assert.Equal(t, "e1", rec["entity_id"])
			assert.Equal(t, tc.reason, rec["reason"])
			if tc.subjectID == "" {
				assert.NotContains(t, rec, "subject_id")
			} else {
				assert.Equal(t, tc.subjectID, rec["subject_id"])
			}
		})
	}
}

// A device sealed into a subject's evidence (a DeviceCheck token used as the
// subject) binds by the same rule as a chain's device token: in a chain of
// that subject alone it is bound, and any other subject of another identity,
// or one with none, unbinds it.
func TestBind_SealedDevice(t *testing.T) {
	svc, _ := deviceService(t, &fakeVerifier{})
	split := evidence{
		V:         evidenceVersion,
		Sub:       creatorSub,
		Iss:       testIssuer,
		AccountID: creatorAccount,
		Exp:       svc.now().Add(time.Minute).Unix(),
		Grants:    []sealedGrant{{FQN: publishValue, Actions: []string{"publish"}, Source: "identity-core"}},
		Device:    &sealedDevice{Class: chaindevice.ClassAttested, AppIDHash: iosAppHash, AppEnv: chaindevice.EnvProduction},
	}
	sealedSubject := func(t *testing.T, ev evidence) *entity.Entity {
		t.Helper()
		sealed, err := sealEvidence(svc.sealKeys[0], ev)
		require.NoError(t, err)
		return claimsEntity(t, "s0", map[string]any{evidenceClaim: sealed})
	}
	pep := callerContext(t.Context(), testPEP)

	t.Run("alone", func(t *testing.T) {
		rep := resolveAs(callerContext(t.Context(), "arks-media"), t, svc, sealedSubject(t, split))[0]
		assert.Equal(t, attestedIOS(true), deviceOf(t, rep))
		assert.Equal(t, map[string][]string{publishValue: {"publish"}}, entitlements(rep), "the subject keeps its grants")
	})
	t.Run("with a subject of another account", func(t *testing.T) {
		reps := resolveAs(pep, t, svc, sealedSubject(t, split), claimsEntity(t, "e1", patronClaims("13167240", "active_patron")))
		assert.Equal(t, attestedIOS(false), deviceOf(t, reps[0]))
	})
	t.Run("with an anonymous subject", func(t *testing.T) {
		anonymous := &entity.Entity{
			EntityType: &entity.Entity_UserName{UserName: "viewer"}, EphemeralId: "e1", Category: entity.Entity_CATEGORY_SUBJECT,
		}
		reps := resolveAs(pep, t, svc, sealedSubject(t, split), anonymous)
		assert.Equal(t, attestedIOS(false), deviceOf(t, reps[0]))
	})
	t.Run("evidence with no account", func(t *testing.T) {
		ev := split
		ev.AccountID = ""
		rep := resolveAs(pep, t, svc, sealedSubject(t, ev))[0]
		assert.Equal(t, attestedIOS(false), deviceOf(t, rep))
	})
}

// Every route's evidence records whom it resolved, so a device can be bound
// to it: the token's or the PEP's iss and arkavo_account_id, and nothing for
// a subject with no trust.
func TestResolveSubject_RecordsIssAndAccount(t *testing.T) {
	svc, _ := deviceService(t, &fakeVerifier{})
	exp := svc.now().Add(time.Hour)

	ev := tokenEvidence(t, svc, signCWT(t, creatorClaims(exp)))
	assert.Equal(t, testIssuer, ev.Iss)
	assert.Equal(t, creatorAccount, ev.AccountID)

	q := source.Query{Action: defaultAction}
	pepEv := svc.resolveSubject(t.Context(), source.Subject{
		Claims: catalogCreatorClaims(), AccountID: creatorAccount, Trust: source.TrustPEP,
	}, q, exp)
	assert.Equal(t, testIssuer, pepEv.Iss)
	assert.Equal(t, creatorAccount, pepEv.AccountID)

	noneEv := svc.resolveSubject(t.Context(), source.Subject{
		Claims: catalogCreatorClaims(), AccountID: creatorAccount, Trust: source.TrustNone,
	}, q, exp)
	assert.Empty(t, noneEv.Iss)
	assert.Empty(t, noneEv.AccountID)
}

// The evidence carries the subject's identity and a sealed device through the
// seal, and omits them when unset, so evidence sealed before them opens alike.
func TestSealedEvidence_RoundTripsIdentityAndDevice(t *testing.T) {
	want := testEvidence()
	want.Iss = testIssuer
	want.AccountID = creatorAccount
	want.Device = &sealedDevice{Class: chaindevice.ClassAttested, AppIDHash: iosAppHash, AppEnv: chaindevice.EnvProduction}

	sealed, err := sealEvidence(evidenceKey, want)
	require.NoError(t, err)
	got, err := openEvidence([][]byte{evidenceKey}, sealed, evidenceNow)
	require.NoError(t, err)
	assert.Equal(t, want, got)

	payload, err := json.Marshal(testEvidence())
	require.NoError(t, err)
	for _, key := range []string{`"iss"`, `"account_id"`, `"device"`} {
		assert.NotContains(t, string(payload), key)
	}
}

// Only the composite writes a device marker. A source whose properties_key is
// the marker's (Validate refuses one, but evidence sealed under an older
// config can carry it) cannot put one on a representation.
func TestDeviceMarker_OnlyTheCompositeWritesIt(t *testing.T) {
	forged := attestedIOS(true).Props()
	forger := sourceOf(SourceConfig{
		ID: "forger", Issuer: testIssuer, PEPAssertable: true, PropertiesKey: chaindevice.PropKey,
	}, fakeSource{res: source.Resolution{Outcome: source.OutcomeComplete, Properties: forged}})
	svc := newTestService(t, pepConfig(), verifiersFor(&fakeVerifier{}),
		[]configuredSource{pepPatreonSource(), forger}, nil)
	pep := callerContext(t.Context(), testPEP)

	t.Run("a source's properties", func(t *testing.T) {
		rep := resolveAs(pep, t, svc, claimsEntity(t, "e0", catalogCreatorClaims()))[0]
		_, isDevice := chaindevice.FromRepresentation(rep)
		assert.False(t, isDevice)
		assert.NotEmpty(t, patreonView(t, rep), "the other properties stay")
	})
	t.Run("sealed properties", func(t *testing.T) {
		sealed, err := sealEvidence(svc.sealKeys[0], evidence{
			V:     evidenceVersion,
			Exp:   svc.now().Add(time.Minute).Unix(),
			Props: map[string]map[string]any{chaindevice.PropKey: forged},
		})
		require.NoError(t, err)
		rep := resolveAs(pep, t, svc, claimsEntity(t, "s0", map[string]any{evidenceClaim: sealed}))[0]
		_, isDevice := chaindevice.FromRepresentation(rep)
		assert.False(t, isDevice)
	})
	t.Run("beside a device token, the marker is the composite's", func(t *testing.T) {
		claims := deviceTokenClaims(svc.now().Add(time.Hour))
		claims[claimAccountID] = otherAccount
		reps := resolveAs(pep, t, svc, claimsEntity(t, "e0", catalogCreatorClaims()), deviceTokenEnv(t, "e1", signCWT(t, claims)))
		_, isDevice := chaindevice.FromRepresentation(reps[0])
		assert.False(t, isDevice)
		assert.Equal(t, attestedIOS(false), deviceOf(t, reps[1]))
	})
}

// deviceFromClaims reads a verified device token's arkavo_npe. Anything it
// does not recognise reads toward fewer grants.
func TestDeviceFromClaims(t *testing.T) {
	full := map[string]any{
		"type": "device", "class": chaindevice.ClassAttested, "app_id_hash": iosAppHash, "app_env": chaindevice.EnvProduction,
	}
	// with is the full token's claims with arkavo_npe[key] set to v, or
	// removed when v is nil.
	with := func(key string, v any) map[string]any {
		members := maps.Clone(full)
		if v == nil {
			delete(members, key)
		} else {
			members[key] = v
		}
		return map[string]any{"arkavo_npe": members}
	}
	verified := func(class, appIDHash, appEnv string) chaindevice.Device {
		return chaindevice.Device{Class: class, Verified: true, AppIDHash: appIDHash, AppEnv: appEnv}
	}
	const (
		attested   = chaindevice.ClassAttested
		unverified = chaindevice.ClassUnverified
		prod       = chaindevice.EnvProduction
	)

	for name, tc := range map[string]struct {
		claims   map[string]any
		verified bool
		want     chaindevice.Device
	}{
		"attested":                 {with("type", "device"), true, verified(attested, iosAppHash, prod)},
		"not verified":             {with("type", "device"), false, chaindevice.Device{Class: unverified}},
		"managed":                  {with("class", chaindevice.ClassManaged), true, verified(chaindevice.ClassManaged, iosAppHash, prod)},
		"class unverified":         {with("class", unverified), true, verified(unverified, iosAppHash, prod)},
		"class missing":            {with("class", nil), true, verified(unverified, iosAppHash, prod)},
		"class unknown":            {with("class", "gold"), true, verified(unverified, iosAppHash, prod)},
		"class in another case":    {with("class", "Attested"), true, verified(unverified, iosAppHash, prod)},
		"class not a string":       {with("class", true), true, verified(unverified, iosAppHash, prod)},
		"hash in upper case":       {with("app_id_hash", strings.ToUpper(iosAppHash)), true, verified(attested, iosAppHash, prod)},
		"hash missing":             {with("app_id_hash", nil), true, verified(attested, "", prod)},
		"hash not a string":        {with("app_id_hash", 1.0), true, verified(attested, "", prod)},
		"env development":          {with("app_env", chaindevice.EnvDevelopment), true, verified(attested, iosAppHash, chaindevice.EnvDevelopment)},
		"env unknown":              {with("app_env", "staging"), true, verified(attested, iosAppHash, "")},
		"env in another case":      {with("app_env", "Production"), true, verified(attested, iosAppHash, "")},
		"env missing":              {with("app_env", nil), true, verified(attested, iosAppHash, "")},
		"no arkavo_npe":            {map[string]any{}, true, verified(unverified, "", "")},
		"arkavo_npe not an object": {map[string]any{"arkavo_npe": "device"}, true, verified(unverified, "", "")},
	} {
		t.Run(name, func(t *testing.T) {
			assert.Equal(t, tc.want, deviceFromClaims(tc.claims, tc.verified))
		})
	}
}
