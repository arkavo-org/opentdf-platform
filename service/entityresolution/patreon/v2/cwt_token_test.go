package patreon

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/base64"
	"reflect"
	"strings"
	"testing"

	"connectrpc.com/connect"
	"github.com/fxamacker/cbor/v2"
	"github.com/veraison/go-cose"
	"google.golang.org/protobuf/types/known/structpb"

	"github.com/opentdf/platform/protocol/go/entity"
	ersV2 "github.com/opentdf/platform/protocol/go/entityresolution/v2"
)

// signCWT mints an in-package COSE_Sign1 CWT — the wire format the KAS
// rewrap path (tdf3Rewrap → canAccess → entity.Token{Jwt: bearer}) hands
// this provider since the bearer became a CWT. The ERS never verifies it
// (the authn interceptor did upstream). Mirrors the helper in
// service/entityresolution/arkavo/v2/entity_resolution_test.go; package
// auth's signCWT test helper is not importable.
func signCWT(t *testing.T, iss, sub string, custom map[any]any) string {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	payload := map[any]any{1: iss, 2: sub}
	for k, v := range custom {
		payload[k] = v
	}
	payloadCBOR, err := cbor.Marshal(payload)
	if err != nil {
		t.Fatalf("marshal payload: %v", err)
	}
	signer, err := cose.NewSigner(cose.AlgorithmES256, priv)
	if err != nil {
		t.Fatalf("new signer: %v", err)
	}
	msg := cose.Sign1Message{
		Headers: cose.Headers{
			Protected: cose.ProtectedHeader{cose.HeaderLabelAlgorithm: cose.AlgorithmES256},
		},
		Payload: payloadCBOR,
	}
	if err := msg.Sign(rand.Reader, nil, signer); err != nil {
		t.Fatalf("sign: %v", err)
	}
	raw, err := msg.MarshalCBOR()
	if err != nil {
		t.Fatalf("marshal cose: %v", err)
	}
	return base64.RawURLEncoding.EncodeToString(raw)
}

const (
	cwtTestIssuer = "https://identity.arkavo.net"
	cwtTestSub    = "did:key:z6Mkconsumer"
	cwtTestAzp    = "arkavo-creator"
)

// patreonJWT and patreonCWT carry the same identity and the same materialized
// arkavo_patreon claim in the two bearer wire formats.
func patreonJWT(t *testing.T) string {
	t.Helper()
	return buildJWT(t, map[string]interface{}{
		"iss": cwtTestIssuer,
		"sub": cwtTestSub,
		"azp": cwtTestAzp,
		"arkavo_patreon": map[string]interface{}{
			"role":            "consumer",
			"patreon_user_id": "p-77",
			"memberships": []interface{}{
				map[string]interface{}{
					"campaign_id":   "11111111",
					"patron_status": "active_patron",
					"tier_slugs":    []interface{}{"gold-tier", "early-access"},
				},
				map[string]interface{}{
					"campaign_id":   "22222222",
					"patron_status": "former_patron",
					"tier_slugs":    []interface{}{"vip"},
				},
			},
		},
	})
}

func patreonCWT(t *testing.T) string {
	t.Helper()
	return signCWT(t, cwtTestIssuer, cwtTestSub, map[any]any{
		"azp": cwtTestAzp,
		"arkavo_patreon": map[any]any{
			"role":            "consumer",
			"patreon_user_id": "p-77",
			"memberships": []any{
				map[any]any{
					"campaign_id":   "11111111",
					"patron_status": "active_patron",
					"tier_slugs":    []any{"gold-tier", "early-access"},
				},
				map[any]any{
					"campaign_id":   "22222222",
					"patron_status": "former_patron",
					"tier_slugs":    []any{"vip"},
				},
			},
		},
	})
}

func chainFor(t *testing.T, svc *EntityResolutionService, token string) []*entity.Entity {
	t.Helper()
	resp, err := svc.CreateEntityChainsFromTokens(context.Background(),
		connect.NewRequest(&ersV2.CreateEntityChainsFromTokensRequest{
			Tokens: []*entity.Token{{EphemeralId: "t0", Jwt: token}},
		}))
	if err != nil {
		t.Fatalf("CreateEntityChainsFromTokens: %v", err)
	}
	return resp.Msg.GetEntityChains()[0].GetEntities()
}

// normalizedEntities projects a chain onto comparable values: ephemeral id,
// category, and the claims struct round-tripped through structpb.AsMap so
// jwx (JSON) and CBOR numeric/collection types don't produce false diffs.
func normalizedEntities(t *testing.T, ents []*entity.Entity) []map[string]interface{} {
	t.Helper()
	out := make([]map[string]interface{}, 0, len(ents))
	for _, e := range ents {
		n := map[string]interface{}{
			"ephemeral_id": e.GetEphemeralId(),
			"category":     e.GetCategory().String(),
		}
		switch et := e.GetEntityType().(type) {
		case *entity.Entity_Claims:
			var s structpb.Struct
			if err := et.Claims.UnmarshalTo(&s); err != nil {
				t.Fatalf("unmarshal claims: %v", err)
			}
			n["claims"] = s.AsMap()
		case *entity.Entity_ClientId:
			n["client_id"] = et.ClientId
		default:
			t.Fatalf("unexpected entity type %T", et)
		}
		out = append(out, n)
	}
	return out
}

// The KAS rewrap path hands the ERS the raw bearer, which since the CWT
// migration is a COSE_Sign1 CWT rather than a JOSE JWT. A CWT carrying
// sub/iss/azp and a trusted arkavo_patreon claim must produce exactly the
// entity chain the equivalent JWT does — same environment entity, same
// subject entity, same flattened patreon view, same preserved claim — so the
// decision flow's second pass grants the same campaign-qualified entitlements.
func TestCreateEntityChainsFromTokens_CWTMatchesEquivalentJWT(t *testing.T) {
	svc := newSvc(t, Config{
		TrustMaterializedClaims: true,
		TrustedIssuer:           cwtTestIssuer,
	})

	jwtEnts := chainFor(t, svc, patreonJWT(t))
	cwtEnts := chainFor(t, svc, patreonCWT(t))

	jwtNorm := normalizedEntities(t, jwtEnts)
	cwtNorm := normalizedEntities(t, cwtEnts)
	if !reflect.DeepEqual(jwtNorm, cwtNorm) {
		t.Fatalf("CWT chain != JWT chain\n jwt=%#v\n cwt=%#v", jwtNorm, cwtNorm)
	}

	// Pin the shape both must have, so the equality above is not vacuous.
	if len(cwtNorm) != 2 {
		t.Fatalf("want 2 entities (environment + subject), got %d: %#v", len(cwtNorm), cwtNorm)
	}
	if cwtNorm[0]["ephemeral_id"] != "patreon-clientid-"+cwtTestAzp ||
		cwtNorm[0]["category"] != entity.Entity_CATEGORY_ENVIRONMENT.String() {
		t.Errorf("environment entity: %#v", cwtNorm[0])
	}
	if cwtNorm[1]["ephemeral_id"] != "patreon-subject-p-77" ||
		cwtNorm[1]["category"] != entity.Entity_CATEGORY_SUBJECT.String() {
		t.Errorf("subject entity: %#v", cwtNorm[1])
	}
	claims, _ := cwtNorm[1]["claims"].(map[string]interface{})
	patreon, _ := claims["patreon"].(map[string]interface{})
	if patreon["status"] != "active" || patreon["user_id"] != "p-77" {
		t.Errorf("flattened patreon view from CWT: %#v", patreon)
	}
	preserved, _ := claims["arkavo_patreon"].(map[string]interface{})
	if preserved["patreon_user_id"] != "p-77" {
		t.Errorf("arkavo_patreon not preserved for the second pass: %#v", claims)
	}
}

// A CWT from an untrusted issuer gets the same treatment as an untrusted JWT:
// the materialized claim is dropped before it can influence anything.
func TestCreateEntityChainsFromTokens_CWTUntrustedIssuerDropsClaim(t *testing.T) {
	svc := newSvc(t, Config{
		TrustMaterializedClaims: true,
		TrustedIssuer:           cwtTestIssuer,
		InferUnknownAsFree:      true,
	})
	forged := signCWT(t, "https://evil.example.com", "attacker", map[any]any{
		"arkavo_patreon": map[any]any{
			"role":            "consumer",
			"patreon_user_id": "p-evil",
			"memberships": []any{map[any]any{
				"campaign_id":   "11111111",
				"patron_status": "active_patron",
				"tier_slugs":    []any{"gold-tier"},
			}},
		},
	})
	ents := normalizedEntities(t, chainFor(t, svc, forged))
	if len(ents) != 1 {
		t.Fatalf("want subject only (no azp), got %#v", ents)
	}
	claims, _ := ents[0]["claims"].(map[string]interface{})
	if _, present := claims["arkavo_patreon"]; present {
		t.Error("untrusted issuer: arkavo_patreon was preserved for second pass")
	}
	patreon, _ := claims["patreon"].(map[string]interface{})
	if patreon["status"] == "active" {
		t.Errorf("untrusted issuer leaked active status: %v", patreon)
	}
}

// Garbage is still rejected.
func TestCreateEntityChainsFromTokens_GarbageTokenErrors(t *testing.T) {
	svc := newSvc(t, Config{})
	_, err := svc.CreateEntityChainsFromTokens(context.Background(),
		connect.NewRequest(&ersV2.CreateEntityChainsFromTokensRequest{
			Tokens: []*entity.Token{{EphemeralId: "t0", Jwt: "definitely-not-a-token"}},
		}))
	if err == nil {
		t.Fatal("garbage token must fail")
	}
}

// A trusted-issuer CWT may carry CBOR-native values inside arkavo_patreon —
// a tag-1 epoch timestamp is what a CBOR minter emits for last_charge_at,
// and an unregistered tag decodes to cbor.Tag. The claim is preserved
// verbatim for the decision flow's second pass, so unless it is sanitized
// first, structpb.NewStruct rejects the whole chain and the KAS rewrap path
// fails with the same "could not perform access" 500 that CWT support was
// added to remove.
func TestCreateEntityChainsFromTokens_CWTWithCBORNativeClaimValues(t *testing.T) {
	svc := newSvc(t, Config{
		TrustMaterializedClaims: true,
		TrustedIssuer:           cwtTestIssuer,
	})
	token := signCWT(t, cwtTestIssuer, cwtTestSub, map[any]any{
		"azp": cwtTestAzp,
		"arkavo_patreon": map[any]any{
			"role":            "consumer",
			"patreon_user_id": "p-77",
			"last_charge_at":  cbor.Tag{Number: 1, Content: int64(1700000000)},
			"attestation":     []byte{0xde, 0xad, 0xbe, 0xef},
			"unknown_tag":     cbor.Tag{Number: 999, Content: "opaque"},
			"memberships": []any{map[any]any{
				"campaign_id":   "11111111",
				"patron_status": "active_patron",
				"tier_slugs":    []any{"gold-tier"},
				"pledge_start":  cbor.Tag{Number: 0, Content: "2023-11-14T22:13:20Z"},
			}},
		},
	})

	ents := normalizedEntities(t, chainFor(t, svc, token))
	if len(ents) != 2 {
		t.Fatalf("want 2 entities (environment + subject), got %d: %#v", len(ents), ents)
	}
	claims, _ := ents[1]["claims"].(map[string]interface{})

	// The membership still resolves, so the timestamps did not cost the
	// caller their entitlements.
	patreon, _ := claims["patreon"].(map[string]interface{})
	if patreon["status"] != "active" || patreon["user_id"] != "p-77" {
		t.Errorf("flattened patreon view: %#v", patreon)
	}

	preserved, _ := claims["arkavo_patreon"].(map[string]interface{})
	if preserved == nil {
		t.Fatalf("arkavo_patreon not preserved for the second pass: %#v", claims)
	}
	// Timestamps survive as epoch seconds (structpb numbers are float64).
	if preserved["last_charge_at"] != float64(1700000000) {
		t.Errorf("last_charge_at: want 1700000000, got %#v", preserved["last_charge_at"])
	}
	// Byte strings survive as base64url.
	if preserved["attestation"] != "3q2-7w" {
		t.Errorf("attestation: want base64url, got %#v", preserved["attestation"])
	}
	// A value with no structpb representation is dropped, not fatal.
	if _, present := preserved["unknown_tag"]; present {
		t.Errorf("unrepresentable value should be dropped, got %#v", preserved["unknown_tag"])
	}
	mems, _ := preserved["memberships"].([]interface{})
	if len(mems) != 1 {
		t.Fatalf("memberships: %#v", preserved["memberships"])
	}
	nested, _ := mems[0].(map[string]interface{})
	if nested["pledge_start"] != float64(1700000000) {
		t.Errorf("nested pledge_start: want 1700000000, got %#v", nested["pledge_start"])
	}
}

// A valid bearer that simply carries no trusted membership claim is a
// not-found subject, not an internal error. CreateEntityChainsFromTokens
// hard-wired CodeInternal, so with infer_unknown_as_free off an ordinary
// unentitled caller produced the same "could not perform access" 500 as a
// genuine server fault. connectCodeFor already draws this distinction for
// ResolveEntities.
func TestCreateEntityChainsFromTokens_NoMembershipClaimIsNotFound(t *testing.T) {
	svc := newSvc(t, Config{
		TrustMaterializedClaims: true,
		TrustedIssuer:           cwtTestIssuer,
	})
	token := signCWT(t, cwtTestIssuer, cwtTestSub, map[any]any{"azp": cwtTestAzp})

	_, err := svc.CreateEntityChainsFromTokens(context.Background(),
		connect.NewRequest(&ersV2.CreateEntityChainsFromTokensRequest{
			Tokens: []*entity.Token{{EphemeralId: "t0", Jwt: token}},
		}))
	if err == nil {
		t.Fatal("token with no membership claim must fail when infer_unknown_as_free is off")
	}
	if got := connect.CodeOf(err); got != connect.CodeNotFound {
		t.Errorf("want CodeNotFound for an unentitled subject, got %v (%v)", got, err)
	}
}

// A bearer in neither wire format is a caller error the ERS cannot resolve,
// and must stay distinguishable from the not-found case above.
func TestCreateEntityChainsFromTokens_GarbageTokenIsInternal(t *testing.T) {
	svc := newSvc(t, Config{
		TrustMaterializedClaims: true,
		TrustedIssuer:           cwtTestIssuer,
	})
	_, err := svc.CreateEntityChainsFromTokens(context.Background(),
		connect.NewRequest(&ersV2.CreateEntityChainsFromTokensRequest{
			Tokens: []*entity.Token{{EphemeralId: "t0", Jwt: "definitely-not-a-token"}},
		}))
	if err == nil {
		t.Fatal("garbage token must fail")
	}
	if got := connect.CodeOf(err); got != connect.CodeInternal {
		t.Errorf("want CodeInternal for an unparseable bearer, got %v", got)
	}
	if !strings.Contains(err.Error(), "parse bearer token") {
		t.Errorf("want a parse failure, got %v", err)
	}
}
