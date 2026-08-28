package arkavo

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/base64"
	"reflect"
	"sort"
	"testing"
	"time"

	"connectrpc.com/connect"
	"github.com/fxamacker/cbor/v2"
	"github.com/opentdf/platform/protocol/go/entity"
	entityresolutionV2 "github.com/opentdf/platform/protocol/go/entityresolution/v2"
	"github.com/opentdf/platform/service/logger"
	"github.com/veraison/go-cose"
	"go.opentelemetry.io/otel/trace/noop"
	"google.golang.org/protobuf/types/known/anypb"
	"google.golang.org/protobuf/types/known/structpb"
)

func testLogger(t *testing.T) *logger.Logger {
	t.Helper()
	l, err := logger.NewLogger(logger.Config{Level: "error", Output: "stderr", Type: "text"})
	if err != nil {
		t.Fatalf("logger: %v", err)
	}
	return l
}

func newSvc(t *testing.T, cfg Config) *EntityResolutionService {
	t.Helper()
	svc := NewERS(cfg, testLogger(t))
	svc.Tracer = noop.NewTracerProvider().Tracer("test")
	return svc
}

const issuer = "https://identity.arkavo.net"

func agentToken(t *testing.T, iss string) string {
	return buildJWT(t, map[string]interface{}{
		"iss": iss, "sub": "did:key:z6Mkagent",
		"arkavo_account_id":   "00000000-0000-0000-0000-000000000001",
		"arkavo_roles":        []interface{}{"agent"},
		"arkavo_entitlements": []interface{}{"https://arkavo.ai/attr/tdf/value/decrypt", "https://arkavo.ai/attr/action/value/read"},
		"arkavo_npe":          map[string]interface{}{"type": "agent", "delegation_id": "did:key:z6Mkagent", "depth": 0},
	})
}

func chainsFor(t *testing.T, svc *EntityResolutionService, tok string) []*entity.Entity {
	t.Helper()
	resp, err := svc.CreateEntityChainsFromTokens(context.Background(), connect.NewRequest(&entityresolutionV2.CreateEntityChainsFromTokensRequest{
		Tokens: []*entity.Token{{EphemeralId: "t1", Jwt: tok}},
	}))
	if err != nil {
		t.Fatalf("chains: %v", err)
	}
	return resp.Msg.GetEntityChains()[0].GetEntities()
}

func entitlementsOf(t *testing.T, svc *EntityResolutionService, ents []*entity.Entity) map[string][]string {
	t.Helper()
	resp, err := svc.ResolveEntities(context.Background(), connect.NewRequest(&entityresolutionV2.ResolveEntitiesRequest{Entities: ents}))
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	got := map[string][]string{}
	for _, r := range resp.Msg.GetEntityRepresentations() {
		for _, d := range r.GetDirectEntitlements() {
			got[d.GetAttributeValueFqn()] = d.GetActions()
		}
	}
	return got
}

func TestAgentToken_SubjectAndEnvironmentEntities(t *testing.T) {
	svc := newSvc(t, Config{TrustMaterializedClaims: true, TrustedIssuer: issuer})
	ents := chainsFor(t, svc, agentToken(t, issuer))
	var subjects, envs int
	for _, e := range ents {
		switch e.GetCategory() {
		case entity.Entity_CATEGORY_SUBJECT:
			subjects++
		case entity.Entity_CATEGORY_ENVIRONMENT:
			envs++
		case entity.Entity_CATEGORY_UNSPECIFIED:
			// not expected from this provider
		}
	}
	if subjects != 1 || envs != 1 {
		t.Fatalf("want 1 subject + 1 environment (agent NPE), got %d/%d", subjects, envs)
	}
}

func TestAgentToken_DirectEntitlementsFromClaims(t *testing.T) {
	svc := newSvc(t, Config{TrustMaterializedClaims: true, TrustedIssuer: issuer})
	got := entitlementsOf(t, svc, chainsFor(t, svc, agentToken(t, issuer)))
	want := []string{"https://arkavo.ai/attr/tdf/value/decrypt", "https://arkavo.ai/attr/action/value/read"}
	for _, fqn := range want {
		acts, ok := got[fqn]
		if !ok || len(acts) != 1 || acts[0] != "read" {
			t.Errorf("entitlement %s = %v (want [read])", fqn, acts)
		}
	}
	if len(got) != len(want) {
		t.Errorf("over-granted: %v", got)
	}
}

func TestUntrustedIssuer_GrantsNothing(t *testing.T) {
	svc := newSvc(t, Config{TrustMaterializedClaims: true, TrustedIssuer: issuer})
	got := entitlementsOf(t, svc, chainsFor(t, svc, agentToken(t, "https://evil.example.com")))
	if len(got) != 0 {
		t.Errorf("untrusted issuer leaked entitlements: %v", got)
	}
}

func TestTrustDisabledByDefault(t *testing.T) {
	svc := newSvc(t, Config{TrustedIssuer: issuer})
	if got := entitlementsOf(t, svc, chainsFor(t, svc, agentToken(t, issuer))); len(got) != 0 {
		t.Errorf("trust off must grant nothing: %v", got)
	}
}

func TestDeviceToken_ClassCeiling(t *testing.T) {
	svc := newSvc(t, Config{
		TrustMaterializedClaims: true, TrustedIssuer: issuer,
		DeviceClassCeilings: map[string][]string{
			"unverified": {"https://arkavo.ai/attr/classification/value/internal"},
			"attested":   {"https://arkavo.ai/attr/classification/value/restricted"},
		},
	})
	tok := buildJWT(t, map[string]interface{}{
		"iss": issuer, "sub": "00000000-0000-0000-0000-000000000001",
		"arkavo_npe": map[string]interface{}{"type": "device", "class": "unverified", "device_id": "K1"},
	})
	got := entitlementsOf(t, svc, chainsFor(t, svc, tok))
	if _, ok := got["https://arkavo.ai/attr/classification/value/internal"]; !ok || len(got) != 1 {
		t.Errorf("device ceiling: %v", got)
	}
}

func TestClaimsEntityPreservesRawForSecondPass(t *testing.T) {
	svc := newSvc(t, Config{TrustMaterializedClaims: true, TrustedIssuer: issuer})
	ents := chainsFor(t, svc, agentToken(t, issuer))
	var subj *entity.Entity
	for _, e := range ents {
		if e.GetCategory() == entity.Entity_CATEGORY_SUBJECT {
			subj = e
		}
	}
	var s structpb.Struct
	if err := subj.GetClaims().UnmarshalTo(&s); err != nil {
		t.Fatal(err)
	}
	if _, ok := s.AsMap()["arkavo_entitlements"]; !ok {
		t.Error("arkavo_entitlements must be preserved on the subject entity for the decision flow's second pass")
	}
	if s.AsMap()["arkavo_trusted"] != true {
		t.Error("trusted marker must be set only by entitiesFromToken")
	}
}

// --- R12: real base64url CWT end-to-end -------------------------------------

// signCWT mints an in-package COSE_Sign1 CWT (unverified by the ERS, exactly
// as the with_request_token path hands it the raw bearer). Kept local since
// package auth's signCWT test helper is not importable.
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

func agentCWT(t *testing.T, iss string) string {
	t.Helper()
	return signCWT(t, iss, "did:key:z6Mkagent", map[any]any{
		"arkavo_account_id": "00000000-0000-0000-0000-000000000001",
		"arkavo_roles":      []any{"agent"},
		"arkavo_entitlements": []any{
			"https://arkavo.ai/attr/tdf/value/decrypt",
			"https://arkavo.ai/attr/action/value/read",
		},
		"arkavo_npe": map[any]any{"type": "agent", "delegation_id": "did:key:z6Mkagent", "depth": int64(0)},
	})
}

func subjectClaimsMap(t *testing.T, ents []*entity.Entity) map[string]interface{} {
	t.Helper()
	for _, e := range ents {
		if e.GetCategory() != entity.Entity_CATEGORY_SUBJECT {
			continue
		}
		var s structpb.Struct
		if err := e.GetClaims().UnmarshalTo(&s); err != nil {
			t.Fatalf("unmarshal claims: %v", err)
		}
		return s.AsMap()
	}
	t.Fatal("no subject entity found")
	return nil
}

func TestCWTToken_MatchesEquivalentJWT(t *testing.T) {
	svc := newSvc(t, Config{TrustMaterializedClaims: true, TrustedIssuer: issuer})

	jwtEnts := chainsFor(t, svc, agentToken(t, issuer))
	cwtEnts := chainsFor(t, svc, agentCWT(t, issuer))

	var jwtSubjects, jwtEnvs, cwtSubjects, cwtEnvs int
	for _, e := range jwtEnts {
		switch e.GetCategory() {
		case entity.Entity_CATEGORY_SUBJECT:
			jwtSubjects++
		case entity.Entity_CATEGORY_ENVIRONMENT:
			jwtEnvs++
		case entity.Entity_CATEGORY_UNSPECIFIED:
			// not expected from this provider
		}
	}
	for _, e := range cwtEnts {
		switch e.GetCategory() {
		case entity.Entity_CATEGORY_SUBJECT:
			cwtSubjects++
		case entity.Entity_CATEGORY_ENVIRONMENT:
			cwtEnvs++
		case entity.Entity_CATEGORY_UNSPECIFIED:
			// not expected from this provider
		}
	}
	if cwtSubjects != jwtSubjects || cwtEnvs != jwtEnvs {
		t.Fatalf("CWT chain shape (%d subj/%d env) != JWT chain shape (%d subj/%d env)", cwtSubjects, cwtEnvs, jwtSubjects, jwtEnvs)
	}

	jwtClaims := subjectClaimsMap(t, jwtEnts)
	cwtClaims := subjectClaimsMap(t, cwtEnts)
	if jwtClaims["sub"] != cwtClaims["sub"] || jwtClaims["iss"] != cwtClaims["iss"] {
		t.Errorf("subject identity mismatch: jwt=%v cwt=%v", jwtClaims, cwtClaims)
	}
	if jwtClaims["arkavo_trusted"] != true || cwtClaims["arkavo_trusted"] != true {
		t.Errorf("both must be trusted: jwt=%v cwt=%v", jwtClaims["arkavo_trusted"], cwtClaims["arkavo_trusted"])
	}

	jwtGot := entitlementsOf(t, svc, jwtEnts)
	cwtGot := entitlementsOf(t, svc, cwtEnts)
	jwtKeys, cwtKeys := make([]string, 0, len(jwtGot)), make([]string, 0, len(cwtGot))
	for k := range jwtGot {
		jwtKeys = append(jwtKeys, k)
	}
	for k := range cwtGot {
		cwtKeys = append(cwtKeys, k)
	}
	sort.Strings(jwtKeys)
	sort.Strings(cwtKeys)
	if !reflect.DeepEqual(jwtKeys, cwtKeys) {
		t.Fatalf("entitlement FQNs differ: jwt=%v cwt=%v", jwtKeys, cwtKeys)
	}
	for _, k := range jwtKeys {
		if !reflect.DeepEqual(jwtGot[k], cwtGot[k]) {
			t.Errorf("actions for %s differ: jwt=%v cwt=%v", k, jwtGot[k], cwtGot[k])
		}
	}
}

// --- Review findings regression tests ---------------------------------------

// TestResolveEntities_FabricatedTrustedMarkerRejected covers Finding 1: a
// caller-supplied Entity_Claims payload is not guaranteed to have come from
// this service's own CreateEntityChainsFromTokens, so a fabricated
// arkavo_trusted marker must not bypass the operator's master switch
// (TrustMaterializedClaims: false here).
func TestResolveEntities_FabricatedTrustedMarkerRejected(t *testing.T) {
	svc := newSvc(t, Config{TrustMaterializedClaims: false, TrustedIssuer: issuer})
	claims, err := structpb.NewStruct(map[string]interface{}{
		"sub":                 "did:key:z6Mkattacker",
		"iss":                 issuer,
		"arkavo_trusted":      true,
		"arkavo_entitlements": []interface{}{"https://arkavo.ai/attr/tdf/value/decrypt", "https://arkavo.ai/attr/action/value/read"},
	})
	if err != nil {
		t.Fatalf("build forged claims: %v", err)
	}
	anyClaims, err := anypb.New(claims)
	if err != nil {
		t.Fatalf("anypb.New: %v", err)
	}
	ents := []*entity.Entity{{
		EntityType:  &entity.Entity_Claims{Claims: anyClaims},
		EphemeralId: "forged-subject",
		Category:    entity.Entity_CATEGORY_SUBJECT,
	}}
	resp, err := svc.ResolveEntities(context.Background(), connect.NewRequest(&entityresolutionV2.ResolveEntitiesRequest{Entities: ents}))
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	for _, r := range resp.Msg.GetEntityRepresentations() {
		if got := r.GetDirectEntitlements(); len(got) != 0 {
			t.Errorf("fabricated arkavo_trusted marker with TrustMaterializedClaims=false must yield zero DirectEntitlements, got %v", got)
		}
	}
}

// TestCWTToken_NpeEpochTimestampAndByteString_Sanitized covers Finding 2: a
// legitimately signed CWT whose arkavo_npe carries a CBOR tag-1 epoch
// timestamp and a byte-string field must not fail CreateEntityChainsFromTokens
// with structpb.NewStruct's "invalid type: time.Time" error — normalizeCBOR
// (service/internal/auth/cwt_verifier.go) hands those back as native
// time.Time / []byte, and the ERS boundary must sanitize them.
func TestCWTToken_NpeEpochTimestampAndByteString_Sanitized(t *testing.T) {
	svc := newSvc(t, Config{TrustMaterializedClaims: true, TrustedIssuer: issuer})
	expiry := time.Date(2030, 1, 1, 0, 0, 0, 0, time.UTC)
	nonce := []byte{0xDE, 0xAD, 0xBE, 0xEF}
	tok := signCWT(t, issuer, "did:key:z6Mkdevice", map[any]any{
		"arkavo_npe": map[any]any{
			"type":               "device",
			"device_id":          "K1",
			"attestation_expiry": cbor.Tag{Number: 1, Content: expiry.Unix()},
			"attestation_nonce":  nonce,
		},
	})

	resp, err := svc.CreateEntityChainsFromTokens(context.Background(), connect.NewRequest(&entityresolutionV2.CreateEntityChainsFromTokensRequest{
		Tokens: []*entity.Token{{EphemeralId: "t1", Jwt: tok}},
	}))
	if err != nil {
		t.Fatalf("CreateEntityChainsFromTokens must not error on a signed CWT with an epoch-timestamp arkavo_npe field: %v", err)
	}

	claims := subjectClaimsMap(t, resp.Msg.GetEntityChains()[0].GetEntities())
	npe, ok := claims["arkavo_npe"].(map[string]interface{})
	if !ok {
		t.Fatalf("arkavo_npe missing or wrong shape on subject entity: %#v", claims["arkavo_npe"])
	}
	gotExpiry, ok := npe["attestation_expiry"].(float64)
	if !ok || int64(gotExpiry) != expiry.Unix() {
		t.Errorf("attestation_expiry = %#v, want %d as a number", npe["attestation_expiry"], expiry.Unix())
	}
	wantNonce := base64.RawURLEncoding.EncodeToString(nonce)
	gotNonce, ok := npe["attestation_nonce"].(string)
	if !ok || gotNonce != wantNonce {
		t.Errorf("attestation_nonce = %#v, want %q", npe["attestation_nonce"], wantNonce)
	}
}

// TestCWTToken_NpeNestedStructures_Sanitized covers Finding 2's recursive
// case: a nested map and a nested list mixing representable values with a
// CBOR type structpb cannot hold (a big.Int from a tag-2 unsigned bignum).
// The call must still succeed, keep representable values, and drop the rest.
func TestCWTToken_NpeNestedStructures_Sanitized(t *testing.T) {
	svc := newSvc(t, Config{TrustMaterializedClaims: true, TrustedIssuer: issuer})
	tok := signCWT(t, issuer, "did:key:z6Mkdevice", map[any]any{
		"arkavo_npe": map[any]any{
			"type":      "device",
			"device_id": "K1",
			"nested_map": map[any]any{
				"keep":    "value",
				"dropped": cbor.Tag{Number: 2, Content: []byte{0x01, 0x00}}, // unsigned bignum -> big.Int, unrepresentable
			},
			"nested_list": []any{
				"keep-me",
				int64(7),
				cbor.Tag{Number: 2, Content: []byte{0x01, 0x00}},
			},
		},
	})

	resp, err := svc.CreateEntityChainsFromTokens(context.Background(), connect.NewRequest(&entityresolutionV2.CreateEntityChainsFromTokensRequest{
		Tokens: []*entity.Token{{EphemeralId: "t1", Jwt: tok}},
	}))
	if err != nil {
		t.Fatalf("CreateEntityChainsFromTokens must not error on nested unrepresentable arkavo_npe values: %v", err)
	}

	claims := subjectClaimsMap(t, resp.Msg.GetEntityChains()[0].GetEntities())
	npe, ok := claims["arkavo_npe"].(map[string]interface{})
	if !ok {
		t.Fatalf("arkavo_npe missing or wrong shape on subject entity: %#v", claims["arkavo_npe"])
	}

	nestedMap, ok := npe["nested_map"].(map[string]interface{})
	if !ok {
		t.Fatalf("nested_map missing or wrong shape: %#v", npe["nested_map"])
	}
	if got := nestedMap["keep"]; got != "value" {
		t.Errorf("nested_map[keep] = %#v, want %q", got, "value")
	}
	if _, present := nestedMap["dropped"]; present {
		t.Errorf("nested_map[dropped] should have been dropped as unrepresentable, got %#v", nestedMap["dropped"])
	}

	nestedList, ok := npe["nested_list"].([]interface{})
	if !ok {
		t.Fatalf("nested_list missing or wrong shape: %#v", npe["nested_list"])
	}
	if len(nestedList) != 2 {
		t.Fatalf("nested_list = %#v, want 2 representable elements (unrepresentable one dropped)", nestedList)
	}
	if nestedList[0] != "keep-me" {
		t.Errorf("nested_list[0] = %#v, want %q", nestedList[0], "keep-me")
	}
	if n, numOK := nestedList[1].(float64); !numOK || n != 7 {
		t.Errorf("nested_list[1] = %#v, want 7 as a number", nestedList[1])
	}
}
