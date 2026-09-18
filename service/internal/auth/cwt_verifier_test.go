package auth

import (
	"context"
	"crypto/ecdsa"
	"encoding/base64"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/fxamacker/cbor/v2"
	"github.com/opentdf/platform/service/internal/cwttest"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/types/known/structpb"
)

// --- helpers ----------------------------------------------------------------

func byteSlicePad(b []byte, n int) []byte {
	if len(b) >= n {
		return b[:n]
	}
	out := make([]byte, n)
	copy(out[n-len(b):], b)
	return out
}

// coseKeySetFromPub serializes a P-256 public key as a one-entry COSE Key
// Set CBOR (matching what authnz-rs publishes at /.well-known/cose-keys).
func coseKeySetFromPub(t *testing.T, pub *ecdsa.PublicKey, kid []byte) []byte {
	t.Helper()
	x := byteSlicePad(pub.X.Bytes(), 32)
	y := byteSlicePad(pub.Y.Bytes(), 32)
	key := map[int64]any{
		1:  int64(2),  // kty = EC2
		3:  int64(-7), // alg = ES256
		-1: int64(1),  // crv = P-256
		-2: x,
		-3: y,
		2:  kid, // kid
	}
	buf, err := cbor.Marshal([]map[int64]any{key})
	require.NoError(t, err)
	return buf
}

// keySetServer wraps a tiny httptest.Server that serves a COSE Key Set,
// mimicking authnz-rs's /.well-known/cose-keys.
func keySetServer(t *testing.T, body []byte) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/cose-key-set+cbor")
		_, _ = w.Write(body)
	}))
}

// standardClaims builds a CWT claims map with CBOR integer labels
// (RFC 8392 §4) for the standard registered claims used in tests.
// `sub` is parameterized so callers can mint tokens for distinct subjects
// (e.g. TestActorToken in authn_test.go mints bearer and actor CWTs with
// different subjects).
func standardClaims(iss, aud, sub string, ttl time.Duration) map[int64]any {
	now := time.Now().Unix()
	return map[int64]any{
		1: iss,                        // iss
		2: sub,                        // sub
		3: aud,                        // aud
		4: now + int64(ttl.Seconds()), // exp
		6: now,                        // iat
	}
}

// --- tests ------------------------------------------------------------------

func TestCWTVerifier_HappyPath(t *testing.T) {
	priv, kid := cwttest.NewKey(t)
	keySet := coseKeySetFromPub(t, &priv.PublicKey, kid)
	srv := keySetServer(t, keySet)
	defer srv.Close()

	v, err := NewCWTVerifier(context.Background(), CWTVerifierConfig{
		COSEKeysURL: srv.URL,
		Issuer:      "https://idp.example",
		Audience:    "opentdf-platform",
		Algorithm:   "ES256",
		CacheTTL:    time.Minute,
	}, nil)
	require.NoError(t, err)

	subjectToken := cwttest.SignLabeled(
		t, priv, kid,
		standardClaims("https://idp.example", "opentdf-platform", "user-1", time.Hour),
		map[string]any{
			"email":             "alice@example.com",
			"arkavo_roles":      []any{"user", "reader"},
			"arkavo_account_id": "acct-1234",
		},
	)
	tok, jwtStr, err := v.VerifyCWTSubjectToken(context.Background(), subjectToken)
	require.NoError(t, err)
	require.NotNil(t, tok)
	require.Equal(t, "user-1", tok.Subject())
	require.NotEmpty(t, jwtStr)
	// Synthetic JWT is alg=none → ends with the trailing dot.
	require.Equal(t, byte('.'), jwtStr[len(jwtStr)-1])
}

func TestCWTVerifier_RejectsWrongIssuer(t *testing.T) {
	priv, kid := cwttest.NewKey(t)
	srv := keySetServer(t, coseKeySetFromPub(t, &priv.PublicKey, kid))
	defer srv.Close()
	v, err := NewCWTVerifier(context.Background(), CWTVerifierConfig{
		COSEKeysURL: srv.URL,
		Issuer:      "https://idp.example",
		Audience:    "opentdf-platform",
		CacheTTL:    time.Minute,
	}, nil)
	require.NoError(t, err)
	tok := cwttest.SignLabeled(
		t, priv, kid,
		standardClaims("https://imposter.example", "opentdf-platform", "user-1", time.Hour),
		nil,
	)
	_, _, err = v.VerifyCWTSubjectToken(context.Background(), tok)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "iss mismatch")
}

func TestCWTVerifier_RejectsWrongAudience(t *testing.T) {
	priv, kid := cwttest.NewKey(t)
	srv := keySetServer(t, coseKeySetFromPub(t, &priv.PublicKey, kid))
	defer srv.Close()
	v, err := NewCWTVerifier(context.Background(), CWTVerifierConfig{
		COSEKeysURL: srv.URL,
		Issuer:      "https://idp.example",
		Audience:    "opentdf-platform",
		CacheTTL:    time.Minute,
	}, nil)
	require.NoError(t, err)
	tok := cwttest.SignLabeled(
		t, priv, kid,
		standardClaims("https://idp.example", "some-other-rs", "user-1", time.Hour),
		nil,
	)
	_, _, err = v.VerifyCWTSubjectToken(context.Background(), tok)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "aud")
}

func TestCWTVerifier_RejectsExpired(t *testing.T) {
	priv, kid := cwttest.NewKey(t)
	srv := keySetServer(t, coseKeySetFromPub(t, &priv.PublicKey, kid))
	defer srv.Close()
	v, err := NewCWTVerifier(context.Background(), CWTVerifierConfig{
		COSEKeysURL: srv.URL,
		Issuer:      "https://idp.example",
		Audience:    "opentdf-platform",
		CacheTTL:    time.Minute,
	}, nil)
	require.NoError(t, err)
	tok := cwttest.SignLabeled(
		t, priv, kid,
		standardClaims("https://idp.example", "opentdf-platform", "user-1", -time.Minute),
		nil,
	)
	_, _, err = v.VerifyCWTSubjectToken(context.Background(), tok)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "expired")
}

func TestCWTVerifier_RejectsUnknownKid(t *testing.T) {
	priv1, kid1 := cwttest.NewKey(t)
	priv2, kid2 := cwttest.NewKey(t)
	// Server publishes priv1's public key.
	srv := keySetServer(t, coseKeySetFromPub(t, &priv1.PublicKey, kid1))
	defer srv.Close()
	v, err := NewCWTVerifier(context.Background(), CWTVerifierConfig{
		COSEKeysURL: srv.URL,
		Issuer:      "https://idp.example",
		Audience:    "opentdf-platform",
		CacheTTL:    time.Minute,
	}, nil)
	require.NoError(t, err)
	// Sign with priv2 and kid2 — server doesn't know it.
	tok := cwttest.SignLabeled(
		t, priv2, kid2,
		standardClaims("https://idp.example", "opentdf-platform", "user-1", time.Hour),
		nil,
	)
	_, _, err = v.VerifyCWTSubjectToken(context.Background(), tok)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "verify")
}

func TestCWTVerifier_RejectsMalformedBase64(t *testing.T) {
	priv, kid := cwttest.NewKey(t)
	srv := keySetServer(t, coseKeySetFromPub(t, &priv.PublicKey, kid))
	defer srv.Close()
	v, err := NewCWTVerifier(context.Background(), CWTVerifierConfig{
		COSEKeysURL: srv.URL,
		Issuer:      "https://idp.example",
		Audience:    "opentdf-platform",
		CacheTTL:    time.Minute,
	}, nil)
	require.NoError(t, err)
	_, _, err = v.VerifyCWTSubjectToken(context.Background(), "!!!not base64!!!")
	require.Error(t, err)
}

func TestCWTVerifier_RejectsMalformedCBOR(t *testing.T) {
	priv, kid := cwttest.NewKey(t)
	srv := keySetServer(t, coseKeySetFromPub(t, &priv.PublicKey, kid))
	defer srv.Close()
	v, err := NewCWTVerifier(context.Background(), CWTVerifierConfig{
		COSEKeysURL: srv.URL,
		Issuer:      "https://idp.example",
		Audience:    "opentdf-platform",
		CacheTTL:    time.Minute,
	}, nil)
	require.NoError(t, err)
	// Valid base64, decodes to non-COSE bytes.
	garbage := base64.RawURLEncoding.EncodeToString([]byte("not a cose_sign1"))
	_, _, err = v.VerifyCWTSubjectToken(context.Background(), garbage)
	require.Error(t, err)
}

func TestCWTVerifier_CustomClaimsRoundTrip(t *testing.T) {
	priv, kid := cwttest.NewKey(t)
	srv := keySetServer(t, coseKeySetFromPub(t, &priv.PublicKey, kid))
	defer srv.Close()
	v, err := NewCWTVerifier(context.Background(), CWTVerifierConfig{
		COSEKeysURL: srv.URL,
		Issuer:      "https://idp.example",
		Audience:    "opentdf-platform",
		CacheTTL:    time.Minute,
	}, nil)
	require.NoError(t, err)
	subjectToken := cwttest.SignLabeled(
		t, priv, kid,
		standardClaims("https://idp.example", "opentdf-platform", "user-1", time.Hour),
		map[string]any{
			"arkavo_roles":        []any{"admin", "reader"},
			"arkavo_entitlements": []any{"tdf:create", "tdf:decrypt"},
			"arkavo_account_id":   "acct-9999",
			"idp":                 "webauthn",
			"email":               "bob@example.com",
		},
	)
	tok, _, err := v.VerifyCWTSubjectToken(context.Background(), subjectToken)
	require.NoError(t, err)

	roles, ok := tok.Get("arkavo_roles")
	require.True(t, ok)
	rolesSlice, ok := roles.([]any)
	require.True(t, ok)
	require.Len(t, rolesSlice, 2)
	assert.Equal(t, "admin", rolesSlice[0])

	idp, ok := tok.Get("idp")
	require.True(t, ok)
	assert.Equal(t, "webauthn", idp)
}

func TestCWTVerifier_AudienceArrayMatches(t *testing.T) {
	priv, kid := cwttest.NewKey(t)
	srv := keySetServer(t, coseKeySetFromPub(t, &priv.PublicKey, kid))
	defer srv.Close()
	v, err := NewCWTVerifier(context.Background(), CWTVerifierConfig{
		COSEKeysURL: srv.URL,
		Issuer:      "https://idp.example",
		Audience:    "opentdf-platform",
		CacheTTL:    time.Minute,
	}, nil)
	require.NoError(t, err)
	claims := standardClaims("https://idp.example", "", "user-1", time.Hour)
	claims[3] = []any{"some-other-rs", "opentdf-platform"} // aud as array
	tok := cwttest.SignLabeled(t, priv, kid, claims, nil)
	_, _, err = v.VerifyCWTSubjectToken(context.Background(), tok)
	require.NoError(t, err)
}

func TestNewCWTVerifier_RejectsBadConfig(t *testing.T) {
	cases := map[string]CWTVerifierConfig{
		"missing url":   {Issuer: "i", Audience: "a"},
		"missing iss":   {COSEKeysURL: "https://x", Audience: "a"},
		"missing aud":   {COSEKeysURL: "https://x", Issuer: "i"},
		"bad algorithm": {COSEKeysURL: "https://x", Issuer: "i", Audience: "a", Algorithm: "RS256"},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			_, err := NewCWTVerifier(context.Background(), c, nil)
			require.Error(t, err)
		})
	}
}

func TestDecodeCWTClaimsFromToken_ParseOnly(t *testing.T) {
	priv, kid := cwttest.NewKey(t)
	tokenRaw := cwttest.SignLabeled(
		t, priv, kid,
		map[int64]any{
			1: "https://identity.arkavo.net",
			2: "did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK",
			3: []any{"https://platform.arkavo.net"},
			4: int64(4102444800),
			6: int64(1700000000),
		},
		map[string]any{
			"arkavo_entitlements": []any{"https://arkavo.ai/attr/tdf/value/decrypt"},
			"arkavo_npe":          map[any]any{"type": "agent", "depth": uint64(0)},
		},
	)

	claims, err := DecodeCWTClaimsFromToken(tokenRaw)
	require.NoError(t, err)
	assert.Equal(t, "did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK", claims["sub"])

	npe, _ := claims["arkavo_npe"].(map[string]any)
	assert.Equal(t, "agent", npe["type"])

	_, err = DecodeCWTClaimsFromToken("not-a-cwt")
	require.Error(t, err)
}

func TestDecodeClaimsFromToken_JOSEThenCWT(t *testing.T) {
	jose, err := encodeUnsignedJWT(map[string]any{"iss": "i", "sub": "s", "arkavo_patreon": map[string]any{"role": "consumer"}})
	require.NoError(t, err)
	m, err := DecodeClaimsFromToken(t.Context(), jose)
	require.NoError(t, err)
	assert.Equal(t, "i", m["iss"])
	assert.Equal(t, "s", m["sub"])
	pat, ok := m["arkavo_patreon"].(map[string]any)
	require.True(t, ok, "JOSE: arkavo_patreon should decode to a map")
	assert.Equal(t, "consumer", pat["role"])

	priv, kid := cwttest.NewKey(t)
	cwt := cwttest.SignLabeled(
		t, priv, kid,
		map[int64]any{1: "i", 2: "s"},
		map[string]any{"arkavo_patreon": map[any]any{"role": "consumer"}},
	)
	m, err = DecodeClaimsFromToken(t.Context(), cwt)
	require.NoError(t, err)
	assert.Equal(t, "i", m["iss"])
	assert.Equal(t, "s", m["sub"])
	pat, ok = m["arkavo_patreon"].(map[string]any)
	require.True(t, ok, "CWT: arkavo_patreon should decode to a map")
	assert.Equal(t, "consumer", pat["role"])

	_, err = DecodeClaimsFromToken(t.Context(), "definitely-not-a-token")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "neither JWT nor CWT")
}

// The combined parse failure reaches clients as a connect/gRPC status message
// and structured logs, both of which are single-line. errors.Join separates
// with a newline, which has to be percent-encoded in the grpc-message header
// and breaks single-line log ingestion.
func TestDecodeClaimsFromToken_ParseErrorIsSingleLine(t *testing.T) {
	_, err := DecodeClaimsFromToken(t.Context(), "definitely-not-a-token")
	require.Error(t, err)

	assert.NotContains(t, err.Error(), "\n", "parse error must stay on one line")
	// Both reasons still survive, and the CWT error stays unwrappable.
	assert.Contains(t, err.Error(), "neither JWT nor CWT")
	assert.Contains(t, err.Error(), "jwt:")
	assert.Contains(t, err.Error(), "cwt:")
	assert.Error(t, errors.Unwrap(err), "cwt error must remain wrapped")
}

// The helper's contract is that callers read one map shape regardless of wire
// format. Standard claims must therefore come back as the same Go types from
// both branches: a caller comparing exp numerically, or handing the map to
// structpb.NewStruct, must not behave differently per format.
func TestDecodeClaimsFromToken_UniformStandardClaimTypes(t *testing.T) {
	const expUnix = int64(4102444800)

	jose, err := encodeUnsignedJWT(map[string]any{
		"iss": "https://identity.arkavo.net",
		"sub": "did:key:zSub",
		"aud": []string{"https://platform.arkavo.net"},
		"exp": expUnix,
	})
	require.NoError(t, err)
	joseClaims, err := DecodeClaimsFromToken(t.Context(), jose)
	require.NoError(t, err)

	priv, kid := cwttest.NewKey(t)
	cwt := cwttest.SignLabeled(t, priv, kid, map[int64]any{
		1: "https://identity.arkavo.net",
		2: "did:key:zSub",
		3: "https://platform.arkavo.net", // CWT aud is a bare string
		4: expUnix,
	}, nil)
	cwtClaims, err := DecodeClaimsFromToken(t.Context(), cwt)
	require.NoError(t, err)

	for _, k := range []string{"iss", "sub", "aud", "exp"} {
		assert.IsType(t, joseClaims[k], cwtClaims[k],
			"claim %q has a different Go type per wire format", k)
		assert.Equal(t, joseClaims[k], cwtClaims[k], "claim %q differs per wire format", k)
	}

	// Pin the canonical shapes so the equality above is not vacuous.
	assert.Equal(t, expUnix, cwtClaims["exp"], "exp must be epoch seconds, not time.Time")
	assert.Equal(t, []string{"https://platform.arkavo.net"}, cwtClaims["aud"],
		"aud must always be a list")
}

// A CWT's custom claims decode to CBOR-native Go types. The helper normalizes
// them so every consumer — structpb.NewStruct, JSON serialization, a subject
// mapping selector — sees one JSON-shaped map, instead of each provider
// re-deriving its own sanitizer.
func TestDecodeClaimsFromToken_NormalizesCBORNativeValues(t *testing.T) {
	priv, kid := cwttest.NewKey(t)
	cwt := cwttest.SignLabeled(
		t, priv, kid,
		map[int64]any{1: "https://identity.arkavo.net", 2: "did:key:zSub"},
		map[string]any{
			"arkavo_patreon": map[any]any{
				"last_charge_at": cbor.Tag{Number: 1, Content: int64(1700000000)},
				"attestation":    []byte{0xde, 0xad, 0xbe, 0xef},
				"depth":          uint64(3),
				"unknown_tag":    cbor.Tag{Number: 999, Content: "opaque"},
			},
		},
	)

	claims, err := DecodeClaimsFromToken(t.Context(), cwt)
	require.NoError(t, err)

	pat, ok := claims["arkavo_patreon"].(map[string]any)
	require.True(t, ok, "arkavo_patreon should decode to a map")
	assert.Equal(t, int64(1700000000), pat["last_charge_at"], "tag-1 timestamp -> epoch seconds")
	assert.Equal(t, "3q2-7w", pat["attestation"], "byte string -> base64url")
	assert.Equal(t, int64(3), pat["depth"], "uint64 -> int64")
	assert.NotContains(t, pat, "unknown_tag", "value with no JSON representation is dropped")

	// The normalized map is directly usable by structpb, which is what the
	// entity resolution providers hand it to.
	_, err = structpb.NewStruct(pat)
	require.NoError(t, err, "normalized claims must be structpb-safe")
}

// StructpbSafe is what callers run a normalized claims map through before
// structpb.NewStruct. A []string is trivially representable, and the aud
// claim is canonically one, so dropping it would silently lose the audience
// of every JOSE token.
func TestStructpbSafe_StringSlice(t *testing.T) {
	safe, ok := StructpbSafe(map[string]any{
		"aud":   []string{"https://platform.arkavo.net", "https://kas.arkavo.net"},
		"empty": []string{},
	})
	require.True(t, ok)

	m, isMap := safe.(map[string]any)
	require.True(t, isMap)
	assert.Equal(t, []any{"https://platform.arkavo.net", "https://kas.arkavo.net"}, m["aud"],
		"[]string must survive as a list, not be dropped")
	assert.Equal(t, []any{}, m["empty"])

	_, err := structpb.NewStruct(m)
	require.NoError(t, err)
}
