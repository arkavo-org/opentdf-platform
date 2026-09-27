package auth

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/base64"
	"testing"
	"time"

	"github.com/fxamacker/cbor/v2"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const (
	coordLen = 32
	// agentDID is the key id authnz-rs writes for an agent cnf: the DID bytes,
	// both at COSE_Key label 2 (kid) and at cnf member 2.
	agentDID = "did:key:z6Mkagent"
	// deviceKid stands in for the App Attest device id / passkey credential id
	// authnz-rs uses as the kid of a P-256 cnf.
	deviceKid = "device-kid"
)

// ed25519CNF is the cnf authnz-rs mints for an agent (cwt.rs cnf_from_ed25519
// + claims_to_cbor): member 1 = COSE_Key {kty OKP, kid DID bytes, crv
// Ed25519, x}, no alg; member 2 = the DID bytes again. RFC 8747 reserves
// member 2 for an encrypted key, so the verifier must ignore it rather than
// reject the token.
func ed25519CNF(pub ed25519.PublicKey) map[any]any {
	return map[any]any{
		1: map[any]any{1: 1, 2: []byte(agentDID), -1: 6, -2: []byte(pub)},
		2: []byte(agentDID),
	}
}

// p256CNF is the cnf authnz-rs mints for an App Attest or passkey binding
// (cwt.rs cose_key_from_p256_verifying_key / cnf_from_passkey): member 1 =
// COSE_Key {kty EC2, kid, alg ES256, crv P-256, x, y}; member 2 = the kid.
func p256CNF(pub *ecdsa.PublicKey) map[any]any {
	return map[any]any{
		1: map[any]any{
			1: 2, 2: []byte(deviceKid), 3: -7, -1: 1,
			-2: pub.X.FillBytes(make([]byte, coordLen)),
			-3: pub.Y.FillBytes(make([]byte, coordLen)),
		},
		2: []byte(deviceKid),
	}
}

// decoded round-trips v through CBOR so tests see the key types the CWT
// decoder really produces (uint64 for positive labels, int64 for negative).
func decoded(t *testing.T, v any) map[any]any {
	t.Helper()
	raw, err := cbor.Marshal(v)
	require.NoError(t, err)
	var out map[any]any
	require.NoError(t, cbor.Unmarshal(raw, &out))
	return out
}

func TestCnfClaim_Ed25519COSEKeyBecomesJWK(t *testing.T) {
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)

	got := cnfClaim(decoded(t, ed25519CNF(pub)))

	// Exact equality: neither the COSE_Key kid nor cnf member 2 may leak.
	assert.Equal(t, map[string]any{"jwk": map[string]any{
		"kty": "OKP", "crv": "Ed25519", "x": base64.RawURLEncoding.EncodeToString(pub),
	}}, got)
}

func TestCnfClaim_P256COSEKeyBecomesJWK(t *testing.T) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	got := cnfClaim(decoded(t, p256CNF(&priv.PublicKey)))

	assert.Equal(t, map[string]any{"jwk": map[string]any{
		"kty": "EC", "crv": "P-256",
		"x": base64.RawURLEncoding.EncodeToString(priv.X.FillBytes(make([]byte, coordLen))),
		"y": base64.RawURLEncoding.EncodeToString(priv.Y.FillBytes(make([]byte, coordLen))),
	}}, got)
}

func TestCnfClaim_COSEKeyWithoutMember2BecomesJWK(t *testing.T) {
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)

	got := cnfClaim(decoded(t, map[any]any{1: map[any]any{1: 1, -1: 6, -2: []byte(pub)}}))

	assert.Equal(t, map[string]any{"jwk": map[string]any{
		"kty": "OKP", "crv": "Ed25519", "x": base64.RawURLEncoding.EncodeToString(pub),
	}}, got)
}

func TestCnfClaim_RefusesUnsupportedKeys(t *testing.T) {
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	x := priv.X.FillBytes(make([]byte, coordLen))
	y := priv.Y.FillBytes(make([]byte, coordLen))
	offCurveY := append([]byte{}, y...)
	offCurveY[coordLen-1] ^= 0x01

	tests := []struct {
		name   string
		key    map[any]any
		reason string
	}{
		{"P-384 curve", map[any]any{1: 2, -1: 2, -2: x, -3: y}, "neither OKP/Ed25519 nor EC2/P-256"},
		{"private key material", map[any]any{1: 1, -1: 6, -2: []byte(pub), -4: []byte("secret")}, "private key material"},
		{"short Ed25519 x", map[any]any{1: 1, -1: 6, -2: []byte(pub[:31])}, "x is 31 bytes"},
		{"alg disagrees with key type", map[any]any{1: 1, 3: -7, -1: 6, -2: []byte(pub)}, "does not match its key type"},
		{"compressed P-256 point", map[any]any{1: 2, -1: 1, -2: x, -3: true}, "compressed points"},
		{"point off the curve", map[any]any{1: 2, -1: 1, -2: x, -3: offCurveY}, "not a valid point"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Member 2 rides along as authnz-rs emits it; it must not rescue
			// or mask a bad COSE_Key.
			cnf := map[any]any{1: tt.key, 2: []byte(agentDID)}
			got, ok := cnfClaim(decoded(t, cnf)).(map[string]any)
			require.True(t, ok)
			reason, ok := got[cnfUnsupportedMember].(string)
			require.True(t, ok, "unsupported key must be marked, got %v", got)
			assert.Contains(t, reason, tt.reason)
			assert.NotContains(t, got, "jwk")
		})
	}
}

func TestCnfClaim_NonMapCOSEKeyIsMarked(t *testing.T) {
	got, ok := cnfClaim(decoded(t, map[any]any{1: []byte("not-a-key"), 2: []byte(agentDID)})).(map[string]any)
	require.True(t, ok)
	assert.Equal(t, "cnf COSE_Key is not a map", got[cnfUnsupportedMember])
	assert.NotContains(t, got, "jwk")
}

func TestCnfClaim_TextKeyedJKTUnchanged(t *testing.T) {
	assert.Equal(t, map[string]any{"jkt": "abc"}, cnfClaim(decoded(t, map[any]any{"jkt": "abc"})))
}

func TestCWTVerifier_RendersCOSEKeyCnfAsJWK(t *testing.T) {
	priv, kid := newP256(t)
	srv := keySetServer(t, coseKeySetFromPub(t, &priv.PublicKey, kid))
	defer srv.Close()
	v, err := NewCWTVerifier(t.Context(), CWTVerifierConfig{
		COSEKeysURL: srv.URL, Issuer: "https://identity.test", Audience: "https://platform.test",
	}, nil)
	require.NoError(t, err)
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	claims := standardClaims("https://identity.test", "https://platform.test", agentDID, time.Hour)
	claims[cwtLabelCnf] = ed25519CNF(pub)

	tok, err := v.VerifyAccessToken(t.Context(), signCWT(t, priv, kid, claims, nil))
	require.NoError(t, err)

	cnf, ok := tok.Get("cnf")
	require.True(t, ok)
	assert.Equal(t, map[string]any{"jwk": map[string]any{
		"kty": "OKP", "crv": "Ed25519", "x": base64.RawURLEncoding.EncodeToString(pub),
	}}, cnf)
}
