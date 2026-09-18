// Package cwttest mints COSE_Sign1 CWTs for tests.
//
// The same ~35-line minting helper had been copied into four packages
// (service/internal/auth, service/authorization/v2, and the arkavo and
// patreon entity resolvers), so any change to the wire fixture — tag #61
// wrapping, untagged Sign1, a new header label — had to be made four times
// or the packages silently diverged in what they claimed to test. It lives
// here instead, importable by all of them; a _test.go helper is not.
package cwttest

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/base64"
	"testing"

	"github.com/fxamacker/cbor/v2"
	"github.com/veraison/go-cose"
)

// CWT standard claim labels (RFC 8392 §4) used by the convenience helpers,
// and the length of the key-derived suffix in a generated kid.
const (
	labelIss  = int64(1)
	labelSub  = int64(2)
	kidSuffix = 4
)

// NewKey returns a fresh ECDSA P-256 keypair plus a short deterministic kid
// derived from it, matching the key ids the COSE Key Set fixtures publish.
func NewKey(t *testing.T) (*ecdsa.PrivateKey, []byte) {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("cwttest: generate key: %v", err)
	}
	return priv, append([]byte("kid-"), pad(priv.X.Bytes(), kidSuffix)...)
}

func pad(b []byte, n int) []byte {
	if len(b) >= n {
		return b[:n]
	}
	out := make([]byte, n)
	copy(out[n-len(b):], b)
	return out
}

// Sign CBOR-encodes claims, signs them as an ES256 COSE_Sign1, and returns
// the base64url wire form the platform accepts as a bearer. A nil kid omits
// the key id header, which is what the resolvers' fixtures do — they never
// verify the signature.
func Sign(t *testing.T, priv *ecdsa.PrivateKey, kid []byte, claims map[any]any) string {
	t.Helper()
	payload, err := cbor.Marshal(claims)
	if err != nil {
		t.Fatalf("cwttest: marshal payload: %v", err)
	}
	signer, err := cose.NewSigner(cose.AlgorithmES256, priv)
	if err != nil {
		t.Fatalf("cwttest: new signer: %v", err)
	}
	protected := cose.ProtectedHeader{cose.HeaderLabelAlgorithm: cose.AlgorithmES256}
	if len(kid) > 0 {
		protected[cose.HeaderLabelKeyID] = kid
	}
	msg := cose.Sign1Message{
		Headers: cose.Headers{Protected: protected},
		Payload: payload,
	}
	if err := msg.Sign(rand.Reader, nil, signer); err != nil {
		t.Fatalf("cwttest: sign: %v", err)
	}
	raw, err := msg.MarshalCBOR()
	if err != nil {
		t.Fatalf("cwttest: marshal cose: %v", err)
	}
	return base64.RawURLEncoding.EncodeToString(raw)
}

// SignLabeled is Sign for the common split between standard claims (CBOR
// integer labels, RFC 8392 §4) and custom ones (text labels, which is how
// authnz-rs encodes them).
func SignLabeled(t *testing.T, priv *ecdsa.PrivateKey, kid []byte, std map[int64]any, custom map[string]any) string {
	t.Helper()
	claims := make(map[any]any, len(std)+len(custom))
	for k, v := range std {
		claims[k] = v
	}
	for k, v := range custom {
		claims[k] = v
	}
	return Sign(t, priv, kid, claims)
}

// SignEphemeral mints a CWT for iss/sub plus custom claims under a throwaway
// key and no kid — for consumers that decode a bearer verified upstream and
// never check the signature.
func SignEphemeral(t *testing.T, iss, sub string, custom map[any]any) string {
	t.Helper()
	priv, _ := NewKey(t)
	claims := map[any]any{labelIss: iss, labelSub: sub}
	for k, v := range custom {
		claims[k] = v
	}
	return Sign(t, priv, nil, claims)
}
