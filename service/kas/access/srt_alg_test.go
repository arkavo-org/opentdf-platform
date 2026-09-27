package access

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"net/http"
	"testing"

	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/lestrrat-go/jwx/v2/jwk"
	"github.com/lestrrat-go/jwx/v2/jwt"
	kaspb "github.com/opentdf/platform/protocol/go/kas"
	"github.com/opentdf/platform/service/logger"
	ctxAuth "github.com/opentdf/platform/service/pkg/auth"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/encoding/protojson"
)

func signedSRT(t *testing.T, alg jwa.SignatureAlgorithm, signer any) string {
	t.Helper()
	body, err := protojson.Marshal(&kaspb.UnsignedRewrapRequest{
		Requests:        makeRewrapRequests(t, fauxPolicyBytes(t), false),
		ClientPublicKey: rsaPublicAlt,
	})
	require.NoError(t, err)
	tok := jwt.New()
	require.NoError(t, tok.Set("requestBody", string(body)))
	raw, err := jwt.Sign(tok, jwt.WithKey(alg, signer))
	require.NoError(t, err)
	return string(raw)
}

func publicJWK(t *testing.T, raw any) jwk.Key {
	t.Helper()
	key, err := jwk.FromRaw(raw)
	require.NoError(t, err)
	return key
}

func TestExtractSRTBody_CallerKeyAlgorithms(t *testing.T) {
	edPub, edPriv, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	otherEdPub, _, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	ecPriv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	ec384Priv, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	require.NoError(t, err)

	tests := []struct {
		name string
		srt  string
		dpop jwk.Key
		ok   bool
	}{
		{"EdDSA SRT verified by the agent's Ed25519 DPoP key", signedSRT(t, jwa.EdDSA, edPriv), publicJWK(t, edPub), true},
		{"ES256 SRT verified by a P-256 DPoP key", signedSRT(t, jwa.ES256, ecPriv), publicJWK(t, &ecPriv.PublicKey), true},
		{"RSA DPoP key keeps RS256", signedSRT(t, jwa.RS256, entityPrivateKey(t)), publicJWK(t, entityPublicKey(t)), true},
		{"EdDSA SRT signed by another key is refused", signedSRT(t, jwa.EdDSA, edPriv), publicJWK(t, otherEdPub), false},
		{"RS256 SRT against an Ed25519 DPoP key is refused", signedSRT(t, jwa.RS256, entityPrivateKey(t)), publicJWK(t, edPub), false},
		{"ES256 SRT against an Ed25519 DPoP key is refused", signedSRT(t, jwa.ES256, ecPriv), publicJWK(t, edPub), false},
		{"EdDSA SRT against a P-256 DPoP key is refused", signedSRT(t, jwa.EdDSA, edPriv), publicJWK(t, &ecPriv.PublicKey), false},
		{"unmapped P-384 DPoP key is refused", signedSRT(t, jwa.ES384, ec384Priv), publicJWK(t, &ec384Priv.PublicKey), false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := ctxAuth.ContextWithAuthNInfo(t.Context(), tt.dpop, mockJWT(t), "bearer")
			p := &Provider{Logger: logger.CreateTestLogger()}
			body, _, err := p.extractSRTBody(ctx, http.Header{}, &kaspb.RewrapRequest{SignedRequestToken: tt.srt})
			if !tt.ok {
				require.Error(t, err)
				assert.Contains(t, err.Error(), "unable to verify request token")
				return
			}
			require.NoError(t, err)
			require.NotNil(t, body)
		})
	}
}
