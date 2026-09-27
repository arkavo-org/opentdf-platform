package auth

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/lestrrat-go/jwx/v2/jwk"
	"github.com/lestrrat-go/jwx/v2/jws"
	"github.com/lestrrat-go/jwx/v2/jwt"
	"github.com/opentdf/platform/service/logger"
	ctxAuth "github.com/opentdf/platform/service/pkg/auth"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const rewrapProcedure = "/kas.AccessService/Rewrap"

// fakeIDP serves OIDC discovery and a one-key COSE Key Set, as authnz-rs
// does, and returns the key that signs the CWTs it issues.
func fakeIDP(t *testing.T) (*httptest.Server, *ecdsa.PrivateKey, []byte) {
	t.Helper()
	priv, kid := newP256(t)
	keySetCBOR := coseKeySetFromPub(t, &priv.PublicKey, kid)
	var srv *httptest.Server
	srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/.well-known/openid-configuration":
			w.Header().Set("Content-Type", "application/json")
			_, _ = fmt.Fprintf(w, `{"issuer":%q,"jwks_uri":%q,"cose_keys_uri":%q}`,
				srv.URL, srv.URL+"/jwks", srv.URL+"/cose-keys")
		case "/cose-keys":
			w.Header().Set("Content-Type", "application/cose-key-set+cbor")
			_, _ = w.Write(keySetCBOR)
		case "/jwks":
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"keys":[]}`))
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(srv.Close)
	return srv, priv, kid
}

// newAgentAuth mirrors production: enforceDPoP off, so only the token's own
// cnf demands a proof.
func newAgentAuth(t *testing.T) (*Authentication, func(cnf map[any]any) string) {
	t.Helper()
	srv, priv, kid := fakeIDP(t)
	a, err := NewAuthenticator(t.Context(), Config{AuthNConfig: AuthNConfig{
		EnforceDPoP: false, Issuer: srv.URL, Audience: "test", DPoPSkew: time.Hour, TokenSkew: time.Minute,
	}}, logger.CreateTestLogger(), func(string, any) error { return nil })
	require.NoError(t, err)
	mint := func(cnf map[any]any) string {
		claims := standardClaims(srv.URL, "test", agentDID, time.Hour)
		claims[cwtLabelCnf] = cnf
		return signCWT(t, priv, kid, claims, nil)
	}
	return a, mint
}

func rewrapReceiver() receiverInfo {
	return receiverInfo{u: []string{rewrapProcedure}, m: []string{http.MethodPost}}
}

// agentProof signs an RFC 9449 proof the way opentdf-rs's caller-key mode
// does: typ dpop+jwt, the public key in the jwk header, ath over the token.
func agentProof(t *testing.T, signer any, alg jwa.SignatureAlgorithm, accessToken, htu, jti string) string {
	t.Helper()
	return agentProofAt(t, signer, alg, accessToken, htu, jti, time.Now())
}

func agentProofAt(t *testing.T, signer any, alg jwa.SignatureAlgorithm, accessToken, htu, jti string, iat time.Time) string {
	t.Helper()
	key, err := jwk.FromRaw(signer)
	require.NoError(t, err)
	pub, err := key.PublicKey()
	require.NoError(t, err)
	hdr := jws.NewHeaders()
	require.NoError(t, hdr.Set(jws.JWKKey, pub))
	require.NoError(t, hdr.Set(jws.TypeKey, dpopJWTType))
	ath := sha256.Sum256([]byte(accessToken))
	b := jwt.NewBuilder().
		Claim("htm", http.MethodPost).
		Claim("htu", htu).
		Claim("ath", base64.RawURLEncoding.EncodeToString(ath[:])).
		IssuedAt(iat)
	if jti != "" {
		b = b.JwtID(jti)
	}
	tok, err := b.Build()
	require.NoError(t, err)
	signed, err := jwt.Sign(tok, jwt.WithKey(alg, key, jws.WithProtectedHeaders(hdr)))
	require.NoError(t, err)
	return string(signed)
}

func TestCOSEBoundDPoP(t *testing.T) {
	a, mint := newAgentAuth(t)
	edPub, edPriv, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	edToken := mint(ed25519CNF(edPub))

	check := func(token string, proofs []string) error {
		_, _, err := a.checkToken(t.Context(), []string{"DPoP " + token}, rewrapReceiver(), proofs, nil)
		return err
	}

	t.Run("Ed25519 proof from the cnf key is accepted and its key reaches the context", func(t *testing.T) {
		proof := agentProof(t, edPriv, jwa.EdDSA, edToken, rewrapProcedure, "jti-ed-ok")
		_, ctx, err := a.checkToken(t.Context(), []string{"DPoP " + edToken}, rewrapReceiver(), []string{proof}, nil)
		require.NoError(t, err)
		okp, ok := ctxAuth.GetJWKFromContext(ctx, a.logger).(jwk.OKPPublicKey)
		require.True(t, ok)
		assert.Equal(t, []byte(edPub), okp.X())
	})

	t.Run("P-256 proof from the cnf key is accepted", func(t *testing.T) {
		ecPriv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		require.NoError(t, err)
		ecToken := mint(p256CNF(&ecPriv.PublicKey))
		require.NoError(t, check(ecToken, []string{agentProof(t, ecPriv, jwa.ES256, ecToken, rewrapProcedure, "jti-ec-ok")}))
	})

	t.Run("missing proof is rejected even with enforceDPoP off", func(t *testing.T) {
		require.ErrorContains(t, check(edToken, nil), "got 0 dpop headers")
	})

	t.Run("proof from a different key is rejected", func(t *testing.T) {
		_, otherPriv, err := ed25519.GenerateKey(rand.Reader)
		require.NoError(t, err)
		proof := agentProof(t, otherPriv, jwa.EdDSA, edToken, rewrapProcedure, "jti-other")
		require.ErrorContains(t, check(edToken, []string{proof}), "didn't match the thumbprint")
	})

	t.Run("replayed jti is rejected", func(t *testing.T) {
		proof := agentProof(t, edPriv, jwa.EdDSA, edToken, rewrapProcedure, "jti-replay")
		require.NoError(t, check(edToken, []string{proof}))
		require.ErrorContains(t, check(edToken, []string{proof}), "already been used")
	})

	t.Run("proof without jti is rejected", func(t *testing.T) {
		proof := agentProof(t, edPriv, jwa.EdDSA, edToken, rewrapProcedure, "")
		require.ErrorContains(t, check(edToken, []string{proof}), "missing `jti`")
	})

	t.Run("proof bound to the REST origin is rejected on the Connect procedure", func(t *testing.T) {
		proof := agentProof(t, edPriv, jwa.EdDSA, edToken, "https://platform.arkavo.net/kas/v2/rewrap", "jti-rest")
		require.ErrorContains(t, check(edToken, []string{proof}), "incorrect `htu`")
	})

	t.Run("Connect htu is the bare procedure path, not an absolute URL", func(t *testing.T) {
		proof := agentProof(t, edPriv, jwa.EdDSA, edToken, "https://platform.arkavo.net"+rewrapProcedure, "jti-abs")
		require.ErrorContains(t, check(edToken, []string{proof}), "incorrect `htu`")
	})

	t.Run("iat inside server.auth.skew ahead (device clock runs fast) is accepted", func(t *testing.T) {
		proof := agentProofAt(t, edPriv, jwa.EdDSA, edToken, rewrapProcedure, "jti-skew-ok", time.Now().Add(30*time.Second))
		require.NoError(t, check(edToken, []string{proof}))
	})

	t.Run("iat beyond server.auth.skew ahead is rejected", func(t *testing.T) {
		proof := agentProofAt(t, edPriv, jwa.EdDSA, edToken, rewrapProcedure, "jti-skew-bad", time.Now().Add(2*time.Minute))
		require.ErrorContains(t, check(edToken, []string{proof}), `"iat" not satisfied`)
	})

	t.Run("P-256 key signing with any algorithm but ES256 is rejected", func(t *testing.T) {
		ecPriv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		require.NoError(t, err)
		ecToken := mint(p256CNF(&ecPriv.PublicKey))
		for _, alg := range []jwa.SignatureAlgorithm{jwa.ES384, jwa.ES512} {
			proof := agentProof(t, ecPriv, alg, ecToken, rewrapProcedure, "jti-alg-"+alg.String())
			require.ErrorContains(t, check(ecToken, []string{proof}), "does not match its key", alg)
		}
	})

	t.Run("a refused proof does not spend its jti", func(t *testing.T) {
		wrongHTU := agentProof(t, edPriv, jwa.EdDSA, edToken, "/kas.AccessService/PublicKey", "jti-spent-last")
		require.ErrorContains(t, check(edToken, []string{wrongHTU}), "incorrect `htu`")
		proof := agentProof(t, edPriv, jwa.EdDSA, edToken, rewrapProcedure, "jti-spent-last")
		require.NoError(t, check(edToken, []string{proof}))
	})

	t.Run("Bearer scheme is also accepted for a COSE-bound token", func(t *testing.T) {
		proof := agentProof(t, edPriv, jwa.EdDSA, edToken, rewrapProcedure, "jti-bearer")
		_, _, err := a.checkToken(t.Context(), []string{"Bearer " + edToken}, rewrapReceiver(), []string{proof}, nil)
		require.NoError(t, err)
	})

	t.Run("unsupported COSE_Key in cnf is rejected", func(t *testing.T) {
		ecPriv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		require.NoError(t, err)
		// The authnz-rs P-256 shape (kid at label 2, member 2) relabelled as
		// P-384 (crv 2), which the verifier does not render.
		p384ish := p256CNF(&ecPriv.PublicKey)
		coseKey, ok := p384ish[1].(map[any]any)
		require.True(t, ok)
		coseKey[-1] = 2
		badToken := mint(p384ish)
		proof := agentProof(t, edPriv, jwa.EdDSA, badToken, rewrapProcedure, "jti-unsupported")
		require.ErrorContains(t, check(badToken, []string{proof}), "unsupported COSE_Key")
	})
}

func TestSignatureAlgorithmForKey(t *testing.T) {
	edPub, _, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	p256, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	p384, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	require.NoError(t, err)
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	tests := []struct {
		name string
		raw  any
		want jwa.SignatureAlgorithm
		ok   bool
	}{
		{"Ed25519", edPub, jwa.EdDSA, true},
		{"P-256", &p256.PublicKey, jwa.ES256, true},
		{"RSA keeps RS256", &rsaKey.PublicKey, jwa.RS256, true},
		{"P-384 refused", &p384.PublicKey, "", false},
		{"symmetric refused", []byte("not-a-pop-key"), "", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			key, err := jwk.FromRaw(tt.raw)
			require.NoError(t, err)
			got, err := SignatureAlgorithmForKey(key)
			if !tt.ok {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestDPoPBinding(t *testing.T) {
	edPub, _, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	edJWK, err := jwk.FromRaw(edPub)
	require.NoError(t, err)
	thumb, err := edJWK.Thumbprint(crypto.SHA256)
	require.NoError(t, err)
	wantJKT := base64.RawURLEncoding.EncodeToString(thumb)
	rendered := map[string]any{"kty": "OKP", "crv": "Ed25519", "x": base64.RawURLEncoding.EncodeToString(edPub)}

	t.Run("cnf.jwk (COSE-rendered or issuer-supplied) is thumbprinted and key-bound", func(t *testing.T) {
		jkt, keyBound, err := dpopBinding(map[string]any{"jwk": rendered})
		require.NoError(t, err)
		assert.True(t, keyBound)
		assert.Equal(t, wantJKT, jkt)
	})
	t.Run("jkt is used as given and is not key-bound", func(t *testing.T) {
		jkt, keyBound, err := dpopBinding(map[string]any{"jkt": wantJKT})
		require.NoError(t, err)
		assert.False(t, keyBound)
		assert.Equal(t, wantJKT, jkt)
	})

	refused := []struct {
		name string
		cnf  map[string]any
		want string
	}{
		{"both jkt and jwk", map[string]any{"jkt": wantJKT, "jwk": rendered}, "both `jkt` and `jwk`"},
		{"non-string jkt", map[string]any{"jkt": 7}, "invalid `jkt`"},
		{"neither member", map[string]any{"kid": "x"}, "missing `jkt` or COSE_Key"},
		{"unsupported marker", map[string]any{cnfUnsupportedMember: "why"}, "unsupported COSE_Key in `cnf` claim: why"},
		{"jwk that is not a JWK", map[string]any{"jwk": map[string]any{"kty": "nope"}}, "is not a JWK"},
		{"private jwk", map[string]any{"jwk": map[string]any{
			"kty": "OKP", "crv": "Ed25519", "x": rendered["x"], "d": base64.RawURLEncoding.EncodeToString(make([]byte, 32)),
		}}, "must be a public key"},
	}
	for _, tt := range refused {
		t.Run(tt.name, func(t *testing.T) {
			_, _, err := dpopBinding(tt.cnf)
			require.ErrorContains(t, err, tt.want)
		})
	}
}

func TestProofAlgorithmMatchesKey(t *testing.T) {
	p256, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	key, err := jwk.FromRaw(&p256.PublicKey)
	require.NoError(t, err)

	require.NoError(t, proofAlgorithmMatchesKey(jwa.ES256, key))
	require.ErrorContains(t, proofAlgorithmMatchesKey(jwa.ES384, key), "does not match its key")
	require.ErrorContains(t, proofAlgorithmMatchesKey(jwa.EdDSA, key), "does not match its key")
}

func TestDPoPReplayCache(t *testing.T) {
	now := time.Unix(1_790_000_000, 0)
	c := newDPoPReplayCache(func() time.Time { return now })

	assert.True(t, c.claim("thumb.jti", now.Add(time.Minute), now))
	assert.False(t, c.claim("thumb.jti", now.Add(time.Minute), now), "second use inside the window")
	assert.True(t, c.claim("other.jti", now.Add(time.Minute), now), "keys are per thumbprint")

	now = now.Add(2 * time.Minute)
	assert.True(t, c.claim("thumb.jti", now.Add(time.Minute), now), "an expired entry no longer blocks")
}

// validateDPoP still accepts a proof at exactly iat + dpopskew, so its id
// must still block at that instant.
func TestDPoPReplayCache_BlocksAtExpiry(t *testing.T) {
	now := time.Unix(1_790_000_000, 0)
	c := newDPoPReplayCache(func() time.Time { return now })
	expiry := now.Add(time.Minute)

	assert.True(t, c.claim("thumb.jti", expiry, now))
	now = expiry
	assert.False(t, c.claim("thumb.jti", expiry, now))
}

// The sweep runs on the cache's own clock, which can be ahead of the reading
// the validator judged the proof live on; it must not drop an entry the
// validator would still accept.
func TestDPoPReplayCache_SweepKeepsEntriesTheValidatorStillAccepts(t *testing.T) {
	validatorNow := time.Unix(1_790_000_000, 0)
	cacheNow := validatorNow
	c := newDPoPReplayCache(func() time.Time { return cacheNow })
	expiry := validatorNow.Add(45 * time.Second)

	require.True(t, c.claim("thumb.jti", expiry, validatorNow))
	cacheNow = validatorNow.Add(90 * time.Second) // past the next sweep and past expiry
	assert.False(t, c.claim("thumb.jti", expiry, validatorNow))
}

// Whoever holds an agent key chooses the jti, so entries are a fixed-size
// digest rather than the id itself.
func TestDPoPReplayCache_KeysAreDigests(t *testing.T) {
	now := time.Unix(1_790_000_000, 0)
	c := newDPoPReplayCache(func() time.Time { return now })

	require.True(t, c.claim("thumb.jti", now.Add(time.Minute), now))
	require.Len(t, c.seen, 1)
	_, ok := c.seen[sha256.Sum256([]byte("thumb.jti"))]
	assert.True(t, ok)
}

func proofWithID(t *testing.T, jti string, iat time.Time) jwt.Token {
	t.Helper()
	proof := jwt.New()
	require.NoError(t, proof.Set(jwt.JwtIDKey, jti))
	require.NoError(t, proof.Set(jwt.IssuedAtKey, iat))
	return proof
}

func TestClaimProofID_FailsClosedWithoutCache(t *testing.T) {
	proof := proofWithID(t, "j", time.Now())
	require.ErrorContains(t, Authentication{}.claimProofID(proof, "thumb", time.Now()), "not configured")
}

// validateDPoP decides a proof is still live on its own clock reading; the
// replay decision must use that same reading, or a proof whose expiry falls
// between the validator's reading and a later one is accepted twice.
func TestClaimProofID_ReplayWhenCacheClockRunsAhead(t *testing.T) {
	validatorNow := time.Unix(1_790_000_000, 0)
	a := Authentication{
		oidcConfiguration: AuthNConfig{DPoPSkew: time.Hour},
		dpopReplay:        newDPoPReplayCache(func() time.Time { return validatorNow.Add(3 * time.Second) }),
	}
	// iat + dpopskew = validatorNow + 1s: live for the validator, expired on
	// the cache's clock.
	proof := proofWithID(t, "j", validatorNow.Add(-time.Hour+time.Second))

	require.NoError(t, a.claimProofID(proof, "thumb", validatorNow))
	require.ErrorContains(t, a.claimProofID(proof, "thumb", validatorNow), "already been used")
}

func TestClaimProofID_BoundsJTILength(t *testing.T) {
	now := time.Unix(1_790_000_000, 0)
	a := Authentication{
		oidcConfiguration: AuthNConfig{DPoPSkew: time.Hour},
		dpopReplay:        newDPoPReplayCache(func() time.Time { return now }),
	}
	require.NoError(t, a.claimProofID(proofWithID(t, strings.Repeat("a", 256), now), "thumb", now))
	require.ErrorContains(t, a.claimProofID(proofWithID(t, strings.Repeat("b", 257), now), "thumb", now), "`jti` is longer than 256 bytes")
}
