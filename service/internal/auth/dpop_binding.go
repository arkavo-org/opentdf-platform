package auth

import (
	"crypto"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/lestrrat-go/jwx/v2/jwk"
	"github.com/lestrrat-go/jwx/v2/jwt"
)

// maxDPoPJTILen bounds the id a key holder can make the server store and hash.
const maxDPoPJTILen = 256

// dpopBinding reads what a token's cnf binds it to and returns the RFC 7638
// thumbprint the DPoP proof key must have. A `jkt` (RFC 9449) is used as
// given. A `jwk` is thumbprinted here: either the CWT verifier rendered it
// from an RFC 8747 COSE_Key (authnz-rs agents), or a trusted issuer put it in
// a JSON JWT as an RFC 7800 cnf. For both, the second result (keyBound)
// reports that the key-bound proof rules (algorithm matches key, single-use
// jti) apply.
func dpopBinding(cnf map[string]any) (string, bool, error) {
	jktValue, hasJKT := cnf["jkt"]
	jwkValue, hasJWK := cnf["jwk"]
	switch {
	case hasJKT && hasJWK:
		return "", false, errors.New("`cnf` claim carries both `jkt` and `jwk`")
	case hasJWK:
		thumbprint, err := cnfKeyThumbprint(jwkValue)
		return thumbprint, true, err
	case hasJKT:
		jkt, ok := jktValue.(string)
		if !ok {
			return "", false, fmt.Errorf("invalid `jkt` field in `cnf` claim: %v. the value must be a JWK thumbprint", jktValue)
		}
		return jkt, false, nil
	}
	if reason, ok := cnf[cnfUnsupportedMember].(string); ok {
		return "", false, fmt.Errorf("unsupported COSE_Key in `cnf` claim: %s", reason)
	}
	return "", false, errors.New("missing `jkt` or COSE_Key in `cnf` claim")
}

func cnfKeyThumbprint(v any) (string, error) {
	raw, err := json.Marshal(v)
	if err != nil {
		return "", fmt.Errorf("`cnf.jwk` is not serializable: %w", err)
	}
	key, err := jwk.ParseKey(raw)
	if err != nil {
		return "", fmt.Errorf("`cnf.jwk` is not a JWK: %w", err)
	}
	if private, err := jwk.IsPrivateKey(key); err != nil || private {
		return "", errors.New("`cnf.jwk` must be a public key")
	}
	thumbprint, err := key.Thumbprint(crypto.SHA256)
	if err != nil {
		return "", fmt.Errorf("couldn't compute thumbprint for `cnf.jwk`: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(thumbprint), nil
}

// SignatureAlgorithmForKey names the one JWS algorithm a proof-of-possession
// key may sign with. RSA keeps RS256, the only algorithm the KAS SRT check
// ever accepted; EC keys must be P-256 (ES256) and OKP keys Ed25519 (EdDSA).
func SignatureAlgorithmForKey(key jwk.Key) (jwa.SignatureAlgorithm, error) {
	switch k := key.(type) {
	case jwk.RSAPublicKey:
		return jwa.RS256, nil
	case jwk.ECDSAPublicKey:
		if k.Crv() == jwa.P256 {
			return jwa.ES256, nil
		}
		return "", fmt.Errorf("unsupported EC curve %v for proof of possession", k.Crv())
	case jwk.OKPPublicKey:
		if k.Crv() == jwa.Ed25519 {
			return jwa.EdDSA, nil
		}
		return "", fmt.Errorf("unsupported OKP curve %v for proof of possession", k.Crv())
	default:
		return "", fmt.Errorf("unsupported key type %v for proof of possession", key.KeyType())
	}
}

// proofAlgorithmMatchesKey holds a key-bound proof to the one algorithm its
// key signs with.
func proofAlgorithmMatchesKey(alg jwa.SignatureAlgorithm, key jwk.Key) error {
	want, err := SignatureAlgorithmForKey(key)
	if err != nil {
		return err
	}
	if alg != want {
		return fmt.Errorf("DPoP JWT alg %v does not match its key (want %v)", alg, want)
	}
	return nil
}

// claimProofID spends a key-bound proof's jti. It runs after every other
// proof check so a rejected proof never consumes an id. The id is kept,
// keyed by the proof key's thumbprint, until the proof could no longer be
// accepted: iat + dpopskew, or sooner the access token's exp + skew, since
// the proof's ath binds it to that token (agent tokens live 15 min or less,
// dpopskew defaults to 1 h). A zero tokenExp means the token has no exp. now
// must be the reading validateDPoP judged the proof live on.
func (a Authentication) claimProofID(proof jwt.Token, tokenExp time.Time, thumbprint string, now time.Time) error {
	jti := proof.JwtID()
	if jti == "" {
		return errors.New("missing `jti` claim in DPoP JWT")
	}
	if len(jti) > maxDPoPJTILen {
		return fmt.Errorf("DPoP JWT `jti` is longer than %d bytes", maxDPoPJTILen)
	}
	if a.dpopReplay == nil {
		return errors.New("DPoP replay cache is not configured")
	}
	expiry := proof.IssuedAt().Add(a.oidcConfiguration.DPoPSkew)
	if !tokenExp.IsZero() {
		expiry = minTime(expiry, tokenExp.Add(a.oidcConfiguration.TokenSkew))
	}
	if !a.dpopReplay.claim(thumbprint+"."+jti, expiry, now) {
		return errors.New("DPoP JWT `jti` has already been used")
	}
	return nil
}

func minTime(a, b time.Time) time.Time {
	if b.Before(a) {
		return b
	}
	return a
}
