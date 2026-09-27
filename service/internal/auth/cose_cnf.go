package auth

import (
	"crypto/ecdh"
	"encoding/base64"
	"errors"
	"fmt"
	"math"
)

// RFC 8747 §3.1 cnf member and the RFC 9052/9053 COSE_Key values a CWT uses
// to bind its holder to a key. Labels shared with the COSE Key Set decoder
// (kty, alg, crv, x, y) are declared in cwt_verifier.go.
const (
	cnfLabelCOSEKey     = 1
	coseKeyLabelD       = -4
	coseKtyOKP          = 1
	coseCrvEd25519      = 6
	coseAlgEdDSA        = -8
	coseAlgES256        = -7
	ed25519PublicKeyLen = 32
	p256CoordinateLen   = 32
	sec1Uncompressed    = 0x04

	// cnfUnsupportedMember is the member cnfClaim writes, in place of a key,
	// to carry why a COSE_Key could not be rendered.
	cnfUnsupportedMember = "unsupported_cose_key"
)

// claimValue normalizes one decoded CWT claim; cnf gets its own rendering.
func claimValue(name string, v any) any {
	if name == "cnf" {
		return cnfClaim(v)
	}
	return normalizeCBOR(v)
}

// cnfClaim renders a CWT cnf (label 8). An RFC 8747 cnf holding a COSE_Key
// (member 1) becomes {"jwk": <public JWK>}, its RFC 7800 JOSE equivalent,
// which validateDPoP compares with the key embedded in the DPoP proof. Other
// members are ignored: authnz-rs puts the key id (the agent DID bytes) in
// member 2, which RFC 8747 reserves for an encrypted key, and the COSE_Key's
// own kid is not part of the JWK either. A COSE_Key that cannot be rendered
// yields {cnfUnsupportedMember: reason}: dropping cnf instead would let the
// token skip proof of possession, because checkToken only runs validateDPoP
// when cnf is present. A text-keyed cnf such as {"jkt": ...} passes through
// unchanged.
func cnfClaim(v any) any {
	members, ok := v.(map[any]any)
	if !ok {
		return normalizeCBOR(v)
	}
	for k, member := range members {
		if label, isInt := coseInt(k); !isInt || label != cnfLabelCOSEKey {
			continue
		}
		key, isMap := member.(map[any]any)
		if !isMap {
			return map[string]any{cnfUnsupportedMember: "cnf COSE_Key is not a map"}
		}
		jwkMembers, err := coseKeyToJWK(key)
		if err != nil {
			return map[string]any{cnfUnsupportedMember: err.Error()}
		}
		return map[string]any{"jwk": jwkMembers}
	}
	return normalizeCBOR(v)
}

// coseInt reads a decoded CBOR integer strictly, for COSE labels and the
// kty/crv/alg values: a float is not an integer even when it equals one,
// and an unsigned value above math.MaxInt64 is refused rather than wrapped
// (2^64-8 would otherwise read as -8, EdDSA).
func coseInt(k any) (int64, bool) {
	switch x := k.(type) {
	case int64:
		return x, true
	case uint64:
		if x > math.MaxInt64 {
			return 0, false
		}
		return int64(x), true
	default:
		return 0, false
	}
}

// coseKeyToJWK renders an OKP/Ed25519 or EC2/P-256 public COSE_Key as JWK
// members (RFC 8037, RFC 7518). Every other shape is refused.
func coseKeyToJWK(key map[any]any) (map[string]any, error) {
	params := make(map[int64]any, len(key))
	for k, v := range key {
		if label, ok := coseInt(k); ok {
			params[label] = v
		}
	}
	if _, private := params[coseKeyLabelD]; private {
		return nil, errors.New("cnf COSE_Key carries private key material")
	}
	kty, _ := coseInt(params[coseKeyLabelKty])
	crv, _ := coseInt(params[coseKeyLabelCrv])
	x, _ := params[coseKeyLabelX].([]byte)
	switch {
	case kty == coseKtyOKP && crv == coseCrvEd25519:
		if err := checkCOSEAlg(params, coseAlgEdDSA); err != nil {
			return nil, err
		}
		if len(x) != ed25519PublicKeyLen {
			return nil, fmt.Errorf("cnf Ed25519 key: x is %d bytes, want %d", len(x), ed25519PublicKeyLen)
		}
		return map[string]any{"kty": "OKP", "crv": "Ed25519", "x": base64.RawURLEncoding.EncodeToString(x)}, nil
	case kty == coseKtyEC2 && crv == coseCrvP256:
		if err := checkCOSEAlg(params, coseAlgES256); err != nil {
			return nil, err
		}
		y, _ := params[coseKeyLabelY].([]byte)
		if len(x) != p256CoordinateLen || len(y) != p256CoordinateLen {
			return nil, errors.New("cnf P-256 key: x and y must each be 32 bytes (compressed points are not accepted)")
		}
		point := append([]byte{sec1Uncompressed}, x...)
		point = append(point, y...)
		if _, err := ecdh.P256().NewPublicKey(point); err != nil {
			return nil, fmt.Errorf("cnf P-256 key is not a valid point: %w", err)
		}
		return map[string]any{
			"kty": "EC",
			"crv": "P-256",
			"x":   base64.RawURLEncoding.EncodeToString(x),
			"y":   base64.RawURLEncoding.EncodeToString(y),
		}, nil
	default:
		return nil, fmt.Errorf("cnf COSE_Key kty=%d crv=%d is neither OKP/Ed25519 nor EC2/P-256", kty, crv)
	}
}

// checkCOSEAlg accepts an absent alg (authnz-rs omits it on agent keys) or
// exactly the one algorithm the key type signs with.
func checkCOSEAlg(params map[int64]any, want int64) error {
	raw, present := params[coseKeyLabelAlg]
	if !present {
		return nil
	}
	if alg, ok := coseInt(raw); ok && alg == want {
		return nil
	}
	return fmt.Errorf("cnf COSE_Key alg %v does not match its key type (want %d)", raw, want)
}
