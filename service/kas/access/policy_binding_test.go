package access

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"testing"

	"connectrpc.com/connect"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// specBinding is the spec-compliant Base64(HMAC) policy binding.
func specBinding(mac []byte) string {
	return base64.StdEncoding.EncodeToString(mac)
}

// flipped returns a copy of mac with its first byte inverted: a well-formed
// HMAC of the right length that does not match the policy.
func flipped(mac []byte) []byte {
	out := bytes.Clone(mac)
	out[0] ^= 0xff
	return out
}

// verifyRewrapRequests accepts exactly two binding encodings -- the spec's
// Base64(HMAC) and the legacy Base64(hex(HMAC)) -- and releases the DEK only
// when the HMAC matches. Everything else, including near-misses in length or
// alphabet, is refused with the same generic 400 and no key.
func TestVerifyRewrapRequests_PolicyBindingEncodings(t *testing.T) {
	const kaoID = "kao-1"
	for _, tt := range []struct {
		name    string
		encode  func(mac []byte) string
		wantLen int // expected length of the binding hash; 0 to skip
		release bool
	}{
		{name: "spec Base64(HMAC)", encode: specBinding, wantLen: 44, release: true},
		{name: "legacy Base64(hex(HMAC))", encode: legacyHexBinding, wantLen: 88, release: true},

		{name: "spec form, wrong HMAC", encode: func(mac []byte) string { return specBinding(flipped(mac)) }, wantLen: 44},
		{name: "legacy form, wrong HMAC", encode: func(mac []byte) string { return legacyHexBinding(flipped(mac)) }, wantLen: 88},

		{name: "raw HMAC truncated to 31 bytes", encode: func(mac []byte) string { return specBinding(mac[:sha256.Size-1]) }},
		{name: "raw HMAC with a trailing byte", encode: func(mac []byte) string { return specBinding(append(bytes.Clone(mac), 0)) }},
		{name: "odd-length hex (63 chars)", encode: func(mac []byte) string {
			return base64.StdEncoding.EncodeToString([]byte(hex.EncodeToString(mac)[:hex.EncodedLen(sha256.Size)-1]))
		}},
		{name: "hex of a truncated HMAC (62 chars)", encode: func(mac []byte) string { return legacyHexBinding(mac[:sha256.Size-1]) }},
		{name: "64 bytes that are not hex", encode: func([]byte) string {
			return base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{'z'}, hex.EncodedLen(sha256.Size)))
		}},
		{name: "hex of the HMAC, not base64 wrapped", encode: hex.EncodeToString},
		{name: "unpadded base64 of the HMAC", encode: base64.RawStdEncoding.EncodeToString},
		{name: "invalid base64", encode: func([]byte) string { return "not!valid!base64" }},
		{name: "empty hash", encode: func([]byte) string { return "" }},
	} {
		t.Run(tt.name, func(t *testing.T) {
			p, _, _ := releasingProvider(t)
			req := requestWithBinding(t, policyBytes(t, &Policy{UUID: uuid.New()}), "policy-1", tt.encode, kaoID)
			if tt.wantLen != 0 {
				require.Len(t, req.GetKeyAccessObjects()[0].GetKeyAccessObject().GetPolicyBinding().GetHash(), tt.wantLen)
			}

			_, results, err := p.verifyRewrapRequests(t.Context(), req)
			require.Contains(t, results, kaoID)
			r := results[kaoID]

			if tt.release {
				require.NoError(t, err)
				require.NoError(t, r.Error)
				assert.NotNil(t, r.DEK, "a matching binding releases the DEK")
				return
			}
			require.ErrorIs(t, err, errNoValidKeyAccessObjects)
			require.Error(t, r.Error)
			assert.Equal(t, connect.CodeInvalidArgument, connect.CodeOf(r.Error))
			assert.Contains(t, r.Error.Error(), "bad request")
			assert.Nil(t, r.DEK, "a refused binding releases no key")
		})
	}
}
