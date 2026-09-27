package auth

import (
	"encoding/json"
	"os"
	"testing"
	"time"

	"github.com/lestrrat-go/jwx/v2/jwk"
	"github.com/lestrrat-go/jwx/v2/jwt"
	"github.com/stretchr/testify/require"
)

type opentdfRsVectorFile struct {
	Provenance map[string]any `json:"provenance"`
	Vectors    []struct {
		Name               string          `json:"name"`
		Alg                string          `json:"alg"`
		PublicJWK          json.RawMessage `json:"public_jwk"`
		AccessToken        string          `json:"access_token"`
		HTU                string          `json:"htu"`
		DPoP               string          `json:"dpop"`
		SignedRequestToken string          `json:"signed_request_token"`
	} `json:"vectors"`
}

// coseBoundAccessToken builds the jwt.Token the CWT verifier produces for an
// agent CWT whose cnf holds pub as a COSE_Key: the COSE map goes through the
// same cnfClaim rendering and the same claimsToJWTToken.
func coseBoundAccessToken(t *testing.T, pub jwk.Key) jwt.Token {
	t.Helper()
	var coseKey map[any]any
	switch k := pub.(type) {
	case jwk.OKPPublicKey:
		coseKey = map[any]any{1: 1, -1: 6, -2: k.X()}
	case jwk.ECDSAPublicKey:
		coseKey = map[any]any{1: 2, -1: 1, -2: k.X(), -3: k.Y()}
	default:
		t.Fatalf("unexpected vector key type %T", pub)
	}
	tok, err := claimsToJWTToken(map[string]any{
		"sub": "did:key:z6Mkvector",
		"cnf": cnfClaim(decoded(t, map[any]any{1: coseKey})),
	})
	require.NoError(t, err)
	return tok
}

// TestOpentdfRsVectors_COSEBoundPath runs opentdf-rs's recorded caller-key
// proofs and SRTs (see testdata provenance) through the agent path.
func TestOpentdfRsVectors_COSEBoundPath(t *testing.T) {
	raw, err := os.ReadFile("testdata/opentdf_rs_dpop_vectors.json")
	require.NoError(t, err)
	var file opentdfRsVectorFile
	require.NoError(t, json.Unmarshal(raw, &file))
	require.NotEmpty(t, file.Provenance["opentdf_platform_commit"], "fixture must name the fork commit it was verified against")
	require.Len(t, file.Vectors, 2)

	for _, v := range file.Vectors {
		t.Run(v.Name, func(t *testing.T) {
			require.Equal(t, rewrapProcedure, v.HTU)
			pub, err := jwk.ParseKey(v.PublicJWK)
			require.NoError(t, err)
			access := coseBoundAccessToken(t, pub)
			// The vectors carry a fixed past iat, so only the past-freshness
			// window is widened; every other check is the production one.
			a := Authentication{
				oidcConfiguration: AuthNConfig{DPoPSkew: 100 * 365 * 24 * time.Hour, TokenSkew: time.Minute},
				dpopReplay:        newDPoPReplayCache(time.Now),
			}

			key, keyBound, err := a.validateDPoP(access, v.AccessToken, rewrapReceiver(), []string{v.DPoP})
			require.NoError(t, err)
			require.True(t, keyBound, "vector must be verified through the key-bound cnf.jwk path")

			_, _, err = a.validateDPoP(access, v.AccessToken, rewrapReceiver(), []string{v.DPoP})
			require.ErrorContains(t, err, "already been used")

			_, _, err = (Authentication{
				oidcConfiguration: a.oidcConfiguration,
				dpopReplay:        newDPoPReplayCache(time.Now),
			}).validateDPoP(access, v.AccessToken+"-other", rewrapReceiver(), []string{v.DPoP})
			require.ErrorContains(t, err, "ath")

			alg, err := SignatureAlgorithmForKey(key)
			require.NoError(t, err)
			require.Equal(t, v.Alg, alg.String())
			_, err = jwt.Parse([]byte(v.SignedRequestToken), jwt.WithKey(alg, key), jwt.WithValidate(false))
			require.NoError(t, err)
		})
	}
}
