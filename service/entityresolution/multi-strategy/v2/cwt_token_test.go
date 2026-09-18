package multistrategy

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/opentdf/platform/service/internal/cwttest"
)

// The multi-strategy resolver maps JWT claims onto strategies, and the KAS
// rewrap path hands it the raw bearer — a CWT on a CWT deployment. Parsing
// JOSE only made every such request fail before any strategy ran.
func Test_CWTBearerParsesIntoClaims(t *testing.T) {
	cwt := cwttest.SignEphemeral(t, "https://identity.arkavo.net", "did:key:zSub", map[any]any{
		"azp":                "opentdf-sdk",
		"preferred_username": "sample-user",
	})

	ers := &ERSV2{}
	claims, err := ers.parseJWTClaims(t.Context(), cwt)
	require.NoError(t, err)

	assert.Equal(t, "did:key:zSub", claims["sub"])
	assert.Equal(t, "https://identity.arkavo.net", claims["iss"])
	assert.Equal(t, "sample-user", claims["preferred_username"])
}
