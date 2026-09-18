package keycloak

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/opentdf/platform/protocol/go/entity"
	entityresolutionV2 "github.com/opentdf/platform/protocol/go/entityresolution/v2"
	"github.com/opentdf/platform/service/internal/cwttest"
	"github.com/opentdf/platform/service/logger"
)

// The KAS rewrap path forwards the raw bearer, which on a CWT deployment is a
// COSE_Sign1 CWT rather than a JOSE JWT. This provider parsed JOSE only, so
// every rewrap of a policy carrying data attributes failed — the same bug
// fixed for the patreon and arkavo resolvers in #38.
func Test_CWTBearerYieldsClientAndUsernameEntities(t *testing.T) {
	cwt := cwttest.SignEphemeral(t, "https://identity.arkavo.net", "e6eb4ae5-8c05", map[any]any{
		"azp":                "opentdf-sdk",
		"preferred_username": "sample-user",
	})

	resp, err := CreateEntityChainsFromTokens(t.Context(),
		&entityresolutionV2.CreateEntityChainsFromTokensRequest{
			Tokens: []*entity.Token{{EphemeralId: "t0", Jwt: cwt}},
		}, Config{}, nil, logger.CreateTestLogger(), nil)
	require.NoError(t, err)

	require.Len(t, resp.GetEntityChains(), 1)
	ents := resp.GetEntityChains()[0].GetEntities()
	require.Len(t, ents, 2)
	assert.Equal(t, "opentdf-sdk", ents[0].GetClientId())
	assert.Equal(t, entity.Entity_CATEGORY_ENVIRONMENT, ents[0].GetCategory())
	assert.Equal(t, "sample-user", ents[1].GetUserName())
	assert.Equal(t, entity.Entity_CATEGORY_SUBJECT, ents[1].GetCategory())
}
