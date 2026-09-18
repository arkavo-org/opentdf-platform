package claims

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/types/known/structpb"

	"github.com/opentdf/platform/protocol/go/entity"
	entityresolutionV2 "github.com/opentdf/platform/protocol/go/entityresolution/v2"
	"github.com/opentdf/platform/service/internal/cwttest"
	"github.com/opentdf/platform/service/logger"
)

// A CWT bearer must produce the same claims entity a JOSE bearer does, with
// the registered claims present so subject-mapping selectors like .sub keep
// working regardless of wire format.
func Test_CWTBearerYieldsClaimsEntity(t *testing.T) {
	cwt := cwttest.SignEphemeral(t, "https://identity.arkavo.net", "did:key:zSub", map[any]any{
		"azp":                 "opentdf-sdk",
		"arkavo_entitlements": []any{"https://arkavo.ai/attr/tdf/value/decrypt"},
	})

	resp, err := CreateEntityChainsFromTokens(t.Context(),
		&entityresolutionV2.CreateEntityChainsFromTokensRequest{
			Tokens: []*entity.Token{{EphemeralId: "t0", Jwt: cwt}},
		}, logger.CreateTestLogger())
	require.NoError(t, err)

	require.Len(t, resp.GetEntityChains(), 1)
	ents := resp.GetEntityChains()[0].GetEntities()
	require.Len(t, ents, 1)

	var st structpb.Struct
	require.NoError(t, ents[0].GetClaims().UnmarshalTo(&st))
	m := st.AsMap()
	assert.Equal(t, "did:key:zSub", m["sub"], "registered claims must survive for .sub selectors")
	assert.Equal(t, "https://identity.arkavo.net", m["iss"])
	assert.Equal(t, "opentdf-sdk", m["azp"])
}
