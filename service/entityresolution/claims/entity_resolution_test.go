package claims_test

import (
	"testing"

	"github.com/opentdf/platform/protocol/go/authorization"
	"github.com/opentdf/platform/protocol/go/entityresolution"
	claims "github.com/opentdf/platform/service/entityresolution/claims"
	"github.com/opentdf/platform/service/internal/chaindevice"
	"github.com/opentdf/platform/service/logger"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/types/known/anypb"
	"google.golang.org/protobuf/types/known/structpb"
)

const samplejwt = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6ImhlbGxvd29ybGQiLCJpYXQiOjE1MTYyMzkwMjJ9.EAOittOMzKENEAs44eaMuZe-xas7VNVsgBxhwmxYiIw"

func Test_ClientResolveEntity(t *testing.T) {
	var validBody []*authorization.Entity
	validBody = append(validBody, &authorization.Entity{Id: "1234", EntityType: &authorization.Entity_ClientId{ClientId: "random"}})

	req := entityresolution.ResolveEntitiesRequest{}
	req.Entities = validBody

	resp, reserr := claims.EntityResolution(t.Context(), &req, logger.CreateTestLogger())

	require.NoError(t, reserr)

	entityRepresentations := resp.GetEntityRepresentations()
	assert.NotNil(t, entityRepresentations)
	assert.Len(t, entityRepresentations, 1)

	assert.Equal(t, "1234", entityRepresentations[0].GetOriginalId())
	assert.Len(t, entityRepresentations[0].GetAdditionalProps(), 1)
	propMap := entityRepresentations[0].GetAdditionalProps()[0].AsMap()
	assert.Equal(t, "random", propMap["clientId"])
	assert.Equal(t, "1234", propMap["id"])
}

func Test_EmailResolveEntity(t *testing.T) {
	var validBody []*authorization.Entity
	validBody = append(validBody, &authorization.Entity{Id: "1234", EntityType: &authorization.Entity_EmailAddress{EmailAddress: "random"}})

	req := entityresolution.ResolveEntitiesRequest{}
	req.Entities = validBody

	resp, reserr := claims.EntityResolution(t.Context(), &req, logger.CreateTestLogger())

	require.NoError(t, reserr)

	entityRepresentations := resp.GetEntityRepresentations()
	assert.NotNil(t, entityRepresentations)
	assert.Len(t, entityRepresentations, 1)

	assert.Equal(t, "1234", entityRepresentations[0].GetOriginalId())
	assert.Len(t, entityRepresentations[0].GetAdditionalProps(), 1)
	propMap := entityRepresentations[0].GetAdditionalProps()[0].AsMap()
	assert.Equal(t, "random", propMap["emailAddress"])
	assert.Equal(t, "1234", propMap["id"])
}

func Test_ClaimsResolveEntity(t *testing.T) {
	customclaims := map[string]interface{}{
		"foo": "bar",
		"baz": 42,
	}
	// Convert map[string]interface{} to *structpb.Struct
	structClaims, err := structpb.NewStruct(customclaims)
	require.NoError(t, err)

	// Wrap the struct in an *anypb.Any
	anyClaims, err := anypb.New(structClaims)
	require.NoError(t, err)

	var validBody []*authorization.Entity
	validBody = append(validBody, &authorization.Entity{Id: "1234", EntityType: &authorization.Entity_Claims{Claims: anyClaims}})

	req := entityresolution.ResolveEntitiesRequest{}
	req.Entities = validBody

	resp, reserr := claims.EntityResolution(t.Context(), &req, logger.CreateTestLogger())

	require.NoError(t, reserr)

	entityRepresentations := resp.GetEntityRepresentations()
	assert.NotNil(t, entityRepresentations)
	assert.Len(t, entityRepresentations, 1)

	assert.Equal(t, "1234", entityRepresentations[0].GetOriginalId())
	assert.Len(t, entityRepresentations[0].GetAdditionalProps(), 1)
	propMap := entityRepresentations[0].GetAdditionalProps()[0].AsMap()
	assert.Equal(t, "bar", propMap["foo"])
	assert.EqualValues(t, 42, propMap["baz"])
}

func Test_JWTToEntityChainClaims(t *testing.T) {
	validBody := []*authorization.Token{{Jwt: samplejwt}}

	resp, reserr := claims.CreateEntityChainFromJwt(t.Context(), &entityresolution.CreateEntityChainFromJwtRequest{Tokens: validBody}, logger.CreateTestLogger())

	require.NoError(t, reserr)

	assert.Len(t, resp.GetEntityChains(), 1)
	assert.Len(t, resp.GetEntityChains()[0].GetEntities(), 1)
	assert.IsType(t, &authorization.Entity_Claims{}, resp.GetEntityChains()[0].GetEntities()[0].GetEntityType())
	assert.Equal(t, authorization.Entity_CATEGORY_SUBJECT, resp.GetEntityChains()[0].GetEntities()[0].GetCategory())

	var unpackedStruct structpb.Struct
	err := resp.GetEntityChains()[0].GetEntities()[0].GetClaims().UnmarshalTo(&unpackedStruct)
	require.NoError(t, err)

	// Convert structpb.Struct to map[string]interface{}
	claimsMap := unpackedStruct.AsMap()

	assert.Equal(t, "helloworld", claimsMap["name"])
	// Standard registered claims like "sub" must be included for subject mapping selectors
	assert.Equal(t, "1234567890", claimsMap["sub"])
	// Time-based claims (iat, exp, nbf) are excluded — structpb cannot serialize time.Time
	assert.NotContains(t, claimsMap, "iat")
}

// Only the composite resolver writes a device marker. The claims resolver
// copies the caller's claims into the representation, so it drops the
// marker's key, and the device token's.
func Test_ClaimsResolveEntity_DropsDeviceMarker(t *testing.T) {
	structClaims, err := structpb.NewStruct(map[string]any{
		"sub":                  "forger",
		chaindevice.PropKey:    map[string]any{"kind": "device", "class": "attested", "verified": true, "bound": true},
		chaindevice.TokenClaim: "a-device-token",
	})
	require.NoError(t, err)
	anyClaims, err := anypb.New(structClaims)
	require.NoError(t, err)
	req := entityresolution.ResolveEntitiesRequest{Entities: []*authorization.Entity{
		{Id: "1234", EntityType: &authorization.Entity_Claims{Claims: anyClaims}},
	}}

	resp, err := claims.EntityResolution(t.Context(), &req, logger.CreateTestLogger())

	require.NoError(t, err)
	reps := resp.GetEntityRepresentations()
	require.Len(t, reps, 1)
	require.Len(t, reps[0].GetAdditionalProps(), 1)
	props := reps[0].GetAdditionalProps()[0].AsMap()
	assert.NotContains(t, props, chaindevice.PropKey)
	assert.NotContains(t, props, chaindevice.TokenClaim)
	assert.Equal(t, "forger", props["sub"], "the other claims stay")
}
