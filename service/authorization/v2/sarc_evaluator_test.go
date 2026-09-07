package authorization

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/opentdf/platform/protocol/go/policy"
	"github.com/opentdf/platform/service/logger"
	"github.com/opentdf/platform/service/pkg/authz"
)

// stubStore serves a fixed set of registered resources.
type stubStore struct {
	resources []*policy.RegisteredResource
	calls     int
}

func (s *stubStore) ListAllAttributes(context.Context) ([]*policy.Attribute, error) { return nil, nil }

func (s *stubStore) ListAllSubjectMappings(context.Context) ([]*policy.SubjectMapping, error) {
	return nil, nil
}

func (s *stubStore) ListAllRegisteredResources(context.Context) ([]*policy.RegisteredResource, error) {
	s.calls++
	return s.resources, nil
}

func (s *stubStore) ListAllObligations(context.Context) ([]*policy.Obligation, error) {
	return nil, nil
}

func (s *stubStore) IsEnabled() bool              { return true }
func (s *stubStore) IsReady(context.Context) bool { return true }

func TestEntityIdentifierPrefersToken(t *testing.T) {
	id, err := entityIdentifier(authz.Subject{ID: "alice", TokenRaw: "raw.token.value"})
	require.NoError(t, err)
	require.Equal(t, "raw.token.value", id.GetToken().GetJwt())
}

func TestEntityIdentifierFromNamedSubject(t *testing.T) {
	user, err := entityIdentifier(authz.Subject{ID: "alice", Type: authz.SubjectTypeUser})
	require.NoError(t, err)
	require.Equal(t, "alice", user.GetEntityChain().GetEntities()[0].GetUserName())

	email, err := entityIdentifier(authz.Subject{ID: "alice@example.com", Type: authz.SubjectTypeUser})
	require.NoError(t, err)
	require.Equal(t, "alice@example.com", email.GetEntityChain().GetEntities()[0].GetEmailAddress())

	client, err := entityIdentifier(authz.Subject{ID: "otdfctl", Type: authz.SubjectTypeClient})
	require.NoError(t, err)
	require.Equal(t, "otdfctl", client.GetEntityChain().GetEntities()[0].GetClientId())

	_, err = entityIdentifier(authz.Subject{})
	require.ErrorIs(t, err, ErrNoSubject)
}

func TestPolicyResourceMapping(t *testing.T) {
	svc := &Service{logger: logger.CreateTestLogger()}

	values, err := svc.policyResource(context.Background(), authz.Resource{
		Type:               authz.ResourceTypeAttributeValues,
		ID:                 "tdf-1",
		AttributeValueFQNs: []string{"https://example.com/attr/classification/value/secret"},
	})
	require.NoError(t, err)
	require.Equal(t, []string{"https://example.com/attr/classification/value/secret"},
		values.GetAttributeValues().GetFqns())

	// A resource policy cannot address is not an error; the caller falls
	// back to the platform grant table.
	none, err := svc.policyResource(context.Background(), authz.Resource{Type: authz.ResourceTypeEndpoint, ID: "x"})
	require.NoError(t, err)
	require.Nil(t, none)
}

func TestRegisteredResourceIndexAbstainsForUnknownEndpoints(t *testing.T) {
	const known = "https://platform.example.com/reg_res/endpoint/value/policy_attributes_attributeservice_createattribute"

	store := &stubStore{resources: []*policy.RegisteredResource{{
		Name: "endpoint",
		Values: []*policy.RegisteredResourceValue{
			{Value: "policy_attributes_attributeservice_createattribute", Fqn: known},
		},
	}}}
	svc := &Service{logger: logger.CreateTestLogger(), cache: store}
	ctx := context.Background()

	resource, err := svc.policyResource(ctx, authz.Resource{Type: authz.ResourceTypeEndpoint, ID: "create", FQN: known})
	require.NoError(t, err)
	require.NotNil(t, resource)
	require.Equal(t, known, resource.GetRegisteredResourceValueFqn())

	unknown, err := svc.policyResource(ctx, authz.Resource{
		Type: authz.ResourceTypeEndpoint,
		ID:   "list",
		FQN:  "https://platform.example.com/reg_res/endpoint/value/policy_attributes_attributeservice_listattributes",
	})
	require.NoError(t, err)
	require.Nil(t, unknown)

	// The index is cached, so repeated decisions do not re-list policy.
	require.Equal(t, 1, store.calls)
}

func TestEvaluateAbstainsWithoutPolicyResource(t *testing.T) {
	svc := &Service{logger: logger.CreateTestLogger()}
	decision, err := svc.Evaluate(context.Background(), authz.DecisionRequest{
		Subject:  authz.Subject{ID: "alice"},
		Action:   authz.Action{Name: "read"},
		Resource: authz.Resource{Type: authz.ResourceTypeEndpoint, ID: "policy.attributes.List"},
	})
	require.NoError(t, err)
	require.Equal(t, authz.EffectAbstain, decision.Effect)
}

func TestEvaluateAbstainsWithoutSubject(t *testing.T) {
	svc := &Service{logger: logger.CreateTestLogger()}
	decision, err := svc.Evaluate(context.Background(), authz.DecisionRequest{
		Action: authz.Action{Name: "read"},
		Resource: authz.Resource{
			Type:               authz.ResourceTypeAttributeValues,
			AttributeValueFQNs: []string{"https://example.com/attr/classification/value/secret"},
		},
	})
	require.NoError(t, err)
	require.Equal(t, authz.EffectAbstain, decision.Effect)
}

func TestRequestContextNamesThePEP(t *testing.T) {
	reqCtx := requestContextFor(authz.DecisionRequest{
		Subject: authz.Subject{ClientID: "otdfctl"},
	})
	require.Equal(t, "otdfctl", reqCtx.GetPep().GetClientId())

	fallback := requestContextFor(authz.DecisionRequest{
		Context: authz.RequestContext{Transport: authz.TransportConnect},
	})
	require.Equal(t, authz.TransportConnect, fallback.GetPep().GetClientId())
}
