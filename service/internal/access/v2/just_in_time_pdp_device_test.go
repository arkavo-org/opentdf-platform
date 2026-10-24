package access

import (
	"context"
	"errors"
	"strings"
	"testing"

	authzV2 "github.com/opentdf/platform/protocol/go/authorization/v2"
	"github.com/opentdf/platform/protocol/go/entity"
	entityresolutionV2 "github.com/opentdf/platform/protocol/go/entityresolution/v2"
	"github.com/opentdf/platform/protocol/go/policy"
	otdfSDK "github.com/opentdf/platform/sdk"
	ent "github.com/opentdf/platform/service/entity"
	"github.com/opentdf/platform/service/internal/chaindevice"
	"github.com/opentdf/platform/service/logger"
	"github.com/opentdf/platform/service/logger/audit"
	"github.com/opentdf/platform/service/policy/actions"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/types/known/anypb"
	"google.golang.org/protobuf/types/known/structpb"
)

// stubERS answers every ResolveEntities call with fixed representations and
// records the entities it was asked about.
type stubERS struct {
	reps []*entityresolutionV2.EntityRepresentation
	seen [][]*entity.Entity
}

func (e *stubERS) ResolveEntities(_ context.Context, req *entityresolutionV2.ResolveEntitiesRequest) (*entityresolutionV2.ResolveEntitiesResponse, error) {
	e.seen = append(e.seen, req.GetEntities())
	return &entityresolutionV2.ResolveEntitiesResponse{EntityRepresentations: e.reps}, nil
}

func (e *stubERS) CreateEntityChainsFromTokens(context.Context, *entityresolutionV2.CreateEntityChainsFromTokensRequest) (*entityresolutionV2.CreateEntityChainsFromTokensResponse, error) {
	return nil, errors.New("stubERS: CreateEntityChainsFromTokens is not used")
}

func claimsEntityOf(t *testing.T, id string, category entity.Entity_Category) *entity.Entity {
	t.Helper()
	st, err := structpb.NewStruct(map[string]any{"sub": id})
	require.NoError(t, err)
	packed, err := anypb.New(st)
	require.NoError(t, err)
	return &entity.Entity{
		EntityType:  &entity.Entity_Claims{Claims: packed},
		EphemeralId: id,
		Category:    category,
	}
}

// repOf is a representation of the entity id: a role under properties, and a
// device marker next to it when marker is not nil (a Device, or any value to
// test a malformed marker).
func repOf(t *testing.T, id string, marker any) *entityresolutionV2.EntityRepresentation {
	t.Helper()
	fields := map[string]any{"properties": map[string]any{"role": "creator"}}
	switch m := marker.(type) {
	case nil:
	case chaindevice.Device:
		fields[chaindevice.PropKey] = m.Props()
	default:
		fields[chaindevice.PropKey] = m
	}
	st, err := structpb.NewStruct(fields)
	require.NoError(t, err)
	return &entityresolutionV2.EntityRepresentation{OriginalId: id, AdditionalProps: []*structpb.Struct{st}}
}

func chainOf(entities ...*entity.Entity) *entity.EntityChain {
	return &entity.EntityChain{EphemeralId: "chain", Entities: entities}
}

func jitWith(ers *stubERS) *JustInTimePDP {
	return &JustInTimePDP{
		logger: logger.CreateTestLogger(),
		sdk:    &otdfSDK.SDK{EntityResolutionV2: ers},
	}
}

func repIDs(reps []*entityresolutionV2.EntityRepresentation) []string {
	ids := make([]string, 0, len(reps))
	for _, r := range reps {
		ids = append(ids, r.GetOriginalId())
	}
	return ids
}

func TestResolveChain_PartitionsDevices(t *testing.T) {
	bound := chaindevice.Device{Class: chaindevice.ClassAttested, Verified: true, Bound: true, AppEnv: chaindevice.EnvProduction}
	unverified := chaindevice.Device{Class: chaindevice.ClassUnverified}

	person := func(t *testing.T) *entity.Entity { return claimsEntityOf(t, "person", entity.Entity_CATEGORY_SUBJECT) }
	device := func(t *testing.T) *entity.Entity {
		return claimsEntityOf(t, "device", entity.Entity_CATEGORY_ENVIRONMENT)
	}

	tests := []struct {
		name         string
		entities     func(t *testing.T) []*entity.Entity
		reps         func(t *testing.T) []*entityresolutionV2.EntityRepresentation
		wantSubjects []string
		wantDevices  []chaindevice.Device
	}{
		{
			name:     "a subject with no marker is a subject only",
			entities: func(t *testing.T) []*entity.Entity { return []*entity.Entity{person(t)} },
			reps: func(t *testing.T) []*entityresolutionV2.EntityRepresentation {
				return []*entityresolutionV2.EntityRepresentation{repOf(t, "person", nil)}
			},
			wantSubjects: []string{"person"},
		},
		{
			name:     "a subject with a bound marker is a subject and a device",
			entities: func(t *testing.T) []*entity.Entity { return []*entity.Entity{person(t)} },
			reps: func(t *testing.T) []*entityresolutionV2.EntityRepresentation {
				return []*entityresolutionV2.EntityRepresentation{repOf(t, "person", bound)}
			},
			wantSubjects: []string{"person"},
			wantDevices:  []chaindevice.Device{bound},
		},
		{
			name:     "an environment entity with a marker is a device only",
			entities: func(t *testing.T) []*entity.Entity { return []*entity.Entity{person(t), device(t)} },
			reps: func(t *testing.T) []*entityresolutionV2.EntityRepresentation {
				return []*entityresolutionV2.EntityRepresentation{repOf(t, "person", nil), repOf(t, "device", bound)}
			},
			wantSubjects: []string{"person"},
			wantDevices:  []chaindevice.Device{bound},
		},
		{
			name:     "an environment entity without a marker is skipped",
			entities: func(t *testing.T) []*entity.Entity { return []*entity.Entity{person(t), device(t)} },
			reps: func(t *testing.T) []*entityresolutionV2.EntityRepresentation {
				return []*entityresolutionV2.EntityRepresentation{repOf(t, "person", nil), repOf(t, "device", nil)}
			},
			wantSubjects: []string{"person"},
		},
		{
			name:     "a malformed marker on an environment entity is an unbound device, never nothing",
			entities: func(t *testing.T) []*entity.Entity { return []*entity.Entity{person(t), device(t)} },
			reps: func(t *testing.T) []*entityresolutionV2.EntityRepresentation {
				return []*entityresolutionV2.EntityRepresentation{repOf(t, "person", nil), repOf(t, "device", "garbage")}
			},
			wantSubjects: []string{"person"},
			wantDevices:  []chaindevice.Device{unverified},
		},
		{
			name:     "several devices all count",
			entities: func(t *testing.T) []*entity.Entity { return []*entity.Entity{person(t), device(t)} },
			reps: func(t *testing.T) []*entityresolutionV2.EntityRepresentation {
				return []*entityresolutionV2.EntityRepresentation{repOf(t, "person", bound), repOf(t, "device", unverified)}
			},
			wantSubjects: []string{"person"},
			wantDevices:  []chaindevice.Device{bound, unverified},
		},
		{
			name:     "a representation that names no entity of the chain is a subject",
			entities: func(t *testing.T) []*entity.Entity { return []*entity.Entity{person(t)} },
			reps: func(t *testing.T) []*entityresolutionV2.EntityRepresentation {
				return []*entityresolutionV2.EntityRepresentation{repOf(t, "person", nil), repOf(t, "stranger", nil)}
			},
			wantSubjects: []string{"person", "stranger"},
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			ers := &stubERS{reps: tc.reps(t)}
			resolved, err := jitWith(ers).resolveEntitiesFromEntityChain(t.Context(), chainOf(tc.entities(t)...))
			require.NoError(t, err)
			assert.Equal(t, tc.wantSubjects, repIDs(resolved.subjects))
			assert.Equal(t, tc.wantDevices, resolved.devices)
		})
	}

	t.Run("an environment entity that is no claims entity never reaches the ERS", func(t *testing.T) {
		client := &entity.Entity{
			EntityType:  &entity.Entity_ClientId{ClientId: "tdf-client"},
			EphemeralId: "client",
			Category:    entity.Entity_CATEGORY_ENVIRONMENT,
		}
		ers := &stubERS{reps: []*entityresolutionV2.EntityRepresentation{repOf(t, "person", nil), repOf(t, "device", bound)}}
		resolved, err := jitWith(ers).resolveEntitiesFromEntityChain(t.Context(), chainOf(person(t), client, device(t)))
		require.NoError(t, err)
		require.Len(t, ers.seen, 1)
		sent := make([]string, 0, len(ers.seen[0]))
		for _, e := range ers.seen[0] {
			sent = append(sent, e.GetEphemeralId())
		}
		assert.Equal(t, []string{"person", "device"}, sent, "the claims device is resolved; the client ID is not")
		assert.Equal(t, []chaindevice.Device{bound}, resolved.devices)
	})

	// The ERS binds a device to the subjects it is sent, so the PDP must not
	// partition the chain otherwise: an ID that a subject and an environment
	// entity share, whether explicit or index-derived as the ERS names an
	// entity with none, is refused before the ERS is asked, and so are two
	// representations with one ID.
	t.Run("an ID a subject and an environment entity share is an error", func(t *testing.T) {
		for name, entities := range map[string]func(t *testing.T) []*entity.Entity{
			"explicit IDs": func(t *testing.T) []*entity.Entity {
				return []*entity.Entity{person(t), device(t), claimsEntityOf(t, "person", entity.Entity_CATEGORY_ENVIRONMENT)}
			},
			"an explicit ID equals an index-derived one": func(t *testing.T) []*entity.Entity {
				idless := claimsEntityOf(t, "", entity.Entity_CATEGORY_ENVIRONMENT)
				return []*entity.Entity{claimsEntityOf(t, ent.EntityIDPrefix+"1", entity.Entity_CATEGORY_SUBJECT), idless}
			},
		} {
			t.Run(name, func(t *testing.T) {
				ers := &stubERS{reps: []*entityresolutionV2.EntityRepresentation{repOf(t, "person", nil)}}
				_, err := jitWith(ers).resolveEntitiesFromEntityChain(t.Context(), chainOf(entities(t)...))
				require.ErrorContains(t, err, "is used by both a subject and an environment entity")
				assert.Empty(t, ers.seen, "the ERS is never asked")
			})
		}
	})

	t.Run("two representations with one ID are an error", func(t *testing.T) {
		for name, reps := range map[string]func(t *testing.T) []*entityresolutionV2.EntityRepresentation{
			"a subject's": func(t *testing.T) []*entityresolutionV2.EntityRepresentation {
				return []*entityresolutionV2.EntityRepresentation{repOf(t, "person", nil), repOf(t, "person", nil)}
			},
			"a device's": func(t *testing.T) []*entityresolutionV2.EntityRepresentation {
				return []*entityresolutionV2.EntityRepresentation{repOf(t, "person", nil), repOf(t, "device", bound), repOf(t, "device", unverified)}
			},
		} {
			t.Run(name, func(t *testing.T) {
				ers := &stubERS{reps: reps(t)}
				_, err := jitWith(ers).resolveEntitiesFromEntityChain(t.Context(), chainOf(person(t), device(t)))
				require.ErrorContains(t, err, "two entity representations with ID")
			})
		}
	})

	t.Run("distinct explicit and index-derived IDs resolve", func(t *testing.T) {
		idless := claimsEntityOf(t, "", entity.Entity_CATEGORY_ENVIRONMENT)
		ers := &stubERS{reps: []*entityresolutionV2.EntityRepresentation{repOf(t, "person", nil), repOf(t, ent.EntityIDPrefix+"1", bound)}}
		resolved, err := jitWith(ers).resolveEntitiesFromEntityChain(t.Context(), chainOf(person(t), idless))
		require.NoError(t, err)
		assert.Equal(t, []string{"person"}, repIDs(resolved.subjects))
		assert.Equal(t, []chaindevice.Device{bound}, resolved.devices)
	})

	t.Run("a chain of environment entities only is an error", func(t *testing.T) {
		ers := &stubERS{}
		_, err := jitWith(ers).resolveEntitiesFromEntityChain(t.Context(), chainOf(device(t)))
		require.ErrorContains(t, err, "no subject entities")
		assert.Empty(t, ers.seen, "nothing is resolved when nothing could be a subject")
	})

	t.Run("no subject representation back is an error", func(t *testing.T) {
		ers := &stubERS{reps: []*entityresolutionV2.EntityRepresentation{repOf(t, "device", bound)}}
		_, err := jitWith(ers).resolveEntitiesFromEntityChain(t.Context(), chainOf(person(t), device(t)))
		require.ErrorContains(t, err, "no subject entity representations")
	})
}

// publishRule is the policy file's rule used throughout: publish needs an
// attested device.
func publishRule(publishFQN string) *chaindevice.Rules {
	return &chaindevice.Rules{Requirements: []chaindevice.Requirement{{
		Grants:        []string{strings.ToLower(publishFQN)},
		DeviceClasses: []string{chaindevice.ClassAttested},
	}}}
}

func entitlementsOf(fqns ...string) []*authzV2.EntityEntitlements {
	perFQN := make(map[string]*authzV2.EntityEntitlements_ActionsList, len(fqns))
	for _, fqn := range fqns {
		perFQN[fqn] = &authzV2.EntityEntitlements_ActionsList{Actions: []*policy.Action{{Name: actions.ActionNameRead}}}
	}
	return []*authzV2.EntityEntitlements{{EphemeralId: "person", ActionsPerAttributeValueFqn: perFQN}}
}

func TestNarrowEntityEntitlements_Rules(t *testing.T) {
	publishFQN := createAttrValueFQN(testBaseNamespace, "capability", "publish")
	campaignFQN := createAttrValueFQN(testBaseNamespace, "campaign", "13167240")
	attested := chaindevice.Device{Class: chaindevice.ClassAttested, Verified: true, Bound: true}
	unbound := chaindevice.Device{Class: chaindevice.ClassAttested, Verified: true}

	kept := func(all []*authzV2.EntityEntitlements) []string {
		var got []string
		for _, e := range all {
			for fqn := range e.GetActionsPerAttributeValueFqn() {
				got = append(got, fqn)
			}
		}
		return got
	}

	t.Run("no devices: a requirement drops what it names", func(t *testing.T) {
		e := entitlementsOf(publishFQN, campaignFQN)
		narrowEntityEntitlements(e, publishRule(publishFQN), nil)
		assert.Equal(t, []string{campaignFQN}, kept(e))
	})
	t.Run("an attested device keeps both", func(t *testing.T) {
		e := entitlementsOf(publishFQN, campaignFQN)
		narrowEntityEntitlements(e, publishRule(publishFQN), []chaindevice.Device{attested})
		assert.ElementsMatch(t, []string{publishFQN, campaignFQN}, kept(e))
	})
	t.Run("an unbound device drops everything", func(t *testing.T) {
		e := entitlementsOf(publishFQN, campaignFQN)
		narrowEntityEntitlements(e, publishRule(publishFQN), []chaindevice.Device{attested, unbound})
		assert.Empty(t, kept(e))
	})
	t.Run("an unbound device drops everything under nil rules too", func(t *testing.T) {
		e := entitlementsOf(publishFQN, campaignFQN)
		narrowEntityEntitlements(e, nil, []chaindevice.Device{unbound})
		assert.Empty(t, kept(e))
	})
	t.Run("nil rules and no devices change nothing", func(t *testing.T) {
		e := entitlementsOf(publishFQN, campaignFQN)
		narrowEntityEntitlements(e, nil, nil)
		assert.ElementsMatch(t, []string{publishFQN, campaignFQN}, kept(e))
	})
}

// ruleStore is an entitlement policy store that serves subject mappings
// locally and declares device rules, as the file-backed store does.
type ruleStore struct {
	attributes []*policy.Attribute
	mappings   []*policy.SubjectMapping
	rules      *chaindevice.Rules
}

func (s *ruleStore) ListAllAttributes(context.Context) ([]*policy.Attribute, error) {
	return s.attributes, nil
}

func (s *ruleStore) ListAllSubjectMappings(context.Context) ([]*policy.SubjectMapping, error) {
	return s.mappings, nil
}

func (s *ruleStore) ListAllRegisteredResources(context.Context) ([]*policy.RegisteredResource, error) {
	return nil, nil
}

func (s *ruleStore) ListAllObligations(context.Context) ([]*policy.Obligation, error) {
	return nil, nil
}
func (s *ruleStore) IsEnabled() bool                 { return true }
func (s *ruleStore) IsReady(context.Context) bool    { return true }
func (s *ruleStore) DeviceRules() *chaindevice.Rules { return s.rules }

func (s *ruleStore) MatchSubjectMappings(context.Context, []*policy.SubjectProperty) ([]*policy.SubjectMapping, error) {
	return s.mappings, nil
}

// emptyStore is a store with no policy but the rules.
func emptyStore(rules *chaindevice.Rules) *ruleStore {
	return &ruleStore{attributes: []*policy.Attribute{}, mappings: []*policy.SubjectMapping{}, rules: rules}
}

// A store that declares device rules gives them to the JIT PDP; one that does
// not, or declares none, leaves it with none.
func TestNewJustInTimePDP_DetectsDeviceRules(t *testing.T) {
	sdk := &otdfSDK.SDK{EntityResolutionV2: &stubERS{}}
	rules := publishRule(createAttrValueFQN(testBaseNamespace, "capability", "publish"))

	pdp, err := NewJustInTimePDP(t.Context(), logger.CreateTestLogger(), sdk, emptyStore(rules), true, false)
	require.NoError(t, err)
	assert.Same(t, rules, pdp.deviceRules)

	pdp, err = NewJustInTimePDP(t.Context(), logger.CreateTestLogger(), sdk, emptyStore(nil), true, false)
	require.NoError(t, err)
	assert.Nil(t, pdp.deviceRules)

	// A store that is no DeviceRuleSource, whatever else it serves.
	pdp, err = NewJustInTimePDP(t.Context(), logger.CreateTestLogger(), sdk, struct{ EntitlementPolicyStore }{emptyStore(rules)}, true, false)
	require.NoError(t, err)
	assert.Nil(t, pdp.deviceRules)
}

// The rules and the chain's devices reach both routes of the JIT PDP: a
// decision and the entitlements of the same chain narrow alike.
func TestJustInTimePDP_DeviceRulesNarrowBothRoutes(t *testing.T) {
	publishFQN := createAttrValueFQN(testBaseNamespace, "capability", "publish")
	campaignFQN := createAttrValueFQN(testBaseNamespace, "campaign", "13167240")
	attested := chaindevice.Device{Class: chaindevice.ClassAttested, Verified: true, Bound: true, AppEnv: chaindevice.EnvProduction}
	managed := chaindevice.Device{Class: chaindevice.ClassManaged, Verified: true, Bound: true}
	unbound := chaindevice.Device{Class: chaindevice.ClassAttested, Verified: true}

	store := &ruleStore{
		attributes: []*policy.Attribute{
			{
				Fqn:    createAttrFQN(testBaseNamespace, "capability"),
				Rule:   policy.AttributeRuleTypeEnum_ATTRIBUTE_RULE_TYPE_ENUM_ANY_OF,
				Values: []*policy.Value{{Fqn: publishFQN, Value: "publish"}},
			},
			{
				Fqn:    createAttrFQN(testBaseNamespace, "campaign"),
				Rule:   policy.AttributeRuleTypeEnum_ATTRIBUTE_RULE_TYPE_ENUM_ANY_OF,
				Values: []*policy.Value{{Fqn: campaignFQN, Value: "13167240"}},
			},
		},
		mappings: []*policy.SubjectMapping{
			createSimpleSubjectMapping(publishFQN, "publish", []*policy.Action{testActionRead}, ".properties.role", []string{"creator"}, nil),
			createSimpleSubjectMapping(campaignFQN, "13167240", []*policy.Action{testActionRead}, ".properties.role", []string{"creator"}, nil),
		},
		rules: publishRule(publishFQN),
	}
	ers := &stubERS{}
	pdp, err := NewJustInTimePDP(t.Context(), logger.CreateTestLogger(), &otdfSDK.SDK{EntityResolutionV2: ers}, store, false, false)
	require.NoError(t, err)

	chain := func(t *testing.T, devices ...chaindevice.Device) *authzV2.EntityIdentifier {
		t.Helper()
		entities := []*entity.Entity{claimsEntityOf(t, "person", entity.Entity_CATEGORY_SUBJECT)}
		reps := []*entityresolutionV2.EntityRepresentation{repOf(t, "person", nil)}
		for i, d := range devices {
			id := "device-" + string(rune('a'+i))
			entities = append(entities, claimsEntityOf(t, id, entity.Entity_CATEGORY_ENVIRONMENT))
			reps = append(reps, repOf(t, id, d))
		}
		ers.reps = reps
		return &authzV2.EntityIdentifier{Identifier: &authzV2.EntityIdentifier_EntityChain{EntityChain: chainOf(entities...)}}
	}
	permitted := func(t *testing.T, id *authzV2.EntityIdentifier, fqn string) bool {
		t.Helper()
		ctx := audit.ContextWithActorID(t.Context(), "pep")
		decision, err := pdp.GetDecision(ctx, id, testActionRead, createResourcePerFqn(fqn), nil, nil)
		require.NoError(t, err)
		return decision.AllPermitted
	}
	entitled := func(t *testing.T, id *authzV2.EntityIdentifier) []string {
		t.Helper()
		got, err := pdp.GetEntitlements(t.Context(), id, false)
		require.NoError(t, err)
		require.Len(t, got, 1, "only the person is a subject")
		var fqns []string
		for fqn := range got[0].GetActionsPerAttributeValueFqn() {
			fqns = append(fqns, fqn)
		}
		return fqns
	}

	t.Run("no device: the requirement holds without one", func(t *testing.T) {
		id := chain(t)
		assert.False(t, permitted(t, id, publishFQN))
		assert.True(t, permitted(t, id, campaignFQN))
		assert.Equal(t, []string{campaignFQN}, entitled(t, id))
	})
	t.Run("an attested device keeps publish", func(t *testing.T) {
		id := chain(t, attested)
		assert.True(t, permitted(t, id, publishFQN))
		assert.True(t, permitted(t, id, campaignFQN))
		assert.ElementsMatch(t, []string{publishFQN, campaignFQN}, entitled(t, id))
	})
	t.Run("a managed device does not", func(t *testing.T) {
		id := chain(t, managed)
		assert.False(t, permitted(t, id, publishFQN))
		assert.True(t, permitted(t, id, campaignFQN))
		assert.Equal(t, []string{campaignFQN}, entitled(t, id))
	})
	t.Run("an unbound device denies everything", func(t *testing.T) {
		id := chain(t, attested, unbound)
		assert.False(t, permitted(t, id, publishFQN))
		assert.False(t, permitted(t, id, campaignFQN))
		assert.Empty(t, entitled(t, id))
	})
}
