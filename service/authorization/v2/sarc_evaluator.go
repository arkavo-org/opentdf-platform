package authorization

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"sync"
	"time"

	authzV2 "github.com/opentdf/platform/protocol/go/authorization/v2"
	"github.com/opentdf/platform/protocol/go/entity"
	"github.com/opentdf/platform/protocol/go/policy"
	access "github.com/opentdf/platform/service/internal/access/v2"
	"github.com/opentdf/platform/service/pkg/authz"
)

// This file makes the authorization service reachable as an in-process
// Policy Decision Point.
//
// Platform enforcement points — the Connect interceptor, the HTTP
// middleware, the AuthZEN endpoint — hand it SARC decision requests
// directly. Nothing loops back through the RPC surface to authorize a
// request the process is already serving:
//
//	          ┌── AuthZEN API
//	          │
//	          ▼
//	   Authorization Engine ──► Service.Evaluate ──► JustInTimePDP
//	          ▲
//	          │
//	Connect interceptor

// registeredResourceTTL bounds how long the evaluator reuses its view of
// which registered resource values exist. Endpoints are addressed by FQN,
// and a request for an FQN policy does not define must fall through to the
// platform grant table rather than be denied, so the evaluator needs to
// know what policy actually contains.
const registeredResourceTTL = 30 * time.Second

// ErrNoSubject is returned when a decision request carries nothing that can
// identify an entity to platform policy.
var ErrNoSubject = errors.New("authorization: decision request has no identifiable subject")

// Evaluate answers a SARC decision request from platform policy. It
// abstains — leaving the answer to the caller's other decision sources —
// when the resource is not represented in policy, so enabling
// policy-governed endpoints is incremental: register the endpoints you want
// policy to govern, and the rest keep their platform grants.
func (as *Service) Evaluate(ctx context.Context, req authz.DecisionRequest) (authz.Decision, error) {
	abstain := func(reason string) (authz.Decision, error) {
		return authz.Decision{Effect: authz.EffectAbstain, Source: "policy", Reason: reason}, nil
	}

	resource, err := as.policyResource(ctx, req.Resource)
	if err != nil {
		return authz.Decision{}, err
	}
	if resource == nil {
		return abstain("resource is not represented in policy")
	}

	entityID, err := entityIdentifier(req.Subject)
	if err != nil {
		return abstain(err.Error())
	}

	pdp, err := access.NewJustInTimePDP(ctx, as.logger, as.sdk, as.cache, as.config.AllowDirectEntitlements, as.config.EnforceNamespacedEntitlements)
	if err != nil {
		return authz.Decision{}, errors.Join(ErrFailedToInitPDP, err)
	}

	decision, err := pdp.GetDecision(
		ctx,
		entityID,
		&policy.Action{Name: req.Action.Name},
		[]*authzV2.Resource{resource},
		requestContextFor(req),
		nil,
	)
	if err != nil {
		return authz.Decision{}, errors.Join(ErrFailedToGetDecision, err)
	}
	if decision == nil || len(decision.Results) == 0 {
		return abstain("policy returned no result")
	}

	result := decision.Results[0]
	effect := authz.EffectDeny
	if result.Passed {
		effect = authz.EffectPermit
	}
	return authz.Decision{
		Effect:      effect,
		Source:      "policy",
		Reason:      "evaluated against platform policy",
		Obligations: result.RequiredObligationValueFQNs,
	}, nil
}

// policyResource maps a SARC resource onto the resource shape the PDP
// evaluates. It returns nil when policy has nothing to say about it.
func (as *Service) policyResource(ctx context.Context, r authz.Resource) (*authzV2.Resource, error) {
	if len(r.AttributeValueFQNs) > 0 {
		return &authzV2.Resource{
			EphemeralId: r.ID,
			Resource: &authzV2.Resource_AttributeValues_{
				AttributeValues: &authzV2.Resource_AttributeValues{Fqns: r.AttributeValueFQNs},
			},
		}, nil
	}
	if r.FQN == "" {
		return nil, nil //nolint:nilnil // absence of a policy resource is not an error
	}
	known, err := as.hasRegisteredResourceValue(ctx, r.FQN)
	if err != nil {
		return nil, err
	}
	if !known {
		return nil, nil //nolint:nilnil // the caller falls back to platform grants
	}
	return &authzV2.Resource{
		EphemeralId: r.ID,
		Resource:    &authzV2.Resource_RegisteredResourceValueFqn{RegisteredResourceValueFqn: r.FQN},
	}, nil
}

// entityIdentifier turns a SARC subject into the entity the PDP resolves
// entitlements for. A verified token is preferred: it carries every claim
// entity resolution may need. A subject named without a token — an AuthZEN
// question about somebody else — is identified by username or client ID.
func entityIdentifier(s authz.Subject) (*authzV2.EntityIdentifier, error) {
	if s.TokenRaw != "" {
		return &authzV2.EntityIdentifier{
			Identifier: &authzV2.EntityIdentifier_Token{
				Token: &entity.Token{Jwt: s.TokenRaw},
			},
		}, nil
	}
	if s.ID == "" {
		return nil, ErrNoSubject
	}

	e := &entity.Entity{
		EphemeralId: "sarc-subject",
		Category:    entity.Entity_CATEGORY_SUBJECT,
	}
	switch {
	case s.Type == authz.SubjectTypeClient:
		e.EntityType = &entity.Entity_ClientId{ClientId: s.ID}
	case strings.Contains(s.ID, "@"):
		e.EntityType = &entity.Entity_EmailAddress{EmailAddress: s.ID}
	default:
		e.EntityType = &entity.Entity_UserName{UserName: s.ID}
	}
	return &authzV2.EntityIdentifier{
		Identifier: &authzV2.EntityIdentifier_EntityChain{
			EntityChain: &entity.EntityChain{
				EphemeralId: "sarc-subject-chain",
				Entities:    []*entity.Entity{e},
			},
		},
	}, nil
}

// requestContextFor names the enforcement point that asked, for downstream
// obligation decisioning.
func requestContextFor(req authz.DecisionRequest) *policy.RequestContext {
	clientID := req.Subject.ClientID
	if clientID == "" {
		clientID = req.Context.Transport
	}
	return &policy.RequestContext{
		Pep: &policy.PolicyEnforcementPoint{ClientId: clientID},
	}
}

// registeredResourceIndex is a short-lived view of the registered resource
// value FQNs policy defines.
type registeredResourceIndex struct {
	mu       sync.RWMutex
	fqns     map[string]struct{}
	loadedAt time.Time
}

func (as *Service) hasRegisteredResourceValue(ctx context.Context, fqn string) (bool, error) {
	idx := as.registeredResources()
	idx.mu.RLock()
	fresh := idx.fqns != nil && time.Since(idx.loadedAt) < registeredResourceTTL
	if fresh {
		_, ok := idx.fqns[strings.ToLower(fqn)]
		idx.mu.RUnlock()
		return ok, nil
	}
	idx.mu.RUnlock()

	idx.mu.Lock()
	defer idx.mu.Unlock()
	// Another goroutine may have refreshed while this one waited.
	if idx.fqns != nil && time.Since(idx.loadedAt) < registeredResourceTTL {
		_, ok := idx.fqns[strings.ToLower(fqn)]
		return ok, nil
	}

	store := as.cache
	if store == nil || !store.IsEnabled() || !store.IsReady(ctx) {
		store = access.NewEntitlementPolicyRetriever(as.sdk)
	}
	resources, err := store.ListAllRegisteredResources(ctx)
	if err != nil {
		return false, fmt.Errorf("authorization: failed to list registered resources: %w", err)
	}

	fqns := make(map[string]struct{})
	for _, resource := range resources {
		for _, value := range resource.GetValues() {
			if f := value.GetFqn(); f != "" {
				fqns[strings.ToLower(f)] = struct{}{}
			}
		}
	}
	idx.fqns = fqns
	idx.loadedAt = time.Now()

	as.logger.DebugContext(ctx, "refreshed registered resource index for endpoint authorization",
		slog.Int("values", len(fqns)),
	)

	_, ok := fqns[strings.ToLower(fqn)]
	return ok, nil
}

func (as *Service) registeredResources() *registeredResourceIndex {
	as.rrOnce.Do(func() {
		as.rrIndex = &registeredResourceIndex{}
	})
	return as.rrIndex
}
