package access

import (
	"context"
	"errors"
	"log/slog"
	"slices"
	"strconv"

	authzV2 "github.com/opentdf/platform/protocol/go/authorization/v2"
	"github.com/opentdf/platform/protocol/go/entity"
	"github.com/opentdf/platform/protocol/go/policy"
	"github.com/opentdf/platform/service/policy/actions"
	"github.com/opentdf/platform/service/tracing"
)

const (
	ErrPolicyDissemInvalid     = Error("policy dissem invalid")
	ErrDecisionUnexpected      = Error("authorization decision unexpected")
	ErrDecisionCountUnexpected = Error("authorization decision count unexpected")
)

var decryptAction = &policy.Action{
	Name: actions.ActionNameRead,
}

type PDPAccessResult struct {
	Access              bool
	Error               error
	Policy              *Policy
	RequiredObligations []string
}

// canAccess runs the ABAC decision for each policy. requester is the
// requesting entity's identifier (the verified token's sub). With
// enforce_dissem on, a policy with a non-empty dissem list is released only
// when the list names requester exactly (see
// https://github.com/opentdf/spec/blob/main/concepts/access_control.md:
// the PEP checks the requesting entity's identifier against dissem); the
// ABAC decision is still required. With it off, dissem is logged as not
// enforced, as upstream does.
func (p *Provider) canAccess(ctx context.Context, token *entity.Token, policies []*Policy, fulfillableObligationFQNs []string, requester string) ([]PDPAccessResult, error) {
	var res []PDPAccessResult
	var resources []*authzV2.Resource
	idPolicyMap := make(map[string]*Policy)
	for i, policy := range policies {
		if len(policy.Body.Dissem) > 0 {
			if !p.EnforceDissem {
				// TODO: Move dissems check to the getdecisions endpoint
				p.Logger.Error("dissems check is not enabled in v2 platform kas")
			} else if !dissemAllows(policy.Body.Dissem, requester) {
				p.Logger.WarnContext(ctx, "requester is not in the policy dissemination list",
					slog.String("requester", requester),
					slog.String("policy_uuid", policy.UUID.String()),
				)
				res = append(res, PDPAccessResult{Access: false, Policy: policy})
				continue
			}
		}
		if len(policy.Body.DataAttributes) > 0 {
			id := "rewrap-" + strconv.Itoa(i)
			attrValueFqns := make([]string, len(policy.Body.DataAttributes))
			for idx, attr := range policy.Body.DataAttributes {
				attrValueFqns[idx] = attr.URI
			}
			resources = append(resources, &authzV2.Resource{
				EphemeralId: id,
				Resource: &authzV2.Resource_AttributeValues_{
					AttributeValues: &authzV2.Resource_AttributeValues{
						Fqns: attrValueFqns,
					},
				},
			})
			idPolicyMap[id] = policy
		} else {
			res = append(res, PDPAccessResult{Access: true, Policy: policy})
		}
	}

	// If no data attributes were found in any policies, return early with the results
	// instead of roundtripping to get a decision on no resources
	if len(resources) == 0 {
		p.Logger.DebugContext(ctx, "no resources to check")
		return res, nil
	}

	ctx, span := p.Start(ctx, "checkAttributes")
	defer span.End()

	resourceDecisions, err := p.checkAttributes(ctx, resources, token, fulfillableObligationFQNs)
	if err != nil {
		return nil, err
	}

	for _, decision := range resourceDecisions {
		policy, ok := idPolicyMap[decision.GetEphemeralResourceId()]
		if !ok { // this really should not happen
			p.Logger.WarnContext(ctx, "unexpected ephemeral resource id not mapped to a policy")
			continue
		}
		res = append(res, PDPAccessResult{Policy: policy, Access: decision.GetDecision() == authzV2.Decision_DECISION_PERMIT, RequiredObligations: decision.GetRequiredObligations()})
	}

	return res, nil
}

// checkAttributes makes authorization service GetDecision requests to check access to resources
func (p *Provider) checkAttributes(ctx context.Context, resources []*authzV2.Resource, ent *entity.Token, fulfillableObligationFQNs []string) ([]*authzV2.ResourceDecision, error) {
	ctx = tracing.InjectTraceContext(ctx)

	// If only one resource, prefer singular endpoint
	if len(resources) == 1 {
		req := &authzV2.GetDecisionRequest{
			EntityIdentifier: &authzV2.EntityIdentifier{
				Identifier: &authzV2.EntityIdentifier_Token{Token: ent},
			},
			Action:                    decryptAction,
			Resource:                  resources[0],
			FulfillableObligationFqns: fulfillableObligationFQNs,
		}
		dr, err := p.SDK.AuthorizationV2.GetDecision(ctx, req)
		if err != nil {
			p.Logger.ErrorContext(ctx, "error received from GetDecision")
			return nil, errors.Join(ErrDecisionUnexpected, err)
		}
		return []*authzV2.ResourceDecision{dr.GetDecision()}, nil
	}

	// If more than one resource, use the optimized bulk endpoint
	req := &authzV2.GetDecisionMultiResourceRequest{
		EntityIdentifier: &authzV2.EntityIdentifier{
			Identifier: &authzV2.EntityIdentifier_Token{Token: ent},
		},
		Action:                    decryptAction,
		Resources:                 resources,
		FulfillableObligationFqns: fulfillableObligationFQNs,
	}

	dr, err := p.SDK.AuthorizationV2.GetDecisionMultiResource(ctx, req)
	if err != nil {
		p.Logger.ErrorContext(ctx, "error received from GetDecisionMultiResource")
		return nil, errors.Join(ErrDecisionUnexpected, err)
	}
	return dr.GetResourceDecisions(), nil
}

// dissemAllows reports whether a policy's dissemination list admits the
// requester. An empty list defers entirely to ABAC; a non-empty one must name
// the requester exactly (identifiers such as DIDs are case-sensitive, so no
// folding or trimming). An empty requester is never admitted, even by an
// empty entry.
func dissemAllows(dissem []string, requester string) bool {
	if len(dissem) == 0 {
		return true
	}
	return requester != "" && slices.Contains(dissem, requester)
}
