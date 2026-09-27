package access

import (
	"context"
	"log/slog"

	kaspb "github.com/opentdf/platform/protocol/go/kas"
	"github.com/opentdf/platform/service/logger/audit"
)

// refuseDuplicatePolicyIDs fails every request whose policy Id another
// request in the same rewrap also carries, and returns the rest. Results are
// keyed by policy Id, so two such requests cannot both be answered: without
// this the later one's results replace the earlier's, its KAOs are then
// looked up in the wrong map, and an unmatched KAO reaches Encapsulate with
// no key. The refusal happens before any KAO is unwrapped. Requests without
// a policy Id pass through untouched, as before.
func (p *Provider) refuseDuplicatePolicyIDs(ctx context.Context, requests []*kaspb.UnsignedRewrapRequest_WithPolicyRequest, results policyKAOResults) []*kaspb.UnsignedRewrapRequest_WithPolicyRequest {
	seen := make(map[string]int, len(requests))
	for _, req := range requests {
		if id := req.GetPolicy().GetId(); id != "" {
			seen[id]++
		}
	}
	unique := make([]*kaspb.UnsignedRewrapRequest_WithPolicyRequest, 0, len(requests))
	for _, req := range requests {
		id := req.GetPolicy().GetId()
		if id == "" || seen[id] == 1 {
			unique = append(unique, req)
			continue
		}
		p.Logger.WarnContext(ctx, "rewrap: policy id shared by more than one request", slog.String("policy_id", id))
		p.refuseRequest(ctx, results, req, err400("bad request"))
	}
	return unique
}

// refuseRequest fails every KAO of req with err and audits each as a
// failure, without unwrapping anything. A KAO with no key access object gets
// the 400 the normal path gives it and, as there, no audit record. Requests
// sharing a policy Id share one result map, so none of their KAOs drops out
// of the response. The policy is decoded only to name it in the audit
// record.
func (p *Provider) refuseRequest(ctx context.Context, results policyKAOResults, req *kaspb.UnsignedRewrapRequest_WithPolicyRequest, err error) {
	policyID := req.GetPolicy().GetId()
	kaoResults, ok := results[policyID]
	if !ok {
		kaoResults = make(map[string]kaoResult)
		results[policyID] = kaoResults
	}
	policy, decodeErr := decodePolicy(req.GetPolicy().GetBody())
	if decodeErr != nil {
		policy = &Policy{}
	}
	kasPolicy := ConvertToAuditKasPolicy(*policy)
	for _, kao := range req.GetKeyAccessObjects() {
		if kao.GetKeyAccessObject() == nil {
			failedKAORewrap(kaoResults, kao, err400("key access object is nil"))
			continue
		}
		p.Logger.Audit.RewrapFailure(ctx, audit.RewrapAuditEventParams{
			Policy:        kasPolicy,
			TDFFormat:     "tdf3",
			Algorithm:     req.GetAlgorithm(),
			PolicyBinding: kao.GetKeyAccessObject().GetPolicyBinding().GetHash(),
			KeyID:         kao.GetKeyAccessObject().GetKid(),
		})
		failedKAORewrap(kaoResults, kao, err)
	}
}
