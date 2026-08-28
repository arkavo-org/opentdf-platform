package filestore_test

import (
	"context"
	"testing"

	authz "github.com/opentdf/platform/protocol/go/authorization/v2"
	entityresolutionV2 "github.com/opentdf/platform/protocol/go/entityresolution/v2"
	"github.com/opentdf/platform/protocol/go/policy"
	access "github.com/opentdf/platform/service/internal/access/v2"
	"github.com/opentdf/platform/service/logger"
	"github.com/opentdf/platform/service/policy/filestore"
)

// TestArkavoSnapshot_DirectEntitlementDecisions proves that the arkavo ERS
// provider's direct-entitlement shape (attribute-value FQNs on
// EntityRepresentation.DirectEntitlements) and the file-backed arkavo.ai
// policy snapshot (examples/config/policy.arkavo.yaml) compose correctly
// through the real v2 PolicyDecisionPoint: no subject mappings are involved,
// only direct entitlements, and the classification attribute's hierarchy
// rule must rank a device's held value against the resource's required
// value rather than treating any held value as sufficient.
func TestArkavoSnapshot_DirectEntitlementDecisions(t *testing.T) {
	ctx := context.Background()
	log := logger.CreateTestLogger()

	store, err := filestore.NewStoreFromFile("../../../examples/config/policy.arkavo.yaml")
	if err != nil {
		t.Fatalf("load snapshot: %v", err)
	}

	allAttrs, err := store.ListAllAttributes(ctx)
	if err != nil {
		t.Fatalf("ListAllAttributes: %v", err)
	}
	allSMs, err := store.ListAllSubjectMappings(ctx)
	if err != nil {
		t.Fatalf("ListAllSubjectMappings: %v", err)
	}
	allRRs, err := store.ListAllRegisteredResources(ctx)
	if err != nil {
		t.Fatalf("ListAllRegisteredResources: %v", err)
	}

	pdp, err := access.NewPolicyDecisionPoint(ctx, log, allAttrs, allSMs, allRRs, true, false)
	if err != nil {
		t.Fatalf("NewPolicyDecisionPoint: %v", err)
	}
	if pdp == nil {
		t.Fatal("nil PDP")
	}

	// FQNs confirmed against examples/config/policy.arkavo.yaml: namespace
	// arkavo.ai, attribute `tdf` (anyOf: create, decrypt) and attribute
	// `classification` (hierarchy, declared highest-first: restricted,
	// confidential, internal, public).
	const (
		tdfDecrypt        = "https://arkavo.ai/attr/tdf/value/decrypt"
		tdfCreate         = "https://arkavo.ai/attr/tdf/value/create"
		classInternal     = "https://arkavo.ai/attr/classification/value/internal"
		classConfidential = "https://arkavo.ai/attr/classification/value/confidential"
	)

	agent := &entityresolutionV2.EntityRepresentation{
		OriginalId: "agent",
		DirectEntitlements: []*entityresolutionV2.DirectEntitlement{
			{AttributeValueFqn: tdfDecrypt, Actions: []string{"read"}},
		},
	}
	device := &entityresolutionV2.EntityRepresentation{
		OriginalId: "device",
		DirectEntitlements: []*entityresolutionV2.DirectEntitlement{
			{AttributeValueFqn: classInternal, Actions: []string{"read"}},
		},
	}

	read := &policy.Action{Name: "read"}

	res := func(fqns ...string) *authz.Resource {
		return &authz.Resource{
			Resource: &authz.Resource_AttributeValues_{
				AttributeValues: &authz.Resource_AttributeValues{Fqns: fqns},
			},
		}
	}

	// Agent's only direct entitlement is tdf/decrypt for the read action, so
	// a resource tagged tdf/decrypt must be permitted...
	assertDecision(ctx, t, pdp, agent, read, res(tdfDecrypt), true,
		"agent entitled to tdf/decrypt should be permitted to read a tdf/decrypt-tagged resource")
	// ...while a resource tagged tdf/create carries no matching entitlement,
	// so it must be denied.
	assertDecision(ctx, t, pdp, agent, read, res(tdfCreate), false,
		"agent without a tdf/create entitlement should be denied read on a tdf/create-tagged resource")

	// Device's direct entitlement is classification/internal. A resource
	// requiring exactly that value must be permitted...
	assertDecision(ctx, t, pdp, device, read, res(classInternal), true,
		"device entitled to classification/internal should be permitted to read an internal resource")
	// ...but classification is a HIERARCHY ranked by declaration index, and
	// confidential (index 1) outranks internal (index 2). A device holding
	// only internal must therefore be denied a confidential resource: this
	// is the direction the hierarchy rule exists to enforce, and getting it
	// backwards (denying the lower-ranked resource instead) would make the
	// hierarchy check vacuous.
	assertDecision(ctx, t, pdp, device, read, res(classConfidential), false,
		"device entitled only to classification/internal must be denied read on a higher-ranked confidential resource")
}

// assertDecision runs pdp.GetDecision for the given entity, action, and
// single resource and asserts Decision.AllPermitted matches wantPermit.
func assertDecision(
	ctx context.Context,
	t *testing.T,
	pdp *access.PolicyDecisionPoint,
	entity *entityresolutionV2.EntityRepresentation,
	action *policy.Action,
	resource *authz.Resource,
	wantPermit bool,
	msg string,
) {
	t.Helper()

	decision, _, err := pdp.GetDecision(ctx, entity, action, []*authz.Resource{resource})
	if err != nil {
		t.Fatalf("GetDecision: %v", err)
	}
	if decision == nil {
		t.Fatal("GetDecision returned nil decision")
	}
	if decision.AllPermitted != wantPermit {
		t.Errorf("%s: Decision.AllPermitted = %v, want %v", msg, decision.AllPermitted, wantPermit)
	}
}
