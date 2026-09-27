package filestore_test

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/opentdf/platform/protocol/go/policy"
	"github.com/opentdf/platform/service/policy/filestore"
)

// clientIDClaim is the claim the arkavo ERS copies arkavo_account_id into
// (arkavo/v2 client_id_claim default) and that arkavo deployments configure as
// server.auth.policy.client_id_claim. A subject mapping keyed on it would
// grant the owner's attributes to every token carrying the owner's account
// id, agent tokens included (identity-plane end state §2.2).
const clientIDClaim = "arkavo_account_id"

// subjectMappingsKeyedOn lists subject mappings with any condition whose
// selector's first path element is claim: ".arkavo_account_id",
// "arkavo_account_id", ".arkavo_account_id[]", ".arkavo_account_id.x".
func subjectMappingsKeyedOn(sms []*policy.SubjectMapping, claim string) []string {
	var hits []string
	for _, sm := range sms {
		for _, set := range sm.GetSubjectConditionSet().GetSubjectSets() {
			for _, group := range set.GetConditionGroups() {
				for _, cond := range group.GetConditions() {
					if selectorNamesClaim(cond.GetSubjectExternalSelectorValue(), claim) {
						hits = append(hits, sm.GetId()+" -> "+sm.GetAttributeValue().GetFqn())
					}
				}
			}
		}
	}
	return hits
}

func selectorNamesClaim(selector, claim string) bool {
	first := strings.TrimPrefix(strings.TrimSpace(selector), ".")
	if i := strings.IndexAny(first, ".["); i >= 0 {
		first = first[:i]
	}
	return first == claim
}

func loadMappings(t *testing.T, path string) []*policy.SubjectMapping {
	t.Helper()
	store, err := filestore.NewStoreFromFile(path)
	if err != nil {
		t.Fatalf("load %s: %v", path, err)
	}
	sms, err := store.ListAllSubjectMappings(context.Background())
	if err != nil {
		t.Fatalf("ListAllSubjectMappings: %v", err)
	}
	return sms
}

func TestPolicySnapshots_NoSubjectMappingKeyedOnClientIDClaim(t *testing.T) {
	paths, err := filepath.Glob("../../../examples/config/policy.*.yaml")
	if err != nil {
		t.Fatal(err)
	}
	var sawArkavo bool
	for _, path := range paths {
		sawArkavo = sawArkavo || filepath.Base(path) == "policy.arkavo.yaml"
		t.Run(filepath.Base(path), func(t *testing.T) {
			if hits := subjectMappingsKeyedOn(loadMappings(t, path), clientIDClaim); len(hits) > 0 {
				t.Fatalf("subject mappings keyed on %q (the ERS copies the owner's account id there): %v", clientIDClaim, hits)
			}
		})
	}
	if !sawArkavo {
		t.Fatal("policy.arkavo.yaml not found; the sweep would be vacuous")
	}
}

// Negative control: proves the sweep above can fail.
func TestSubjectMappingsKeyedOn_DetectsClientIDMapping(t *testing.T) {
	const snapshot = `
namespaces:
  - name: arkavo.ai
attributes:
  - namespace: arkavo.ai
    name: tdf
    rule: anyOf
    values:
      - value: decrypt
subject_mappings:
  - id: owner-by-account
    attribute_value_fqn: https://arkavo.ai/attr/tdf/value/decrypt
    inline_condition_set:
      subject_sets:
        - condition_groups:
            - boolean_operator: AND
              conditions:
                - subject_external_selector_value: .arkavo_account_id
                  operator: IN
                  subject_external_values:
                    - 00000000-0000-0000-0000-000000000001
    actions:
      - name: read
`
	path := filepath.Join(t.TempDir(), "policy.yaml")
	if err := os.WriteFile(path, []byte(snapshot), 0o600); err != nil {
		t.Fatal(err)
	}
	if hits := subjectMappingsKeyedOn(loadMappings(t, path), clientIDClaim); len(hits) != 1 {
		t.Fatalf("want exactly the planted mapping, got %v", hits)
	}
}
