package filestore

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/opentdf/platform/protocol/go/policy"
)

const samplePolicyYAML = `
namespaces:
  - name: example.com
key_access_servers:
  - id: kas1
    uri: https://kas.example.com
attributes:
  - namespace: example.com
    name: classification
    rule: hierarchy
    grants:
      - id: kas1
    values:
      - value: topsecret
      - value: secret
      - value: public
  - namespace: example.com
    name: dept
    rule: anyOf
    values:
      - value: eng
      - value: sales
subject_mappings:
  - attribute_value_fqn: https://example.com/attr/classification/value/topsecret
    inline_condition_set:
      subject_sets:
        - condition_groups:
            - boolean_operator: AND
              conditions:
                - subject_external_selector_value: .realm_access.roles
                  operator: IN
                  subject_external_values: [topsecret-cleared]
    actions:
      - name: read
        standard: TRANSMIT
`

func TestStore_LoadAndQuery(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "policy.yaml")
	if err := os.WriteFile(path, []byte(samplePolicyYAML), 0o600); err != nil {
		t.Fatal(err)
	}
	store, err := NewStoreFromFile(path)
	if err != nil {
		t.Fatalf("NewStoreFromFile: %v", err)
	}
	ctx := context.Background()

	attrs, err := store.ListAllAttributes(ctx)
	if err != nil {
		t.Fatalf("ListAllAttributes: %v", err)
	}
	if len(attrs) != 2 {
		t.Fatalf("want 2 attributes, got %d", len(attrs))
	}
	if attrs[0].GetFqn() != "https://example.com/attr/classification" {
		t.Fatalf("attribute fqn mismatch: %q", attrs[0].GetFqn())
	}
	if attrs[0].GetRule() != policy.AttributeRuleTypeEnum_ATTRIBUTE_RULE_TYPE_ENUM_HIERARCHY {
		t.Fatalf("expected hierarchy rule, got %v", attrs[0].GetRule())
	}
	if len(attrs[0].GetValues()) != 3 {
		t.Fatalf("want 3 values, got %d", len(attrs[0].GetValues()))
	}
	if len(attrs[0].GetGrants()) != 1 || attrs[0].GetGrants()[0].GetUri() != "https://kas.example.com" {
		t.Fatalf("kas grant not resolved: %+v", attrs[0].GetGrants())
	}

	sms, err := store.ListAllSubjectMappings(ctx)
	if err != nil {
		t.Fatalf("ListAllSubjectMappings: %v", err)
	}
	if len(sms) != 1 {
		t.Fatalf("want 1 subject mapping, got %d", len(sms))
	}

	vals, err := store.GetAttributeValuesByFqns(ctx, []string{"https://example.com/attr/classification/value/secret"})
	if err != nil {
		t.Fatalf("GetAttributeValuesByFqns: %v", err)
	}
	if len(vals) != 1 {
		t.Fatalf("want 1 value, got %d", len(vals))
	}

	matched, err := store.MatchSubjectMappings(ctx, []*policy.SubjectProperty{
		{ExternalSelectorValue: ".realm_access.roles"},
	})
	if err != nil {
		t.Fatalf("MatchSubjectMappings: %v", err)
	}
	if len(matched) != 1 {
		t.Fatalf("expected 1 matched subject mapping, got %d", len(matched))
	}
	if matched[0].GetAttributeValue().GetFqn() != "https://example.com/attr/classification/value/topsecret" {
		t.Fatalf("matched wrong attribute value: %q", matched[0].GetAttributeValue().GetFqn())
	}

	noMatch, err := store.MatchSubjectMappings(ctx, []*policy.SubjectProperty{
		{ExternalSelectorValue: ".other"},
	})
	if err != nil {
		t.Fatalf("MatchSubjectMappings no-match: %v", err)
	}
	if len(noMatch) != 0 {
		t.Fatalf("expected 0 matched subject mappings, got %d", len(noMatch))
	}
}
