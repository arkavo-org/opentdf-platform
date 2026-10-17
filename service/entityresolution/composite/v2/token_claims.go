package composite

import (
	"context"

	"github.com/opentdf/platform/service/entityresolution/source"
)

// tokenClaimsSource grants the attribute value FQNs a token carries in one
// claim, restricted to the definitions the source owns.
type tokenClaimsSource struct {
	claim       string
	definitions map[string]bool
}

// newTokenClaimsSource returns the identity-core source: of the strings in
// claim, only value FQNs of its own definitions become grants, lowercased.
// Its grants carry no actions; the resolver gives them the source's
// configured ones.
func newTokenClaimsSource(claim string, definitions []string) source.Source {
	own := make(map[string]bool, len(definitions))
	for _, d := range definitions {
		if key, ok := definitionKey(d); ok {
			own[key] = true
		}
	}
	return &tokenClaimsSource{claim: claim, definitions: own}
}

// Resolve never fails: there is no I/O, and malformed claim data is dropped.
func (s *tokenClaimsSource) Resolve(_ context.Context, subject source.Subject, _ source.Query) (source.Resolution, error) {
	var grants []source.Grant
	seen := map[string]bool{}
	for _, raw := range stringList(subject.Claims[s.claim]) {
		fqn, ok := source.ParseFQN(raw)
		if !ok || !s.definitions[fqn.DefinitionFQN()] {
			continue
		}
		key := fqn.String()
		if seen[key] {
			continue
		}
		seen[key] = true
		grants = append(grants, source.Grant{FQN: key})
	}
	if len(grants) == 0 {
		return source.Resolution{Outcome: source.OutcomeNotApplicable}, nil
	}
	return source.Resolution{Grants: grants, Outcome: source.OutcomeComplete}, nil
}

// stringList returns the string elements of a claim list; anything else in
// it, or a non-list claim, is ignored.
func stringList(v any) []string {
	switch list := v.(type) {
	case []string:
		return list
	case []any:
		out := make([]string, 0, len(list))
		for _, e := range list {
			if str, ok := e.(string); ok {
				out = append(out, str)
			}
		}
		return out
	default:
		return nil
	}
}
