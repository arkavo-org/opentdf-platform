// Package source defines the contract every entitlement source implements and
// the composite entity resolver consumes. It is a leaf: it imports nothing
// from the other entityresolution packages.
package source

import (
	"context"
	"strings"
	"time"

	"github.com/opentdf/platform/service/internal/agentstatus"
)

// Kind classifies the subject an entitlement is resolved for.
type Kind string

const (
	KindPerson Kind = "person"
	KindAgent  Kind = "agent"
	KindDevice Kind = "device"
)

// Trust says how far a subject's claims may be believed.
type Trust int

const (
	// TrustNone: the claims are discarded.
	TrustNone Trust = iota
	// TrustPEP: the unsealed claims of an allowlisted PEP.
	TrustPEP
	// TrustVerified: the claims of a verified token.
	TrustVerified
)

// Subject is the entity a source resolves entitlements for.
type Subject struct {
	Claims    map[string]any
	Kind      Kind
	AccountID string
	Trust     Trust
}

// Query describes the decision being served. Resources holds the requested
// value FQNs and is empty when the route carries none.
type Query struct {
	Action    string
	Resources []string
}

// Grant is one attribute value FQN a subject may act on. A zero ExpiresAt
// means the evidence expiry applies.
type Grant struct {
	FQN       string
	Actions   []string
	ExpiresAt time.Time
}

// Outcome is how a source's resolution ended.
type Outcome string

const (
	OutcomeComplete      Outcome = "complete"
	OutcomeNotApplicable Outcome = "not_applicable"
	OutcomeUnavailable   Outcome = "unavailable"
	OutcomeInvalid       Outcome = "invalid"
)

// Resolution is what a source returns for one subject and query.
type Resolution struct {
	Grants     []Grant
	Properties map[string]any
	Outcome    Outcome
}

// Source resolves one slice of a subject's entitlements.
type Source interface {
	Resolve(ctx context.Context, subject Subject, query Query) (Resolution, error)
}

// FQN is a parsed attribute value FQN.
type FQN struct {
	Namespace, Definition, Value string
}

const (
	scheme       = "https://"
	attrSegment  = "attr"
	valueSegment = "value"
)

// ParseFQN parses https://<ns>/attr/<def>/value/<value>. It is structural:
// the input is lowercased, every part must be non-empty and no further "/" is
// allowed. It does not judge whether the namespace is one anybody owns.
func ParseFQN(s string) (FQN, bool) {
	parts, ok := splitFQN(s)
	if !ok || len(parts) != 5 || parts[3] != valueSegment || parts[4] == "" {
		return FQN{}, false
	}
	return FQN{Namespace: parts[0], Definition: parts[2], Value: parts[4]}, true
}

// ParseDefinition parses https://<ns>/attr/<def>.
func ParseDefinition(s string) (string, string, bool) {
	parts, ok := splitFQN(s)
	if !ok || len(parts) != 3 {
		return "", "", false
	}
	return parts[0], parts[2], true
}

// splitFQN lowercases s, strips the https scheme and splits the rest. It
// checks the shared prefix: a non-empty namespace, "attr" and a non-empty
// definition.
func splitFQN(s string) ([]string, bool) {
	rest, ok := strings.CutPrefix(strings.ToLower(s), scheme)
	if !ok {
		return nil, false
	}
	parts := strings.Split(rest, "/")
	if len(parts) < 3 || parts[0] == "" || parts[1] != attrSegment || parts[2] == "" {
		return nil, false
	}
	return parts, true
}

// DefinitionFQN returns https://<ns>/attr/<def>.
func (f FQN) DefinitionFQN() string {
	return scheme + f.Namespace + "/" + attrSegment + "/" + f.Definition
}

// String returns https://<ns>/attr/<def>/value/<value>.
func (f FQN) String() string {
	return f.DefinitionFQN() + "/" + valueSegment + "/" + f.Value
}

// KindOf classifies claims: an agent marker wins, then an arkavo_npe of type
// device, and everything else is a person.
func KindOf(claims map[string]any) Kind {
	if agentstatus.HasAgentMarker(claims) {
		return KindAgent
	}
	if npe, _ := claims[agentstatus.ClaimNpe].(map[string]any); npe != nil {
		if typ, _ := npe["type"].(string); typ == agentstatus.NpeTypeDevice {
			return KindDevice
		}
	}
	return KindPerson
}
