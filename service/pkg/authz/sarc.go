// Package authz defines the platform's single authorization contract.
//
// Every authorization question the platform asks — "may this caller invoke
// this API?", "may this entity read this TDF?", "may this agent unwrap this
// key?" — is expressed in the same SARC shape (Subject, Action, Resource,
// Context) and answered by one Policy Decision Point.
//
// The types here are deliberately transport-free. They are shared by:
//
//   - the Connect/HTTP interceptors in service/internal/auth (the PEP that
//     guards the control plane),
//   - the AuthZEN evaluation API (the public, standards-shaped contract),
//   - the OpenTDF Authorization v2 service (the PDP that evaluates them
//     against platform policy).
//
// No component calls the PDP over RPC to answer a request it is already
// serving; the evaluator is an in-process interface, and the AuthZEN
// endpoint is a thin adapter over the same interface.
package authz

import (
	"context"

	"github.com/lestrrat-go/jwx/v2/jwt"
)

// Effect is the outcome of evaluating one decision request against one
// decision source.
type Effect string

const (
	// EffectPermit allows the request.
	EffectPermit Effect = "permit"
	// EffectDeny refuses the request.
	EffectDeny Effect = "deny"
	// EffectAbstain means the source held no opinion; evaluation continues
	// with the next source, and a request no source permits is denied.
	EffectAbstain Effect = "abstain"
)

// Subject types. A subject is whoever (or whatever) is acting.
const (
	SubjectTypeUser    = "user"
	SubjectTypeClient  = "client"
	SubjectTypeUnknown = "unknown"
)

// Resource types. Platform API operations are resources, exactly like the
// data resources the PDP has always governed.
const (
	// ResourceTypeEndpoint is a platform API operation: a Connect RPC
	// procedure or an HTTP route.
	ResourceTypeEndpoint = "endpoint"
	// ResourceTypeRegisteredResource is a policy registered resource value,
	// addressed by FQN.
	ResourceTypeRegisteredResource = "registered_resource"
	// ResourceTypeAttributeValues is a set of attribute value FQNs, such as
	// those carried on a TDF.
	ResourceTypeAttributeValues = "attribute_values"
)

// Transports a decision request may arrive over.
const (
	TransportConnect = "connect"
	TransportHTTP    = "http"
	TransportAPI     = "authzen"
)

// Subject is the actor being authorized.
type Subject struct {
	// Type is one of the SubjectType* constants.
	Type string
	// ID identifies the actor: the username claim for a person, the client
	// ID for a machine.
	ID string
	// ClientID is the idP client the request was made through, when known.
	ClientID string
	// Roles are the role/group identifiers resolved by the configured
	// RoleProvider.
	Roles []string
	// Capabilities are root-of-trust capabilities asserted by the caller's
	// token. They are only honored when the token was issued by a
	// configured bootstrap authority; see the authzen package.
	Capabilities []string
	// Token is the verified access token, when the request carried one.
	Token jwt.Token
	// TokenRaw is the token as presented, used to derive an entity chain
	// when the decision is evaluated against platform policy.
	TokenRaw string
	// Properties carries additional subject facts (AuthZEN "properties").
	Properties map[string]any
}

// Action is what the subject is attempting.
type Action struct {
	Name       string
	Properties map[string]any
}

// Resource is what the action is attempted on.
type Resource struct {
	// Type is one of the ResourceType* constants.
	Type string
	// ID is the canonical platform identifier, e.g.
	// "policy.attributes.AttributeService/CreateAttribute" for an RPC or
	// "/policy/attributes" for an HTTP route.
	ID string
	// FQN is the policy fully-qualified name this resource maps to, when
	// one exists (registered resource value FQN).
	FQN string
	// AttributeValueFQNs is set for ResourceTypeAttributeValues.
	AttributeValueFQNs []string
	// Properties carries additional resource facts (AuthZEN "properties").
	Properties map[string]any
}

// RequestContext is the environmental facts of the request.
type RequestContext struct {
	// Issuer of the caller's token.
	Issuer string
	// Transport is one of the Transport* constants.
	Transport string
	// Method is the HTTP method for HTTP requests.
	Method string
	// Path is the HTTP path or RPC procedure as received.
	Path string
	// Properties carries additional context facts (AuthZEN "context").
	Properties map[string]any
}

// DecisionRequest is one SARC question.
type DecisionRequest struct {
	Subject  Subject
	Action   Action
	Resource Resource
	Context  RequestContext
}

// Decision is the answer, plus enough provenance to audit it.
type Decision struct {
	// Effect is the outcome.
	Effect Effect
	// Source names the decision source that produced the effect, e.g.
	// "bootstrap", "policy", "grants", "default".
	Source string
	// Reason is a short, machine-stable explanation.
	Reason string
	// Obligations the PEP must fulfill, as fully qualified obligation
	// value FQNs.
	Obligations []string
}

// Allowed reports whether the decision permits the request.
func (d Decision) Allowed() bool { return d.Effect == EffectPermit }

// PDP answers SARC questions. One implementation governs the whole
// platform: control plane and data plane alike.
type PDP interface {
	Decide(ctx context.Context, req DecisionRequest) (Decision, error)
}

// Evaluator is implemented by the OpenTDF Authorization v2 service so the
// PEP can reach platform policy in-process, with no RPC recursion. An
// evaluator returns EffectAbstain when the resource is not represented in
// policy, which lets the engine fall through to its next source.
type Evaluator interface {
	Evaluate(ctx context.Context, req DecisionRequest) (Decision, error)
}
