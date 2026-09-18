// Package authzen implements the platform's single Policy Decision Point.
//
// It answers SARC (Subject, Action, Resource, Context) questions from
// service/pkg/authz for both planes of the platform:
//
//	Connect interceptor ─┐
//	HTTP middleware     ─┼─► Engine ─► bootstrap root of trust
//	AuthZEN API         ─┘             OpenTDF Authorization v2 policy
//	                                   platform grants
//	                                   default deny
//
// Platform API operations are resources: an RPC procedure or HTTP route is
// normalized into a resource identifier here, and — when endpoint policy is
// enabled — into a registered resource value FQN that the OpenTDF policy
// graph can govern directly.
package authzen

import (
	"path"
	"strings"

	"github.com/opentdf/platform/service/pkg/authz"
)

// Endpoint actions. These are the action names the platform derives from an
// RPC method name or HTTP verb; policy may define richer actions.
const (
	ActionRead   = "read"
	ActionWrite  = "write"
	ActionDelete = "delete"
	ActionUnsafe = "unsafe"
	ActionOther  = "other"
)

// ActionForRPC derives the action from a Connect/gRPC method name.
func ActionForRPC(method string) string {
	switch {
	case strings.HasPrefix(method, "List") || strings.HasPrefix(method, "Get"):
		return ActionRead
	case strings.HasPrefix(method, "Create") || strings.HasPrefix(method, "Update") || strings.HasPrefix(method, "Assign"):
		return ActionWrite
	case strings.HasPrefix(method, "Delete") || strings.HasPrefix(method, "Remove") || strings.HasPrefix(method, "Deactivate"):
		return ActionDelete
	case strings.HasPrefix(method, "Unsafe"):
		return ActionUnsafe
	}
	return ActionOther
}

// ActionForHTTP derives the action from an HTTP method.
func ActionForHTTP(method string) string {
	switch strings.ToUpper(method) {
	case "GET", "HEAD", "OPTIONS":
		return ActionRead
	case "POST", "PUT", "PATCH":
		return ActionWrite
	case "DELETE":
		return ActionDelete
	}
	return ActionUnsafe
}

// ResourceForProcedure normalizes a Connect procedure
// ("/policy.attributes.AttributeService/CreateAttribute") into the resource
// identifier the platform authorizes against
// ("policy.attributes.AttributeService/CreateAttribute"). Procedures that do
// not have the expected shape are returned trimmed of their leading slash so
// they remain addressable by policy rather than silently unauthorizable.
func ResourceForProcedure(procedure string) string {
	trimmed := strings.TrimPrefix(procedure, "/")
	parts := strings.Split(trimmed, "/")
	if len(parts) < 2 { //nolint:mnd // service + method
		return trimmed
	}
	return path.Join(parts[0], parts[1])
}

// ConnectRequest builds the decision request for a Connect RPC procedure.
func ConnectRequest(procedure string) authz.DecisionRequest {
	trimmed := strings.TrimPrefix(procedure, "/")
	parts := strings.Split(trimmed, "/")
	method := ""
	if len(parts) >= 2 { //nolint:mnd // service + method
		method = parts[1]
	}
	return authz.DecisionRequest{
		Action: authz.Action{Name: ActionForRPC(method)},
		Resource: authz.Resource{
			Type: authz.ResourceTypeEndpoint,
			ID:   ResourceForProcedure(procedure),
		},
		Context: authz.RequestContext{
			Transport: authz.TransportConnect,
			Path:      procedure,
		},
	}
}

// HTTPRequest builds the decision request for an HTTP route.
func HTTPRequest(method, urlPath string) authz.DecisionRequest {
	return authz.DecisionRequest{
		Action: authz.Action{Name: ActionForHTTP(method)},
		Resource: authz.Resource{
			Type: authz.ResourceTypeEndpoint,
			ID:   urlPath,
		},
		Context: authz.RequestContext{
			Transport: authz.TransportHTTP,
			Method:    method,
			Path:      urlPath,
		},
	}
}
