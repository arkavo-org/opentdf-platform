package authzen

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"strings"

	"github.com/opentdf/platform/service/logger"
	"github.com/opentdf/platform/service/pkg/authz"
)

// Decision sources, in the order the engine consults them.
const (
	SourceBootstrap = "bootstrap"
	SourcePolicy    = "policy"
	SourceGrants    = "grants"
	SourceDefault   = "default"
)

// ErrPermissionDenied is returned to a policy enforcement point when a
// request is not authorized.
var ErrPermissionDenied = errors.New("permission denied")

// EndpointPolicyConfig controls whether platform API operations are
// governed by the policy graph itself. When enabled, each endpoint is
// addressed as a registered resource value FQN and evaluated by the
// OpenTDF Authorization v2 PDP; endpoints with no registered resource fall
// through to the platform grant table.
type EndpointPolicyConfig struct {
	Enabled bool `mapstructure:"enabled" json:"enabled" default:"false"`
	// Namespace the endpoint registered resources live in, e.g.
	// "platform.example.com". Required when enabled.
	Namespace string `mapstructure:"namespace" json:"namespace"`
	// ResourceName is the registered resource whose values are platform
	// endpoints.
	ResourceName string `mapstructure:"resource_name" json:"resource_name" default:"endpoint"`
}

// Config assembles the engine.
type Config struct {
	// Grants is the platform grant table.
	Grants *GrantSet
	// Bootstrap configures the root of trust.
	Bootstrap BootstrapConfig
	// EndpointPolicy configures policy-governed endpoints.
	EndpointPolicy EndpointPolicyConfig
	// Evaluators is the registry the authorization service registers its
	// in-process evaluator with. May be nil in deployments that do not run
	// the authorization service.
	Evaluators *authz.EvaluatorRegistry
	// Logger is required.
	Logger *logger.Logger
}

// Engine is the platform's Policy Decision Point. It is the only thing that
// answers authorization questions, for the control plane and the data plane
// alike.
type Engine struct {
	grants     *GrantSet
	bootstrap  *Bootstrap
	evaluators *authz.EvaluatorRegistry
	endpoint   EndpointPolicyConfig
	logger     *logger.Logger
}

// NewEngine builds the engine. A nil grant set falls back to the platform
// defaults.
func NewEngine(cfg Config) (*Engine, error) {
	if cfg.Logger == nil {
		return nil, errors.New("authzen: logger is required")
	}
	grants := cfg.Grants
	if grants == nil {
		var err error
		grants, err = DefaultGrants()
		if err != nil {
			return nil, err
		}
	}
	bootstrap, err := NewBootstrap(cfg.Bootstrap)
	if err != nil {
		return nil, err
	}
	endpoint := cfg.EndpointPolicy
	if endpoint.ResourceName == "" {
		endpoint.ResourceName = "endpoint"
	}
	if endpoint.Enabled && endpoint.Namespace == "" {
		return nil, errors.New("authzen: endpoint_policy.namespace is required when endpoint policy is enabled")
	}

	if len(grants.SkippedLines) > 0 {
		cfg.Logger.Warn("authorization grants contain lines that could not be parsed and are not in force",
			slog.Any("lines", grants.SkippedLines),
		)
	}

	return &Engine{
		grants:     grants,
		bootstrap:  bootstrap,
		evaluators: cfg.Evaluators,
		endpoint:   endpoint,
		logger:     cfg.Logger,
	}, nil
}

// BootstrapEnabled reports whether the root of trust is active.
func (e *Engine) BootstrapEnabled() bool { return e.bootstrap.Enabled() }

// CapabilitiesClaim is the token claim the engine reads root capabilities
// from.
func (e *Engine) CapabilitiesClaim() string { return e.bootstrap.CapabilitiesClaim() }

// TrustsBootstrapIssuer reports whether an issuer may assert capabilities.
func (e *Engine) TrustsBootstrapIssuer(issuer string) bool { return e.bootstrap.TrustsIssuer(issuer) }

// Decide answers one SARC question.
//
// Sources are consulted in order and the first definite answer wins:
//
//  1. the bootstrap root of trust, which may only permit;
//  2. OpenTDF policy, for resources policy represents;
//  3. the platform grant table, for endpoints;
//  4. deny.
func (e *Engine) Decide(ctx context.Context, req authz.DecisionRequest) (authz.Decision, error) {
	if d := e.bootstrap.Evaluate(req); d.Allowed() {
		e.log(ctx, req, d)
		return d, nil
	}

	if e.policyApplies(req) {
		if req.Resource.Type == authz.ResourceTypeEndpoint && req.Resource.FQN == "" {
			req.Resource.FQN = e.EndpointFQN(req.Resource.ID)
		}
		d, err := e.evaluators.Evaluate(ctx, req)
		if err != nil {
			return authz.Decision{
				Effect: authz.EffectDeny,
				Source: SourcePolicy,
				Reason: "policy evaluation failed",
			}, fmt.Errorf("authzen: policy evaluation failed: %w", err)
		}
		if d.Effect != authz.EffectAbstain {
			d.Source = SourcePolicy
			e.log(ctx, req, d)
			return d, nil
		}
	}

	if e.grantsApply(req) {
		if d := e.grants.Evaluate(req); d.Effect != authz.EffectAbstain {
			e.log(ctx, req, d)
			return d, nil
		}
	}

	d := authz.Decision{Effect: authz.EffectDeny, Source: SourceDefault, Reason: "no decision source permitted the request"}
	e.log(ctx, req, d)
	return d, nil
}

// EndpointFQN returns the registered resource value FQN that represents a
// platform endpoint, or "" when endpoint policy is not configured.
func (e *Engine) EndpointFQN(resourceID string) string {
	if !e.endpoint.Enabled || e.endpoint.Namespace == "" || resourceID == "" {
		return ""
	}
	return fmt.Sprintf("https://%s/reg_res/%s/value/%s",
		e.endpoint.Namespace,
		SanitizePolicyName(e.endpoint.ResourceName),
		SanitizePolicyName(resourceID),
	)
}

// SanitizePolicyName renders an arbitrary platform identifier as a policy
// name: lowercase alphanumerics separated by single underscores, which is
// what registered resource names and values accept.
func SanitizePolicyName(in string) string {
	var b strings.Builder
	b.Grow(len(in))
	lastUnderscore := false
	for _, r := range strings.ToLower(in) {
		switch {
		case (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9'):
			b.WriteRune(r)
			lastUnderscore = false
		default:
			if !lastUnderscore && b.Len() > 0 {
				b.WriteByte('_')
				lastUnderscore = true
			}
		}
	}
	return strings.Trim(b.String(), "_")
}

// policyApplies reports whether the policy graph should be consulted. Data
// resources always go to policy; endpoints only when endpoint policy is
// enabled.
func (e *Engine) policyApplies(req authz.DecisionRequest) bool {
	if e.evaluators == nil || e.evaluators.Evaluator() == nil {
		return false
	}
	if req.Resource.Type == authz.ResourceTypeEndpoint || req.Resource.Type == "" {
		return e.endpoint.Enabled
	}
	return true
}

// grantsApply reports whether the platform grant table has anything to say
// about a resource. Grants govern platform operations; data resources are
// policy's business alone.
func (e *Engine) grantsApply(req authz.DecisionRequest) bool {
	return req.Resource.Type == authz.ResourceTypeEndpoint || req.Resource.Type == ""
}

func (e *Engine) log(ctx context.Context, req authz.DecisionRequest, d authz.Decision) {
	attrs := []any{
		slog.String("subject", req.Subject.ID),
		slog.Any("roles", req.Subject.Roles),
		slog.String("action", req.Action.Name),
		slog.String("resource", req.Resource.ID),
		slog.String("resource_type", req.Resource.Type),
		slog.String("effect", string(d.Effect)),
		slog.String("decision_source", d.Source),
		slog.String("reason", d.Reason),
	}
	if d.Allowed() {
		e.logger.DebugContext(ctx, "authorization permitted", attrs...)
		return
	}
	e.logger.DebugContext(ctx, "authorization denied", attrs...)
}
