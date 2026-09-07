package auth

import (
	"errors"
	"time"

	"github.com/opentdf/platform/service/internal/authzen"
	"github.com/opentdf/platform/service/logger"
	"github.com/opentdf/platform/service/pkg/authz"
)

// AuthConfig pulls AuthN and AuthZ together
type Config struct {
	Enabled      bool     `mapstructure:"enabled" json:"enabled" default:"true"`
	PublicRoutes []string `mapstructure:"-" json:"-"`
	// Used for re-authentication of IPC connections
	IPCReauthRoutes []string `mapstructure:"-" json:"-"`
	AuthNConfig     `mapstructure:",squash"`

	// Programmatic role provider overrides (not loaded from config)
	RoleProvider          authz.RoleProvider                   `mapstructure:"-" json:"-"`
	RoleProviderFactories map[string]authz.RoleProviderFactory `mapstructure:"-" json:"-"`

	// Evaluators is the registry the OpenTDF authorization service
	// registers its in-process policy evaluator with, so the platform's
	// enforcement points reach the PDP without an RPC hop.
	Evaluators *authz.EvaluatorRegistry `mapstructure:"-" json:"-"`
}

// AuthNConfig is the configuration need for the platform to validate tokens
type AuthNConfig struct { //nolint:revive // AuthNConfig is a valid name
	EnforceDPoP  bool          `mapstructure:"enforceDPoP" json:"enforceDPoP" default:"false"`
	Issuer       string        `mapstructure:"issuer" json:"issuer"`
	Audience     string        `mapstructure:"audience" json:"audience"`
	Policy       PolicyConfig  `mapstructure:"policy" json:"policy"`
	CacheRefresh string        `mapstructure:"cache_refresh_interval" json:"cache_refresh_interval"`
	DPoPSkew     time.Duration `mapstructure:"dpopskew" json:"dpopskew" default:"1h"`
	TokenSkew    time.Duration `mapstructure:"skew" json:"skew" default:"1m"`
}

// PolicyConfig configures the platform's authorization decisions: how a
// subject is derived from a token, which grants the platform starts from,
// and whether platform operations are governed by the policy graph itself.
type PolicyConfig struct {
	// Builtin replaces the embedded default grant table. Set
	// programmatically via server.WithBuiltinAuthZPolicy.
	Builtin string `mapstructure:"-" json:"-"`
	// Username claim to use for user information
	UserNameClaim string `mapstructure:"username_claim" json:"username_claim" default:"preferred_username"`
	// Claim to use for group/role information
	GroupsClaim string `mapstructure:"groups_claim" json:"groups_claim" default:"realm_access.roles"`
	// Role provider configuration (resolved via StartOptions)
	RolesProvider RolesProviderConfig `mapstructure:"roles_provider" json:"roles_provider"`
	// Claim to use to reference idP clientID
	ClientIDClaim string `mapstructure:"client_id_claim" json:"client_id_claim" default:"azp"`
	// Deprecated: Use GroupsClaim instead
	RoleClaim string `mapstructure:"claim" json:"claim" default:"realm_access.roles"`
	// RoleMap binds a platform role (key) to an idP group identifier
	// (value). Equivalent to a `bindings` entry in the grant table.
	RoleMap map[string]string `mapstructure:"map" json:"map"`
	// Grants replaces the built-in grant table. Accepts the YAML grant
	// form or the legacy comma-separated policy lines.
	Grants string `mapstructure:"grants" json:"grants"`
	// Deprecated: Use Grants. Retained so existing configuration keeps
	// working; the legacy policy lines are translated into grants.
	Csv string `mapstructure:"csv" json:"csv"`
	// Extension extends the grant table in force. Accepts either form.
	Extension string `mapstructure:"extension" json:"extension"`
	// Bootstrap configures the cryptographic root of trust that can
	// authorize the small set of operations which would otherwise depend
	// on the policy they are about to change.
	Bootstrap authzen.BootstrapConfig `mapstructure:"bootstrap" json:"bootstrap"`
	// EndpointPolicy governs platform API operations with the policy graph
	// itself, representing each endpoint as a registered resource.
	EndpointPolicy authzen.EndpointPolicyConfig `mapstructure:"endpoint_policy" json:"endpoint_policy"`
	// AuthZEN exposes the PDP over the AuthZEN Authorization API.
	AuthZEN EvaluationAPIConfig `mapstructure:"authzen" json:"authzen"`
}

// EvaluationAPIConfig controls the public AuthZEN evaluation endpoints.
type EvaluationAPIConfig struct {
	Enabled bool `mapstructure:"enabled" json:"enabled" default:"true"`
}

type RolesProviderConfig struct {
	Name   string         `mapstructure:"name" json:"name"`
	Config map[string]any `mapstructure:"config" json:"config"`
}

// GrantSources renders the configured grant inputs for the engine.
func (c PolicyConfig) GrantSources() authzen.GrantSources {
	grants := c.Grants
	if grants == "" {
		grants = c.Csv
	}
	return authzen.GrantSources{
		Builtin:   c.Builtin,
		Grants:    grants,
		Extension: c.Extension,
		RoleMap:   c.RoleMap,
	}
}

func (c AuthNConfig) validateAuthNConfig(logger *logger.Logger) error {
	if c.Issuer == "" {
		return errors.New("config Auth.Issuer is required")
	}

	if c.Audience == "" {
		return errors.New("config Auth.Audience is required")
	}

	if !c.EnforceDPoP {
		logger.Warn("config Auth.EnforceDPoP is false. DPoP will not be enforced.")
	}

	return nil
}
