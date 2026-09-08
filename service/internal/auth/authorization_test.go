package auth

import (
	"context"
	"fmt"
	"strings"
	"testing"

	"github.com/creasty/defaults"
	"github.com/lestrrat-go/jwx/v2/jwt"
	"github.com/stretchr/testify/require"
	"github.com/stretchr/testify/suite"

	"github.com/opentdf/platform/service/internal/authzen"
	"github.com/opentdf/platform/service/logger"
	"github.com/opentdf/platform/service/pkg/authz"
)

// AuthorizationSuite covers endpoint authorization end to end: a verified
// token becomes a SARC subject, and the platform PDP answers whether that
// subject may invoke an operation.
type AuthorizationSuite struct {
	suite.Suite
}

func TestAuthorizationSuite(t *testing.T) {
	suite.Run(t, new(AuthorizationSuite))
}

type staticProvider struct {
	roles []string
	err   error
}

func (p staticProvider) Roles(_ context.Context, _ jwt.Token, _ authz.RoleRequest) ([]string, error) {
	return p.roles, p.err
}

func (s *AuthorizationSuite) Test_DefaultGrantsAreLoadable() {
	grants, err := authzen.DefaultGrants()
	s.Require().NoError(err)
	s.NotEmpty(grants.Grants)
	s.NotEmpty(grants.Bindings)
	s.Require().NoError(grants.Validate())
}

func (s *AuthorizationSuite) Test_Enforcement() {
	admin := []bool{true, false}
	standard := []bool{false, true}
	unknown := []bool{false, false}

	tests := []struct {
		allowed  bool
		roles    []bool
		resource string
		action   string
	}{
		// admin role
		{allowed: true, roles: admin, resource: "policy.attributes.DoSomething", action: "read"},
		{allowed: true, roles: admin, resource: "policy.attributes.DoSomething", action: "write"},
		{allowed: true, roles: admin, resource: "non-existent", action: "read"},

		// standard role
		{allowed: true, roles: standard, resource: "policy.attributes.DoSomething", action: "read"},
		{allowed: false, roles: standard, resource: "policy.attributes.DoSomething", action: "write"},
		{allowed: false, roles: standard, resource: "non-existent", action: "read"},
		{allowed: true, roles: standard, resource: "authorization.AuthorizationService/GetDecisions", action: "read"},
		{allowed: true, roles: standard, resource: "authorization.AuthorizationService/GetDecisionsByToken", action: "read"},
		{allowed: true, roles: standard, resource: "authorization.v2.AuthorizationService/GetDecision", action: "read"},
		{allowed: true, roles: standard, resource: "/access/v1/evaluation", action: "write"},

		// key access is decided on the data, not the caller's platform role
		{allowed: true, roles: standard, resource: "kas.AccessService/Rewrap", action: "other"},
		{allowed: true, roles: unknown, resource: "kas.AccessService/Rewrap", action: "other"},

		// undefined role
		{allowed: false, roles: unknown, resource: "policy.attributes.DoSomething", action: "read"},
		{allowed: false, roles: unknown, resource: "policy.attributes.DoSomething", action: "write"},
		{allowed: false, roles: unknown, resource: "non-existent", action: "read"},
		{allowed: false, roles: unknown, resource: "/access/v1/evaluation", action: "write"},
	}

	for _, test := range tests {
		var actor string
		switch {
		case test.roles[0]:
			actor = "admin"
		case test.roles[1]:
			actor = "standard"
		default:
			actor = "undefined"
		}
		name := fmt.Sprintf("%s may _%s_ %s: %t", actor, test.action, test.resource, test.allowed)

		s.Run(name, func() {
			cfg := s.defaultPolicyConfig()
			engine, resolver := s.newPDP(cfg, nil)
			tok := s.tokenWithRoles(test.roles[0], test.roles[1], "", "")
			s.Equal(test.allowed, s.decide(engine, resolver, tok, test.resource, test.action))
		})
	}
}

func (s *AuthorizationSuite) Test_ExtendGrants_YAML() {
	cfg := s.defaultPolicyConfig()
	cfg.Extension = `
grants:
  - subjects: ["role:standard"]
    resources: ["new.service.*"]
    actions: ["read"]
bindings:
  - subject: opentdf-admin
    role: admin
  - subject: opentdf-standard
    role: standard
`
	engine, resolver := s.newPDP(cfg, nil)

	adminTok := s.tokenWithRoles(true, false, "", "")
	s.True(s.decide(engine, resolver, adminTok, "new.service.DoSomething", "read"))
	s.True(s.decide(engine, resolver, adminTok, "new.service.DoSomething", "write"))

	standardTok := s.tokenWithRoles(false, true, "", "")
	s.True(s.decide(engine, resolver, standardTok, "new.service.DoSomething", "read"))
	s.False(s.decide(engine, resolver, standardTok, "new.service.DoSomething", "write"))
}

// Configuration written against the platform's previous policy format must
// keep working: the lines are translated into grants at startup.
func (s *AuthorizationSuite) Test_ExtendGrants_LegacyLines() {
	cfg := s.defaultPolicyConfig()
	cfg.Extension = strings.Join([]string{
		"p, role:standard, new.service.*, read, allow",
		"g, opentdf-admin, role:admin",
		"g, opentdf-standard, role:standard",
	}, "\n")
	engine, resolver := s.newPDP(cfg, nil)

	adminTok := s.tokenWithRoles(true, false, "", "")
	s.True(s.decide(engine, resolver, adminTok, "new.service.DoSomething", "read"))
	s.True(s.decide(engine, resolver, adminTok, "new.service.DoSomething", "write"))

	standardTok := s.tokenWithRoles(false, true, "", "")
	s.True(s.decide(engine, resolver, standardTok, "new.service.DoSomething", "read"))
	s.False(s.decide(engine, resolver, standardTok, "new.service.DoSomething", "write"))
}

func (s *AuthorizationSuite) Test_LegacyDenyStillWins() {
	cfg := s.defaultPolicyConfig()
	cfg.Csv = strings.Join([]string{
		"p, role:admin, new.hello.*, *, allow",
		"p, role:standard, new.hello.*, read, allow",
		"p, role:standard, new.hello.*, write, deny",
		"g, opentdf-admin, role:admin",
		"g, opentdf-standard, role:standard",
	}, "\n")
	engine, resolver := s.newPDP(cfg, nil)

	adminTok := s.tokenWithRoles(true, false, "", "")
	s.True(s.decide(engine, resolver, adminTok, "new.hello.World", "write"))

	standardTok := s.tokenWithRoles(false, true, "", "")
	s.True(s.decide(engine, resolver, standardTok, "new.hello.World", "read"))
	s.False(s.decide(engine, resolver, standardTok, "new.hello.World", "write"))

	// the replaced table no longer grants the platform defaults
	s.False(s.decide(engine, resolver, standardTok, "policy.attributes.List", "read"))
}

func (s *AuthorizationSuite) Test_UsernameGrant() {
	cfg := s.defaultPolicyConfig()
	cfg.Extension = "p, platform-user, new.service.*, read, allow"
	engine, resolver := s.newPDP(cfg, nil)

	tok := s.tokenWithRoles(true, false, "preferred_username", "")
	s.True(s.decide(engine, resolver, tok, "new.service.DoSomething", "read"))
	// an operator-stated grant table replaces the default group bindings,
	// so membership of opentdf-admin no longer implies administration
	s.False(s.decide(engine, resolver, tok, "policy.attributes.List", "read"))
}

func (s *AuthorizationSuite) Test_ExternalRoleProvider() {
	cfg := s.defaultPolicyConfig()
	cfg.Extension = "p, role:admin, policy.attributes.*, read, allow"
	engine, resolver := s.newPDP(cfg, staticProvider{roles: []string{"role:admin"}})

	s.True(s.decide(engine, resolver, jwt.New(), "policy.attributes.List", "read"))
}

// A role provider that cannot be reached refuses the request, but it is an
// outage rather than a denial and must be distinguishable as one.
func (s *AuthorizationSuite) Test_RoleProviderErrorIsNotADenial() {
	cfg := s.defaultPolicyConfig()
	engine, resolver := s.newPDP(cfg, staticProvider{err: context.DeadlineExceeded})

	allowed, err := s.decideE(engine, resolver, jwt.New(), "policy.attributes.List", "read")
	s.False(allowed)
	s.Require().ErrorIs(err, ErrSubjectResolution)
	s.Require().ErrorIs(err, context.DeadlineExceeded)
	s.Require().NotErrorIs(err, ErrPermissionDenied)
}

func (s *AuthorizationSuite) Test_RoleMapBindsGroups() {
	cfg := s.defaultPolicyConfig()
	cfg.RoleMap = map[string]string{"admin": "test-admin"}
	engine, resolver := s.newPDP(cfg, nil)

	tok := jwt.New()
	s.Require().NoError(tok.Set("realm_access", map[string]any{"roles": []any{"test-admin"}}))
	s.True(s.decide(engine, resolver, tok, "policy.attributes.List", "write"))

	// the default group bindings step aside once the operator states theirs
	defaultTok := s.tokenWithRoles(true, false, "", "")
	s.False(s.decide(engine, resolver, defaultTok, "policy.attributes.List", "write"))
}

func (s *AuthorizationSuite) Test_OverrideOfUsernameClaim() {
	cfg := s.defaultPolicyConfig()
	cfg.UserNameClaim = "username"
	cfg.Extension = "p, platform-user, new.service.*, read, allow"
	engine, resolver := s.newPDP(cfg, nil)

	tok := s.tokenWithRoles(true, false, "username", "")
	s.True(s.decide(engine, resolver, tok, "new.service.DoSomething", "read"))
	s.False(s.decide(engine, resolver, tok, "policy.attributes.List", "read"))
}

func (s *AuthorizationSuite) Test_OverrideOfGroupsClaim() {
	cfg := s.defaultPolicyConfig()
	cfg.GroupsClaim = "realm_access.groups"
	engine, resolver := s.newPDP(cfg, nil)

	tok := s.tokenWithRoles(false, true, "", "groups")
	s.False(s.decide(engine, resolver, tok, "new.service.DoSomething", "read"))
	s.True(s.decide(engine, resolver, tok, "policy.attributes.List", "read"))
}

func (s *AuthorizationSuite) Test_MalformedGrantsAreRejected() {
	cfg := s.defaultPolicyConfig()
	cfg.Grants = "grants:\n  - subjects: [\"role:admin\"]\n"
	_, err := authzen.BuildGrantSet(cfg.GrantSources())
	s.Require().Error(err)
}

// Bootstrap capabilities are only honored for a configured root authority,
// and only for the operations the capability covers.
func (s *AuthorizationSuite) Test_BootstrapRootOfTrust() {
	const rootIssuer = "https://root.example.com"

	cfg := s.defaultPolicyConfig()
	cfg.Bootstrap = authzen.BootstrapConfig{
		Enabled:             true,
		Issuers:             []string{rootIssuer},
		CapabilitiesClaim:   authzen.DefaultCapabilitiesClaim,
		RequireConfirmation: false,
	}
	engine, resolver := s.newPDP(cfg, nil)

	rootTok := jwt.New()
	s.Require().NoError(rootTok.Set(jwt.IssuerKey, rootIssuer))
	s.Require().NoError(rootTok.Set(authzen.DefaultCapabilitiesClaim, []any{authzen.CapabilityPolicyBootstrap}))

	// the capability covers seeding the policy graph
	s.True(s.decide(engine, resolver, rootTok, "policy.subjectmapping.SubjectMappingService/CreateSubjectMapping", "write"))
	// but not the KAS registry
	s.False(s.decide(engine, resolver, rootTok, "kasregistry.KeyAccessServerRegistryService/CreateKeyAccessServer", "write"))

	// the same claim from an untrusted issuer grants nothing
	impostor := jwt.New()
	s.Require().NoError(impostor.Set(jwt.IssuerKey, "https://not-the-root.example.com"))
	s.Require().NoError(impostor.Set(authzen.DefaultCapabilitiesClaim, []any{authzen.CapabilityPolicyAdmin}))
	s.False(s.decide(engine, resolver, impostor, "policy.attributes.AttributeService/CreateAttribute", "write"))
}

func (s *AuthorizationSuite) Test_BootstrapRequiresKeyBinding() {
	const rootIssuer = "https://root.example.com"

	cfg := s.defaultPolicyConfig()
	cfg.Bootstrap = authzen.BootstrapConfig{
		Enabled:             true,
		Issuers:             []string{rootIssuer},
		RequireConfirmation: true,
	}
	engine, resolver := s.newPDP(cfg, nil)

	bearer := jwt.New()
	s.Require().NoError(bearer.Set(jwt.IssuerKey, rootIssuer))
	s.Require().NoError(bearer.Set(authzen.DefaultCapabilitiesClaim, []any{authzen.CapabilityPolicyAdmin}))
	s.False(s.decide(engine, resolver, bearer, "policy.attributes.AttributeService/CreateAttribute", "write"))

	keyBound := jwt.New()
	s.Require().NoError(keyBound.Set(jwt.IssuerKey, rootIssuer))
	s.Require().NoError(keyBound.Set(authzen.DefaultCapabilitiesClaim, []any{authzen.CapabilityPolicyAdmin}))
	s.Require().NoError(keyBound.Set("cnf", map[string]any{"jkt": "abc"}))
	s.True(s.decide(engine, resolver, keyBound, "policy.attributes.AttributeService/CreateAttribute", "write"))
}

func (s *AuthorizationSuite) Test_BootstrapRequiresIssuer() {
	_, err := authzen.NewBootstrap(authzen.BootstrapConfig{Enabled: true})
	s.Require().ErrorIs(err, authzen.ErrBootstrapIssuerRequired)
}

// newPDP builds the engine and subject resolver a policy config produces.
func (s *AuthorizationSuite) newPDP(cfg PolicyConfig, provider authz.RoleProvider) (*authzen.Engine, subjectResolver) {
	s.T().Helper()
	log := logger.CreateTestLogger()

	grants, err := authzen.BuildGrantSet(cfg.GrantSources())
	s.Require().NoError(err)

	engine, err := authzen.NewEngine(authzen.Config{
		Grants:         grants,
		Bootstrap:      cfg.Bootstrap,
		EndpointPolicy: cfg.EndpointPolicy,
		Logger:         log,
	})
	s.Require().NoError(err)

	if provider == nil {
		provider = newJWTClaimsRoleProvider(cfg.GroupsClaim, log)
	}
	return engine, subjectResolver{
		policy:       cfg,
		roleProvider: provider,
		engine:       engine,
		logger:       log,
	}
}

func (s *AuthorizationSuite) decide(engine *authzen.Engine, resolver subjectResolver, tok jwt.Token, resource, action string) bool {
	s.T().Helper()
	allowed, err := s.decideE(engine, resolver, tok, resource, action)
	s.Require().NoError(err)
	return allowed
}

// decideE resolves the subject and asks the PDP, surfacing the error a
// caller would see.
func (s *AuthorizationSuite) decideE(engine *authzen.Engine, resolver subjectResolver, tok jwt.Token, resource, action string) (bool, error) {
	s.T().Helper()
	ctx := context.Background()
	subject, err := resolver.resolve(ctx, tok, authz.RoleRequest{Resource: resource, Action: action})
	if err != nil {
		return false, err
	}
	decision, err := engine.Decide(ctx, authz.DecisionRequest{
		Subject:  subject,
		Action:   authz.Action{Name: action},
		Resource: authz.Resource{Type: authz.ResourceTypeEndpoint, ID: resource},
		Context:  authz.RequestContext{Transport: authz.TransportConnect, Issuer: tok.Issuer()},
	})
	if err != nil {
		return false, err
	}
	return decision.Allowed(), nil
}

func (s *AuthorizationSuite) defaultPolicyConfig() PolicyConfig {
	s.T().Helper()
	cfg := PolicyConfig{}
	s.Require().NoError(defaults.Set(&cfg))
	return cfg
}

func (s *AuthorizationSuite) tokenWithRoles(admin, standard bool, usernameClaim, groupClaim string) jwt.Token {
	s.T().Helper()
	tok := jwt.New()

	if groupClaim == "" {
		groupClaim = "roles"
	}
	roles := make([]any, 0, 2)
	if admin {
		roles = append(roles, "opentdf-admin")
	}
	if standard {
		roles = append(roles, "opentdf-standard")
	}
	s.Require().NoError(tok.Set("realm_access", map[string]any{groupClaim: roles}))

	if usernameClaim != "" {
		s.Require().NoError(tok.Set(usernameClaim, "platform-user"))
	}
	return tok
}

func TestClientIDFromToken(t *testing.T) {
	tok := jwt.New()
	require.NoError(t, tok.Set("azp", "otdfctl"))

	clientID, err := clientIDFromToken(context.Background(), tok, "azp")
	require.NoError(t, err)
	require.Equal(t, "otdfctl", clientID)

	_, err = clientIDFromToken(context.Background(), tok, "")
	require.ErrorIs(t, err, ErrClientIDClaimNotConfigured)
}

func TestPolicyConfigDefaults(t *testing.T) {
	cfg := Config{}
	require.NoError(t, defaults.Set(&cfg))

	// The AuthZEN contract is on by default; the root of trust and
	// policy-governed endpoints are opt-in.
	require.True(t, cfg.Policy.AuthZEN.Enabled)
	require.False(t, cfg.Policy.Bootstrap.Enabled)
	require.True(t, cfg.Policy.Bootstrap.RequireConfirmation)
	require.Equal(t, authzen.DefaultCapabilitiesClaim, cfg.Policy.Bootstrap.CapabilitiesClaim)
	require.False(t, cfg.Policy.EndpointPolicy.Enabled)
	require.Equal(t, "endpoint", cfg.Policy.EndpointPolicy.ResourceName)
}

func TestGrantSourcesPrefersGrantsOverLegacyCsv(t *testing.T) {
	cfg := PolicyConfig{
		Grants: "grants: []",
		Csv:    "p, role:admin, *, *, allow",
	}
	require.Equal(t, "grants: []", cfg.GrantSources().Grants)

	legacyOnly := PolicyConfig{Csv: "p, role:admin, *, *, allow"}
	require.Equal(t, "p, role:admin, *, *, allow", legacyOnly.GrantSources().Grants)
}
