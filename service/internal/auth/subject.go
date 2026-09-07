package auth

import (
	"context"
	"log/slog"
	"net/http"

	"github.com/lestrrat-go/jwx/v2/jwt"

	"github.com/opentdf/platform/service/internal/authzen"
	"github.com/opentdf/platform/service/logger"
	ctxAuth "github.com/opentdf/platform/service/pkg/auth"
	"github.com/opentdf/platform/service/pkg/authz"
)

// subjectResolver derives the SARC subject the PDP reasons about from a
// verified token. Everything the PDP is told about a caller — identity,
// roles, root capabilities — originates here, from claims the platform
// itself verified; nothing is taken from the request body.
type subjectResolver struct {
	policy       PolicyConfig
	roleProvider authz.RoleProvider
	engine       *authzen.Engine
	logger       *logger.Logger
}

// contextualize fills in the subject and context of a decision request from
// a verified token.
func (a *Authentication) contextualize(ctx context.Context, token jwt.Token, req *authz.DecisionRequest) error {
	subject, err := a.subjects().resolve(ctx, token, authz.RoleRequest{
		Issuer:   a.oidcConfiguration.Issuer,
		Resource: req.Resource.ID,
		Action:   req.Action.Name,
	})
	if err != nil {
		return err
	}
	req.Subject = subject
	req.Context.Issuer = tokenIssuer(token, a.oidcConfiguration.Issuer)
	return nil
}

func (a *Authentication) subjects() subjectResolver {
	return subjectResolver{
		policy:       a.oidcConfiguration.Policy,
		roleProvider: a.roleProvider,
		engine:       a.pdp,
		logger:       a.logger,
	}
}

// resolve derives the SARC subject from a verified token.
func (r subjectResolver) resolve(ctx context.Context, token jwt.Token, roleReq authz.RoleRequest) (authz.Subject, error) {
	s := authz.Subject{
		Type:     authz.SubjectTypeUser,
		Token:    token,
		TokenRaw: ctxAuth.GetRawAccessTokenFromContext(ctx, r.logger),
	}
	if token == nil {
		s.Type = authz.SubjectTypeUnknown
		return s, nil
	}

	if r.roleProvider != nil {
		roles, err := r.roleProvider.Roles(ctx, token, roleReq)
		if err != nil {
			r.logger.WarnContext(ctx, "role provider error", slog.Any("error", err))
			return s, ErrPermissionDenied
		}
		s.Roles = roles
	}

	if claim, found := token.Get(r.policy.UserNameClaim); found {
		username, ok := claim.(string)
		if !ok {
			r.logger.WarnContext(ctx, "username claim not of type string",
				slog.String("claim", r.policy.UserNameClaim),
			)
		}
		s.ID = username
	}

	if clientID, err := clientIDFromToken(ctx, token, r.policy.ClientIDClaim); err == nil {
		s.ClientID = clientID
	}
	if s.ID == "" {
		s.ID = s.ClientID
		s.Type = authz.SubjectTypeClient
	}

	// Root capabilities are only read when a bootstrap authority is
	// configured, and are only honored by the engine when the token's
	// issuer is one of them.
	if r.engine.BootstrapEnabled() && r.engine.TrustsBootstrapIssuer(token.Issuer()) {
		if claim, found := token.Get(r.engine.CapabilitiesClaim()); found {
			s.Capabilities = authzen.CapabilitiesFromClaim(claim)
		}
	}

	return s, nil
}

// SubjectFromContext resolves the authenticated caller from a request
// context. Used by the AuthZEN endpoint, which is reached after the
// authentication middleware has run.
func (a *Authentication) SubjectFromContext(ctx context.Context) authz.Subject {
	token := ctxAuth.GetAccessTokenFromContext(ctx, a.logger)
	if token == nil {
		return authz.Subject{Type: authz.SubjectTypeUnknown}
	}
	subject, err := a.subjects().resolve(ctx, token, authz.RoleRequest{Issuer: a.oidcConfiguration.Issuer})
	if err != nil {
		return authz.Subject{Type: authz.SubjectTypeUnknown, Token: token}
	}
	return subject
}

// Evaluators returns the registry the OpenTDF authorization service uses to
// publish its in-process policy evaluator to the platform's enforcement
// points.
func (a *Authentication) Evaluators() *authz.EvaluatorRegistry {
	if a == nil {
		return nil
	}
	return a.evaluators
}

// PDP returns the platform's policy decision point.
func (a *Authentication) PDP() authz.PDP {
	if a == nil {
		return nil
	}
	return a.pdp
}

// MountAuthZEN registers the AuthZEN Authorization API on a mux, when it is
// enabled. The routes sit behind the platform's authentication middleware
// and are themselves authorized like any other endpoint.
func (a *Authentication) MountAuthZEN(mux *http.ServeMux) bool {
	if a == nil || a.authzenAPI == nil || mux == nil {
		return false
	}
	a.authzenAPI.Mount(mux)
	return true
}

func tokenIssuer(token jwt.Token, fallback string) string {
	if token == nil || token.Issuer() == "" {
		return fallback
	}
	return token.Issuer()
}
