package patreon

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"strconv"
	"strings"

	"connectrpc.com/connect"
	"github.com/go-viper/mapstructure/v2"
	"github.com/lestrrat-go/jwx/v2/jwt"
	"github.com/opentdf/platform/protocol/go/entity"
	entityresolutionV2 "github.com/opentdf/platform/protocol/go/entityresolution/v2"
	ent "github.com/opentdf/platform/service/entity"
	"github.com/opentdf/platform/service/logger"
	"github.com/opentdf/platform/service/pkg/config"
	"github.com/opentdf/platform/service/pkg/serviceregistry"
	"go.opentelemetry.io/otel/trace"
	"google.golang.org/protobuf/types/known/anypb"
	"google.golang.org/protobuf/types/known/structpb"
)

// Default JWT claim names used to locate the Patreon identity on inbound
// tokens. Overridable via Config.JWT.*.
const (
	defaultPatreonUserIDClaim = "patreon_user_id"
	defaultUsernameClaim      = "preferred_username"
	defaultClientIDClaim      = "azp"
	defaultPatreonTokenClaim  = "patreon_access_token"
)

// Config configures the Patreon entity resolution provider.
type Config struct {
	APIBase            string    `mapstructure:"api_base" json:"api_base"`
	TokenURL           string    `mapstructure:"token_url" json:"token_url"`
	ClientID           string    `mapstructure:"client_id" json:"client_id"`
	ClientSecret       string    `mapstructure:"client_secret" json:"client_secret"`
	CreatorAccessToken string    `mapstructure:"creator_access_token" json:"creator_access_token"`
	CampaignIDs        []string  `mapstructure:"campaign_ids" json:"campaign_ids"`
	JWT                JWTConfig `mapstructure:"jwt" json:"jwt"`
	// InferUnknownAsFree returns a free-tier membership instead of an error
	// when the subject can't be matched in Patreon. Useful so unauthenticated
	// or non-Patreon traffic still flows through subject mappings.
	InferUnknownAsFree bool `mapstructure:"infer_unknown_as_free" json:"infer_unknown_as_free"`
}

// JWTConfig customizes which JWT claims the provider reads.
type JWTConfig struct {
	PatreonUserIDClaim string `mapstructure:"patreon_user_id_claim" json:"patreon_user_id_claim"`
	UsernameClaim      string `mapstructure:"username_claim" json:"username_claim"`
	ClientIDClaim      string `mapstructure:"client_id_claim" json:"client_id_claim"`
	PatreonTokenClaim  string `mapstructure:"patreon_access_token_claim" json:"patreon_access_token_claim"`
}

// LogValue redacts secrets from log output.
func (c Config) LogValue() slog.Value {
	return slog.GroupValue(
		slog.String("api_base", c.APIBase),
		slog.String("token_url", c.TokenURL),
		slog.String("client_id", c.ClientID),
		slog.String("client_secret", redact(c.ClientSecret)),
		slog.String("creator_access_token", redact(c.CreatorAccessToken)),
		slog.Any("campaign_ids", c.CampaignIDs),
		slog.Bool("infer_unknown_as_free", c.InferUnknownAsFree),
	)
}

func redact(s string) string {
	if s == "" {
		return ""
	}
	return "[REDACTED]"
}

// EntityResolutionService is the v2 Patreon entity resolver.
type EntityResolutionService struct {
	entityresolutionV2.UnimplementedEntityResolutionServiceServer
	cfg    Config
	client MembershipAPI
	logger *logger.Logger
	trace.Tracer
}

// MembershipAPI is the subset of *Client the resolver depends on (extracted
// for unit testing).
type MembershipAPI interface {
	ResolveByUserID(ctx context.Context, userID string) (*Membership, error)
	ResolveByEmail(ctx context.Context, email string) (*Membership, error)
	ResolveSelf(ctx context.Context, userAccessToken string) (*Membership, error)
}

// RegisterPatreonERS adapts the Patreon ERS to the platform serviceregistry.
func RegisterPatreonERS(cfg config.ServiceConfig, log *logger.Logger) (*EntityResolutionService, serviceregistry.HandlerServer) {
	var c Config
	if err := mapstructure.Decode(cfg, &c); err != nil {
		log.Error("failed to decode patreon entity resolution config", slog.Any("error", err))
		panic(fmt.Sprintf("failed to decode patreon entity resolution config: %v", err))
	}
	applyJWTDefaults(&c.JWT)
	log.Debug("patreon entity resolution configuration", slog.Any("config", c))

	client := NewClient(ClientOptions{
		APIBase:            c.APIBase,
		TokenURL:           c.TokenURL,
		ClientID:           c.ClientID,
		ClientSecret:       c.ClientSecret,
		CreatorAccessToken: c.CreatorAccessToken,
		CampaignIDs:        c.CampaignIDs,
	})
	return &EntityResolutionService{cfg: c, client: client, logger: log}, nil
}

// NewERSWithClient is the test-friendly constructor.
func NewERSWithClient(cfg Config, client MembershipAPI, log *logger.Logger) *EntityResolutionService {
	applyJWTDefaults(&cfg.JWT)
	return &EntityResolutionService{cfg: cfg, client: client, logger: log}
}

func applyJWTDefaults(j *JWTConfig) {
	if j.PatreonUserIDClaim == "" {
		j.PatreonUserIDClaim = defaultPatreonUserIDClaim
	}
	if j.UsernameClaim == "" {
		j.UsernameClaim = defaultUsernameClaim
	}
	if j.ClientIDClaim == "" {
		j.ClientIDClaim = defaultClientIDClaim
	}
	if j.PatreonTokenClaim == "" {
		j.PatreonTokenClaim = defaultPatreonTokenClaim
	}
}

// ResolveEntities looks each requested entity up in Patreon and returns the
// resolved membership wrapped as additional claims under a "patreon" key,
// matching the .patreon.* selectors used by subject mappings.
func (s *EntityResolutionService) ResolveEntities(
	ctx context.Context,
	req *connect.Request[entityresolutionV2.ResolveEntitiesRequest],
) (*connect.Response[entityresolutionV2.ResolveEntitiesResponse], error) {
	ctx, span := s.Start(ctx, "ResolveEntities")
	defer span.End()

	payload := req.Msg.GetEntities()
	resolved := make([]*entityresolutionV2.EntityRepresentation, 0, len(payload))

	for idx, ident := range payload {
		originalID := ident.GetEphemeralId()
		if originalID == "" {
			originalID = ent.EntityIDPrefix + strconv.Itoa(idx)
		}

		mem, err := s.resolveEntity(ctx, ident)
		if err != nil {
			if errors.Is(err, ErrMemberNotFound) && s.cfg.InferUnknownAsFree {
				mem = freeMembership(ident)
			} else {
				s.logger.WarnContext(ctx, "patreon resolve failed",
					slog.String("entity_id", originalID),
					slog.String("error", err.Error()))
				return nil, connect.NewError(connectCodeFor(err), err)
			}
		}

		repr, err := membershipToRepresentation(originalID, mem)
		if err != nil {
			return nil, connect.NewError(connect.CodeInternal, err)
		}
		resolved = append(resolved, repr)
	}

	return connect.NewResponse(&entityresolutionV2.ResolveEntitiesResponse{
		EntityRepresentations: resolved,
	}), nil
}

// CreateEntityChainsFromTokens builds an entity chain per JWT: an environment
// entity for the client id and a subject entity carrying the user's Patreon
// membership claims (resolved via the JWT's identity hints).
func (s *EntityResolutionService) CreateEntityChainsFromTokens(
	ctx context.Context,
	req *connect.Request[entityresolutionV2.CreateEntityChainsFromTokensRequest],
) (*connect.Response[entityresolutionV2.CreateEntityChainsFromTokensResponse], error) {
	ctx, span := s.Start(ctx, "CreateEntityChainsFromTokens")
	defer span.End()

	chains := make([]*entity.EntityChain, 0, len(req.Msg.GetTokens()))
	for _, tok := range req.Msg.GetTokens() {
		entities, err := s.entitiesFromToken(ctx, tok.GetJwt())
		if err != nil {
			return nil, connect.NewError(connect.CodeInternal, err)
		}
		chains = append(chains, &entity.EntityChain{
			EphemeralId: tok.GetEphemeralId(),
			Entities:    entities,
		})
	}
	return connect.NewResponse(&entityresolutionV2.CreateEntityChainsFromTokensResponse{
		EntityChains: chains,
	}), nil
}

func (s *EntityResolutionService) entitiesFromToken(ctx context.Context, jwtString string) ([]*entity.Entity, error) {
	parsed, err := jwt.ParseString(jwtString, jwt.WithVerify(false), jwt.WithValidate(false))
	if err != nil {
		return nil, fmt.Errorf("parse jwt: %w", err)
	}
	claims, err := parsed.AsMap(ctx)
	if err != nil {
		return nil, fmt.Errorf("read jwt claims: %w", err)
	}

	out := []*entity.Entity{}
	if v, ok := claims[s.cfg.JWT.ClientIDClaim].(string); ok && v != "" {
		out = append(out, &entity.Entity{
			EntityType:  &entity.Entity_ClientId{ClientId: v},
			EphemeralId: "patreon-clientid-" + v,
			Category:    entity.Entity_CATEGORY_ENVIRONMENT,
		})
	}

	mem, err := s.resolveFromClaims(ctx, claims)
	switch {
	case errors.Is(err, ErrMemberNotFound) && s.cfg.InferUnknownAsFree:
		mem = &Membership{TierSlug: "free", Status: "former"}
	case err != nil:
		return nil, err
	}

	patreonStruct, err := membershipStruct(mem)
	if err != nil {
		return nil, err
	}
	subjectClaims, err := structpb.NewStruct(map[string]interface{}{
		"patreon": patreonStruct.AsMap(),
	})
	if err != nil {
		return nil, err
	}
	anyClaims, err := anypb.New(subjectClaims)
	if err != nil {
		return nil, err
	}
	id := mem.UserID
	if id == "" {
		id = mem.Email
	}
	if id == "" {
		id = "anonymous"
	}
	out = append(out, &entity.Entity{
		EntityType:  &entity.Entity_Claims{Claims: anyClaims},
		EphemeralId: "patreon-subject-" + id,
		Category:    entity.Entity_CATEGORY_SUBJECT,
	})
	return out, nil
}

// resolveEntity routes a single ResolveEntities request entry through the
// best lookup strategy for its type.
func (s *EntityResolutionService) resolveEntity(ctx context.Context, e *entity.Entity) (*Membership, error) {
	switch et := e.GetEntityType().(type) {
	case *entity.Entity_UserName:
		return s.client.ResolveByUserID(ctx, et.UserName)
	case *entity.Entity_EmailAddress:
		return s.client.ResolveByEmail(ctx, et.EmailAddress)
	case *entity.Entity_ClientId:
		// Treat client id as a Patreon user id (callers can override claims).
		return s.client.ResolveByUserID(ctx, et.ClientId)
	case *entity.Entity_Claims:
		var asStruct structpb.Struct
		if err := e.GetClaims().UnmarshalTo(&asStruct); err != nil {
			return nil, fmt.Errorf("unpack claims: %w", err)
		}
		return s.resolveFromClaims(ctx, asStruct.AsMap())
	default:
		return nil, fmt.Errorf("%w: unsupported entity type %T", ErrMemberNotFound, et)
	}
}

func (s *EntityResolutionService) resolveFromClaims(ctx context.Context, claims map[string]interface{}) (*Membership, error) {
	if tok, ok := claims[s.cfg.JWT.PatreonTokenClaim].(string); ok && tok != "" {
		return s.client.ResolveSelf(ctx, tok)
	}
	if uid, ok := claims[s.cfg.JWT.PatreonUserIDClaim].(string); ok && uid != "" {
		return s.client.ResolveByUserID(ctx, uid)
	}
	if email, ok := claims["email"].(string); ok && email != "" {
		return s.client.ResolveByEmail(ctx, email)
	}
	if username, ok := claims[s.cfg.JWT.UsernameClaim].(string); ok && username != "" {
		if strings.Contains(username, "@") {
			return s.client.ResolveByEmail(ctx, username)
		}
		return s.client.ResolveByUserID(ctx, username)
	}
	return nil, ErrMemberNotFound
}

// freeMembership returns a synthetic free-tier membership tied to the
// caller identity, used when InferUnknownAsFree is set.
func freeMembership(e *entity.Entity) *Membership {
	mem := &Membership{TierSlug: "free", Status: "former"}
	switch et := e.GetEntityType().(type) {
	case *entity.Entity_UserName:
		mem.UserID = et.UserName
	case *entity.Entity_EmailAddress:
		mem.Email = et.EmailAddress
	}
	return mem
}

func membershipStruct(mem *Membership) (*structpb.Struct, error) {
	m := map[string]interface{}{
		"user_id":           mem.UserID,
		"email":             mem.Email,
		"full_name":         mem.FullName,
		"status":            mem.Status,
		"tier_slug":         mem.TierSlug,
		"tier_amount_cents": mem.TierAmount,
		"campaign_ids":      toIfaceSlice(mem.CampaignIDs),
		"benefits":          toIfaceSlice(mem.Benefits),
	}
	if mem.PledgeStart != "" {
		m["pledge_start"] = mem.PledgeStart
	}
	if mem.LastChargeAt != "" {
		m["last_charge_at"] = mem.LastChargeAt
	}
	return structpb.NewStruct(m)
}

func membershipToRepresentation(originalID string, mem *Membership) (*entityresolutionV2.EntityRepresentation, error) {
	patreonStruct, err := membershipStruct(mem)
	if err != nil {
		return nil, err
	}
	wrapped, err := structpb.NewStruct(map[string]interface{}{
		"patreon": patreonStruct.AsMap(),
		"id":      mem.UserID,
		"email":   mem.Email,
	})
	if err != nil {
		return nil, err
	}
	return &entityresolutionV2.EntityRepresentation{
		OriginalId:      originalID,
		AdditionalProps: []*structpb.Struct{wrapped},
	}, nil
}

func toIfaceSlice(in []string) []interface{} {
	out := make([]interface{}, len(in))
	for i, v := range in {
		out[i] = v
	}
	return out
}

func connectCodeFor(err error) connect.Code {
	switch {
	case errors.Is(err, ErrMemberNotFound):
		return connect.CodeNotFound
	case errors.Is(err, ErrPatreonUnavailable):
		return connect.CodeUnavailable
	default:
		return connect.CodeInternal
	}
}
