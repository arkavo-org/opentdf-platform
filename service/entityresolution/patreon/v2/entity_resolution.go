package patreon

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"strconv"

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
	// EntitlementsNamespace is the namespace for direct-entitlement FQNs
	// emitted by the claims-passthrough path (default patreon.arkavo.com).
	EntitlementsNamespace string    `mapstructure:"entitlements_namespace" json:"entitlements_namespace"`
	JWT                   JWTConfig `mapstructure:"jwt" json:"jwt"`
	// InferUnknownAsFree returns a free-tier membership instead of an error
	// when a subject carries no usable Patreon claim, so unauthenticated or
	// non-Patreon traffic still flows through subject mappings.
	InferUnknownAsFree bool `mapstructure:"infer_unknown_as_free" json:"infer_unknown_as_free"`
	// TrustMaterializedClaims enables the claims-passthrough path: when an
	// entity's claims already carry the arkavo_patreon materialization, emit
	// campaign-qualified direct entitlements from it WITHOUT calling Patreon.
	//
	// SECURITY — this is the real trust control, default false. The
	// materialized claim is honored as authoritative, so it must only ever
	// reach this provider through a cryptographically trusted channel:
	//   - the platform's own decision flow, where the subject token's
	//     signature was verified by the authn interceptor before the ERS
	//     re-parses it (and entitiesFromToken additionally pins the token's
	//     issuer to TrustedIssuer below); or
	//   - an entityChain submitted by a PEP that authenticated with a
	//     role:standard credential and is trusted to have verified the
	//     subject token itself (e.g. the catalog node, which verifies the
	//     consumer CWT before forwarding arkavo_patreon).
	// Leave false unless every decision caller satisfies one of those.
	TrustMaterializedClaims bool `mapstructure:"trust_materialized_claims" json:"trust_materialized_claims"`
	// TrustedIssuer, when set, is the issuer the materialized claim must
	// have been minted by. On the verified-token path the iss claim is
	// inside the signed token (non-forgeable), so this rejects a claim
	// carried by a token from any other IdP. Empty = no issuer check
	// (entityChain/claims path has no token iss to check; relies on the
	// PEP trust boundary above).
	TrustedIssuer string `mapstructure:"trusted_issuer" json:"trusted_issuer"`
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
		slog.String("entitlements_namespace", c.EntitlementsNamespace),
		slog.Bool("infer_unknown_as_free", c.InferUnknownAsFree),
		slog.Bool("trust_materialized_claims", c.TrustMaterializedClaims),
		slog.String("trusted_issuer", c.TrustedIssuer),
	)
}

// EntityResolutionService is the v2 Patreon entity resolver.
type EntityResolutionService struct {
	entityresolutionV2.UnimplementedEntityResolutionServiceServer
	cfg    Config
	logger *logger.Logger
	trace.Tracer
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

	if c.TrustMaterializedClaims && c.TrustedIssuer == "" {
		log.Warn("patreon: trust_materialized_claims is enabled with no trusted_issuer — " +
			"any signature-valid token from any IdP the platform accepts can inject " +
			"arkavo_patreon membership claims; set trusted_issuer to pin the materializer")
	}

	return &EntityResolutionService{cfg: c, logger: log}, nil
}

// NewERS is the test-friendly constructor.
func NewERS(cfg Config, log *logger.Logger) *EntityResolutionService {
	applyJWTDefaults(&cfg.JWT)
	return &EntityResolutionService{cfg: cfg, logger: log}
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

		res, err := s.resolveEntity(ctx, ident)
		if err != nil {
			if errors.Is(err, ErrMemberNotFound) && s.cfg.InferUnknownAsFree {
				res = &resolution{mem: freeMembership(ident)}
			} else {
				s.logger.WarnContext(ctx, "patreon resolve failed",
					slog.String("entity_id", originalID),
					slog.String("error", err.Error()))
				return nil, connect.NewError(connectCodeFor(err), err)
			}
		}

		repr, err := resolutionToRepresentation(originalID, res)
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

	// Honor the materialized claim only through a trusted channel. Drop it
	// up front when trust is off or the token's verified issuer is not the
	// pinned one, so NEITHER the flattened patreon.* view (derived just
	// below) NOR the re-preserved claim for the second pass can come from an
	// untrusted issuer. The iss lives inside the signature-verified token,
	// so the pin is non-forgeable on this path.
	trusted := s.cfg.TrustMaterializedClaims && s.issuerTrusted(claims)
	if !trusted {
		delete(claims, "arkavo_patreon")
	}

	res, err := s.resolveFromClaims(ctx, claims)
	switch {
	case errors.Is(err, ErrMemberNotFound) && s.cfg.InferUnknownAsFree:
		res = &resolution{mem: &Membership{TierSlug: tierFree, Status: statusFormer}}
	case err != nil:
		return nil, err
	}
	mem := res.mem

	patreonStruct, err := membershipStruct(mem)
	if err != nil {
		return nil, err
	}
	wrappedClaims := map[string]interface{}{
		"patreon": patreonStruct.AsMap(),
	}
	// Preserve the (now trust-checked) materialized claim verbatim so the
	// decision flow's second pass re-derives the passthrough — including its
	// direct entitlements — without consulting Patreon.
	if raw, ok := claims["arkavo_patreon"].(map[string]interface{}); ok {
		wrappedClaims["arkavo_patreon"] = raw
	}
	subjectClaims, err := structpb.NewStruct(wrappedClaims)
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

// resolveEntity resolves a single entity. Only a claims entity can carry the
// materialized arkavo_patreon membership this provider consumes; other entity
// types (username/email/client id) have no membership source now that live
// Patreon lookups are gone, so they resolve as not-found (→ free when
// InferUnknownAsFree).
func (s *EntityResolutionService) resolveEntity(ctx context.Context, e *entity.Entity) (*resolution, error) {
	if claimsEntity, ok := e.GetEntityType().(*entity.Entity_Claims); ok {
		var asStruct structpb.Struct
		if err := claimsEntity.Claims.UnmarshalTo(&asStruct); err != nil {
			return nil, fmt.Errorf("unpack claims: %w", err)
		}
		return s.resolveFromClaims(ctx, asStruct.AsMap())
	}
	return nil, ErrMemberNotFound
}

// resolveFromClaims is the single resolution path: the claims-passthrough.
// Pre-materialized memberships from identity.arkavo.net (in arkavo_patreon)
// emit campaign-qualified direct entitlements with no Patreon access. Gated
// on TrustMaterializedClaims (default off) — the claim is authoritative, so
// it is only honored when the operator has asserted the trust boundary.
// Without a usable claim the subject is not-found (→ free when
// InferUnknownAsFree). See passthrough.go.
func (s *EntityResolutionService) resolveFromClaims(_ context.Context, claims map[string]interface{}) (*resolution, error) {
	if s.cfg.TrustMaterializedClaims {
		if claim := parseArkavoPatreon(claims); claim != nil {
			return passthroughResolution(claim, s.cfg.entitlementsNamespace()), nil
		}
	}
	return nil, ErrMemberNotFound
}

// freeMembership returns a synthetic free-tier membership tied to the
// caller identity, used when InferUnknownAsFree is set.
func freeMembership(e *entity.Entity) *Membership {
	mem := &Membership{TierSlug: tierFree, Status: statusFormer}
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

func resolutionToRepresentation(originalID string, res *resolution) (*entityresolutionV2.EntityRepresentation, error) {
	mem := res.mem
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
	// Campaign-qualified direct entitlements from the claims-passthrough
	// path. The PDP merges these with subject-mapping entitlements when
	// allow_direct_entitlements is enabled; with synthetic-value support,
	// only the attribute definitions need to exist in policy — values are
	// fully dynamic, so onboarding a creator requires zero policy changes.
	var direct []*entityresolutionV2.DirectEntitlement
	for _, fqn := range res.entitlements {
		direct = append(direct, &entityresolutionV2.DirectEntitlement{
			AttributeValueFqn: fqn,
			Actions:           []string{"read"},
		})
	}
	return &entityresolutionV2.EntityRepresentation{
		OriginalId:         originalID,
		AdditionalProps:    []*structpb.Struct{wrapped},
		DirectEntitlements: direct,
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
	default:
		return connect.CodeInternal
	}
}
