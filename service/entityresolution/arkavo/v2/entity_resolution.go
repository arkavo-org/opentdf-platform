// Package arkavo is the claims-passthrough Entity Resolution Service for
// authnz-rs (identity.arkavo.net) tokens. It emits the person (PE) as the
// SUBJECT entity, each arkavo_npe (agent, device) as an ENVIRONMENT entity,
// and direct entitlements from arkavo_entitlements — no subject mappings.
package arkavo

import (
	"context"
	"fmt"
	"log/slog"

	"connectrpc.com/connect"
	"github.com/go-viper/mapstructure/v2"
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

// arkavo_npe.class values (see authnz-rs's device attestation ladder) and
// arkavo_npe.type values. Re-added here per Task 3 (see config.go's NOTE) —
// this is the code that switches on them.
const (
	classUnverified = "unverified"
	classManaged    = "managed"
	classAttested   = "attested"
	npeTypeAgent    = "agent"
	npeTypeDevice   = "device"
)

// trustedMarker is set on the subject entity's claims by entitiesFromToken
// after the issuer check, so ResolveEntities (second pass, no token) can
// honor entitlements without re-checking iss. A caller-supplied claims
// entity can forge it — that path is guarded by the PEP's role:standard
// credential, exactly as in the patreon provider.
const trustedMarker = "arkavo_trusted"

type EntityResolutionService struct {
	entityresolutionV2.UnimplementedEntityResolutionServiceServer
	cfg    Config
	logger *logger.Logger
	trace.Tracer
}

func RegisterArkavoERS(cfg config.ServiceConfig, log *logger.Logger) (*EntityResolutionService, serviceregistry.HandlerServer) {
	var c Config
	if err := mapstructure.Decode(cfg, &c); err != nil {
		log.Error("failed to decode arkavo entity resolution config", slog.Any("error", err))
		panic(fmt.Sprintf("failed to decode arkavo entity resolution config: %v", err))
	}
	c.applyDefaults()
	log.Debug("arkavo entity resolution configuration", slog.Any("config", c))
	if c.TrustMaterializedClaims && c.TrustedIssuer == "" {
		log.Warn("arkavo: trust_materialized_claims is enabled with no trusted_issuer — any token the platform accepts can assert entitlements")
	}
	return &EntityResolutionService{cfg: c, logger: log}, nil
}

func NewERS(cfg Config, log *logger.Logger) *EntityResolutionService {
	cfg.applyDefaults()
	return &EntityResolutionService{cfg: cfg, logger: log}
}

// CreateEntityChainsFromTokens: one chain per token. Accepts JOSE or CWT.
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
		chains = append(chains, &entity.EntityChain{EphemeralId: tok.GetEphemeralId(), Entities: entities})
	}
	return connect.NewResponse(&entityresolutionV2.CreateEntityChainsFromTokensResponse{EntityChains: chains}), nil
}

// ResolveEntities: a claims entity carrying the trusted marker yields direct
// entitlements: arkavo_entitlements verbatim, plus the class ceiling when the
// claims describe a device NPE. Everything else resolves with no entitlements.
func (s *EntityResolutionService) ResolveEntities(
	ctx context.Context,
	req *connect.Request[entityresolutionV2.ResolveEntitiesRequest],
) (*connect.Response[entityresolutionV2.ResolveEntitiesResponse], error) {
	_, span := s.Start(ctx, "ResolveEntities")
	defer span.End()
	reps := make([]*entityresolutionV2.EntityRepresentation, 0, len(req.Msg.GetEntities()))
	for i, e := range req.Msg.GetEntities() {
		id := e.GetEphemeralId()
		if id == "" {
			id = fmt.Sprintf("%s%d", ent.EntityIDPrefix, i)
		}
		rep := &entityresolutionV2.EntityRepresentation{OriginalId: id}
		if claimsEntity, ok := e.GetEntityType().(*entity.Entity_Claims); ok {
			var st structpb.Struct
			if err := claimsEntity.Claims.UnmarshalTo(&st); err != nil {
				return nil, connect.NewError(connect.CodeInvalidArgument, fmt.Errorf("unpack claims: %w", err))
			}
			claims := st.AsMap()
			rep.AdditionalProps = []*structpb.Struct{&st}
			if claims[trustedMarker] == true {
				rep.DirectEntitlements = s.directEntitlements(parseArkavoClaims(claims))
			}
		}
		reps = append(reps, rep)
	}
	return connect.NewResponse(&entityresolutionV2.ResolveEntitiesResponse{EntityRepresentations: reps}), nil
}

func (s *EntityResolutionService) issuerTrusted(c arkavoClaims) bool {
	return s.cfg.TrustMaterializedClaims && (s.cfg.TrustedIssuer == "" || c.Iss == s.cfg.TrustedIssuer)
}

func (s *EntityResolutionService) entitiesFromToken(ctx context.Context, tokenRaw string) ([]*entity.Entity, error) {
	m, err := claimsFromToken(ctx, tokenRaw)
	if err != nil {
		return nil, err
	}
	c := parseArkavoClaims(m)
	trusted := s.issuerTrusted(c)

	out := []*entity.Entity{}
	// NPE (agent or device) as an ENVIRONMENT entity — audited, never evaluated.
	if c.Npe != nil {
		out = append(out, &entity.Entity{
			EntityType:  &entity.Entity_ClientId{ClientId: npeID(c)},
			EphemeralId: "arkavo-npe-" + c.Npe.Type,
			Category:    entity.Entity_CATEGORY_ENVIRONMENT,
		})
	}

	// SUBJECT: the PE for person/device tokens; the agent DID for agent tokens
	// (agent tokens are evaluated as their own subject — spec §1, choice A).
	subjectClaims := map[string]any{"sub": c.Sub, "iss": c.Iss}
	if c.AccountID != "" {
		subjectClaims[s.cfg.ClientIDClaim] = c.AccountID
	}
	if len(c.Roles) > 0 {
		subjectClaims["arkavo_roles"] = toAnySlice(c.Roles)
	}
	if trusted {
		subjectClaims[trustedMarker] = true
		if len(c.Entitlements) > 0 {
			subjectClaims["arkavo_entitlements"] = toAnySlice(c.Entitlements)
		}
		if raw, ok := m["arkavo_npe"].(map[string]any); ok {
			subjectClaims["arkavo_npe"] = raw
		}
	}
	st, err := structpb.NewStruct(subjectClaims)
	if err != nil {
		return nil, err
	}
	anyClaims, err := anypb.New(st)
	if err != nil {
		return nil, err
	}
	out = append(out, &entity.Entity{
		EntityType:  &entity.Entity_Claims{Claims: anyClaims},
		EphemeralId: "arkavo-subject",
		Category:    entity.Entity_CATEGORY_SUBJECT,
	})
	return out, nil
}

func npeID(c arkavoClaims) string {
	switch c.Npe.Type {
	case npeTypeDevice:
		return "device:" + c.Npe.DeviceID
	default:
		return c.Sub
	}
}

func toAnySlice(in []string) []any {
	out := make([]any, len(in))
	for i, s := range in {
		out[i] = s
	}
	return out
}

func (s *EntityResolutionService) directEntitlements(c arkavoClaims) []*entityresolutionV2.DirectEntitlement {
	fqns := append([]string{}, c.Entitlements...)
	if c.Npe != nil && c.Npe.Type == npeTypeDevice {
		class := c.Npe.Class
		if class == "" {
			class = classUnverified
		}
		fqns = append(fqns, s.cfg.DeviceClassCeilings[class]...)
	}
	out := make([]*entityresolutionV2.DirectEntitlement, 0, len(fqns))
	seen := map[string]bool{}
	for _, fqn := range fqns {
		if fqn == "" || seen[fqn] {
			continue
		}
		seen[fqn] = true
		out = append(out, &entityresolutionV2.DirectEntitlement{
			AttributeValueFqn: fqn,
			Actions:           append([]string{}, s.cfg.DirectEntitlementActions...),
		})
	}
	return out
}
