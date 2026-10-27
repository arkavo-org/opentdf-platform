package composite

import (
	"cmp"
	"context"
	"errors"
	"fmt"
	"log/slog"
	"slices"
	"strconv"
	"strings"
	"time"

	"connectrpc.com/connect"
	authzV2 "github.com/opentdf/platform/protocol/go/authorization/v2"
	"github.com/opentdf/platform/protocol/go/entity"
	entityresolutionV2 "github.com/opentdf/platform/protocol/go/entityresolution/v2"
	ent "github.com/opentdf/platform/service/entity"
	"github.com/opentdf/platform/service/entityresolution/source"
	"github.com/opentdf/platform/service/internal/agentstatus"
	"github.com/opentdf/platform/service/internal/auth"
	"github.com/opentdf/platform/service/internal/chaindevice"
	"github.com/opentdf/platform/service/internal/publishingstatus"
	"github.com/opentdf/platform/service/logger"
	ctxAuth "github.com/opentdf/platform/service/pkg/auth"
	"go.opentelemetry.io/otel/trace"
	"google.golang.org/protobuf/types/known/anypb"
	"google.golang.org/protobuf/types/known/structpb"
)

const (
	// subjectEphemeralIDPrefix starts the ephemeral ID of the one entity of
	// every chain the token route returns. The evidence's sub, or
	// anonymousSubject, follows it: the second call reports it as the
	// representation's original ID, so decision audits name the viewer.
	subjectEphemeralIDPrefix = "composite-subject-"
	anonymousSubject         = "anonymous"
	// tokenOutcome is the Outcomes key of the token itself.
	tokenOutcome = "_token"
	// invalidEvidenceTTL is how long the evidence of an invalid token lasts.
	invalidEvidenceTTL = 60 * time.Second
	// claimAccountID holds the subject's stable account ID, and an agent's
	// owner.
	claimAccountID = "arkavo_account_id"
	// clientIDNone and clientIDConflict stand for a caller with no client
	// ID and one with several. Neither is ever allowlisted.
	clientIDNone     = "none"
	clientIDConflict = "conflict"
)

// claimsVerifier verifies a CWT and returns its claims. *auth.CWTVerifier is
// one, for one issuer.
type claimsVerifier interface {
	VerifyCWTClaims(ctx context.Context, token string) (map[string]any, error)
}

// configuredSource is a source under its capability. id names it in
// outcomes, provenance and logs; propsKey, when set, is where its properties
// go.
type configuredSource struct {
	id, propsKey string
	cap          capability
	src          source.Source
}

// Service is the composite entity resolver.
type Service struct {
	entityresolutionV2.UnimplementedEntityResolutionServiceServer
	trace.Tracer

	cfg Config
	// verifiers holds one verifier per token issuer.
	verifiers map[string]claimsVerifier
	sources   []configuredSource
	// sealKeys: the first seals, every one opens.
	sealKeys [][]byte
	// peps are the client IDs whose unsealed claims chains are accepted.
	peps map[string]bool
	// agentStatus judges agent subjects; nil withholds every one.
	agentStatus agentstatus.Checker
	// publishing withholds arkavo-creator from suspended creators; nil is off.
	publishing publishingstatus.Checker
	now        func() time.Time
	logger     *logger.Logger
}

// New builds the resolver from the sources and verifiers already built from
// cfg, and decodes its seal keys. A nil checker withholds every agent subject.
func New(cfg Config, verifiers map[string]claimsVerifier, sources []configuredSource, checker agentstatus.Checker, log *logger.Logger) (*Service, error) {
	if cfg.Deadline <= 0 {
		cfg.Deadline = defaultDeadline
	}
	sealKey, err := decodeKey(cfg.Evidence.SealKey)
	if err != nil {
		return nil, fmt.Errorf("evidence.seal_key: %w", err)
	}
	keys := [][]byte{sealKey}
	for i, k := range cfg.Evidence.PreviousSealKeys {
		key, keyErr := decodeKey(k)
		if keyErr != nil {
			return nil, fmt.Errorf("evidence.previous_seal_keys[%d]: %w", i, keyErr)
		}
		keys = append(keys, key)
	}
	peps := make(map[string]bool, len(cfg.Evidence.ClaimsChainPEPs))
	for _, id := range cfg.Evidence.ClaimsChainPEPs {
		peps[id] = true
	}
	return &Service{
		cfg:         cfg,
		verifiers:   verifiers,
		sources:     sources,
		sealKeys:    keys,
		peps:        peps,
		agentStatus: checker,
		now:         time.Now,
		logger:      log,
	}, nil
}

// CreateEntityChainsFromTokens resolves each token on the licence and KAS
// rewrap routes and returns one chain per token, holding one subject entity:
// the resolution, sealed as arkavo_evidence. A token that is not a verified
// CWT seals an evidence with no grants, so it is denied rather than failing
// the decision. A device token is split into its person and the person's
// device (see resolveToken), still one subject entity.
func (s *Service) CreateEntityChainsFromTokens(
	ctx context.Context,
	req *connect.Request[entityresolutionV2.CreateEntityChainsFromTokensRequest],
) (*connect.Response[entityresolutionV2.CreateEntityChainsFromTokensResponse], error) {
	ctx, span := s.Start(ctx, "CreateEntityChainsFromTokens")
	defer span.End()
	q := source.Query{Action: defaultAction, Resources: requestedFQNs(req.Msg.GetResources())}
	chains := make([]*entity.EntityChain, 0, len(req.Msg.GetTokens()))
	for _, tok := range req.Msg.GetTokens() {
		subject, err := s.subjectEntity(s.resolveToken(ctx, tok.GetJwt(), q))
		if err != nil {
			s.logger.ErrorContext(ctx, "composite: cannot seal evidence", slog.Any("error", err))
			return nil, connect.NewError(connect.CodeInternal, fmt.Errorf("composite: seal evidence: %w", err))
		}
		chains = append(chains, &entity.EntityChain{EphemeralId: tok.GetEphemeralId(), Entities: []*entity.Entity{subject}})
	}
	return connect.NewResponse(&entityresolutionV2.CreateEntityChainsFromTokensResponse{EntityChains: chains}), nil
}

// ResolveEntities turns each entity into its representation.
//   - A claims entity carrying arkavo_evidence is judged by its seal alone:
//     the opened evidence is the representation, whoever the caller. One
//     that does not open grants nothing and is never read as a PEP's claims.
//   - A claims entity carrying arkavo_device_token is a device, judged by
//     the token's signature alone, whoever the caller (see
//     deviceTokenEntity). It holds no grants. It must be an environment
//     entity: the PDP would read one of any other category as a co-subject
//     with no grants, which denies every decision while the person's
//     entitlements still list its grants, so such a request is refused
//     before anything is resolved.
//   - Any other claims entity is a PEP's assertion. It counts only from a
//     client ID on claims_chain_peps, and only pep_assertable sources read
//     it.
//   - Everything else, an unsealed chain from any other caller included, is
//     a subject with no trust: the sources see no claims.
//
// The request is one chain, so once every entity is resolved each device is
// bound to the chain's subjects, or not (see bindDevices), and carries a
// marker saying which (see chaindevice). The PDP partitions the chain by
// representation ID, so a request in which two entities share an ID is
// refused before anything is resolved: binding would otherwise see fewer
// subjects than the PDP narrows.
func (s *Service) ResolveEntities(
	ctx context.Context,
	req *connect.Request[entityresolutionV2.ResolveEntitiesRequest],
) (*connect.Response[entityresolutionV2.ResolveEntitiesResponse], error) {
	ctx, span := s.Start(ctx, "ResolveEntities")
	defer span.End()
	ids, dup := entityIDs(req.Msg.GetEntities())
	if dup != "" {
		s.logger.WarnContext(
			ctx, "composite: two entities of the request share an ID; it is refused",
			slog.String("entity_id", dup),
		)
		return nil, connect.NewError(connect.CodeInvalidArgument, fmt.Errorf("composite: entity ID %q is used by two entities", dup))
	}
	if id, category := misplacedDeviceToken(req.Msg.GetEntities(), ids); id != "" {
		s.logger.WarnContext(
			ctx, "composite: a device token in an entity that is not an environment entity; the request is refused",
			slog.String("entity_id", id),
			slog.String("category", category.String()),
		)
		return nil, connect.NewError(connect.CodeInvalidArgument,
			fmt.Errorf("composite: entity %q carries %s but is not an environment entity", id, chaindevice.TokenClaim))
	}
	// The request names no resources, so sources answer subject-wide.
	q := source.Query{Action: defaultAction}
	entries := make([]resolvedEntry, 0, len(req.Msg.GetEntities()))
	for i, e := range req.Msg.GetEntities() {
		id := ids[i]
		ev, device, err := s.resolveEntity(ctx, id, e, q)
		if err != nil {
			s.logger.WarnContext(
				ctx, "composite: cannot read claims entity",
				slog.String("entity_id", id),
				slog.Any("error", err),
			)
			return nil, connect.NewError(connect.CodeInvalidArgument, fmt.Errorf("composite: unpack claims: %w", err))
		}
		entries = append(entries, resolvedEntry{
			id:       id,
			category: e.GetCategory(),
			ev:       ev,
			device:   device,
			iss:      ev.Iss,
			account:  ev.AccountID,
		})
	}
	bindDevices(entries)
	reps := make([]*entityresolutionV2.EntityRepresentation, 0, len(entries))
	for _, entry := range entries {
		if entry.device != nil && !entry.device.Bound {
			s.logUnbound(ctx, entry, entries)
		}
		rep, err := representation(entry.id, entry.ev, entry.device)
		if err != nil {
			s.logger.ErrorContext(
				ctx, "composite: cannot build entity representation",
				slog.String("entity_id", entry.id),
				slog.Any("error", err),
			)
			return nil, connect.NewError(connect.CodeInternal, fmt.Errorf("composite: entity representation: %w", err))
		}
		reps = append(reps, rep)
	}
	return connect.NewResponse(&entityresolutionV2.ResolveEntitiesResponse{EntityRepresentations: reps}), nil
}

// entityIDs names each entity as its representation is named, and as the PDP
// names it: its ephemeral ID, or EntityIDPrefix and its index when it has
// none. It also returns the first ID two entities share, or "".
func entityIDs(entities []*entity.Entity) ([]string, string) {
	ids := make([]string, len(entities))
	seen := make(map[string]bool, len(entities))
	for i, e := range entities {
		id := e.GetEphemeralId()
		if id == "" {
			id = ent.EntityIDPrefix + strconv.Itoa(i)
		}
		if seen[id] {
			return nil, id
		}
		seen[id] = true
		ids[i] = id
	}
	return ids, ""
}

// misplacedDeviceToken returns the ID, as entityIDs names it, and the
// category of the first entity that carries chaindevice.TokenClaim in its
// claims but is not an environment entity, whatever else it carries, or "".
// Claims that do not unpack are left to resolveEntity to refuse.
func misplacedDeviceToken(entities []*entity.Entity, ids []string) (string, entity.Entity_Category) {
	for i, e := range entities {
		if e.GetCategory() == entity.Entity_CATEGORY_ENVIRONMENT || e.GetClaims() == nil {
			continue
		}
		var st structpb.Struct
		if err := e.GetClaims().UnmarshalTo(&st); err != nil {
			continue
		}
		if _, carried := st.GetFields()[chaindevice.TokenClaim]; carried {
			return ids[i], e.GetCategory()
		}
	}
	return "", entity.Entity_CATEGORY_UNSPECIFIED
}

// subjectEntity seals ev into a chain's subject entity.
func (s *Service) subjectEntity(ev evidence) (*entity.Entity, error) {
	sealed, err := sealEvidence(s.sealKeys[0], ev)
	if err != nil {
		return nil, err
	}
	st, err := structpb.NewStruct(map[string]any{evidenceClaim: sealed})
	if err != nil {
		return nil, err
	}
	claims, err := anypb.New(st)
	if err != nil {
		return nil, err
	}
	return &entity.Entity{
		EntityType:  &entity.Entity_Claims{Claims: claims},
		EphemeralId: subjectEphemeralID(ev.Sub),
		Category:    entity.Entity_CATEGORY_SUBJECT,
	}, nil
}

// subjectEphemeralID names a token route subject entity after its sub.
func subjectEphemeralID(sub string) string {
	if sub == "" {
		sub = anonymousSubject
	}
	return subjectEphemeralIDPrefix + sub
}

// resolveToken verifies raw and resolves its subject until the token
// expires. Anything but a verified CWT with an exp still ahead resolves to
// no grants, recorded as an invalid token, for invalidEvidenceTTL.
//
// A verified token that KindOf judges a device's (a DeviceCheck token, which
// iOS presents at KAS rewrap) carries a person and the person's device, and is
// split. The sources resolve the person from personClaims, as any person
// token. The device, as deviceFromClaims reads it, is sealed beside the
// person's grants; ResolveEntities binds it as it binds any device, so in a
// chain of its subject alone it is that subject's own. A device never grants:
// device rules in the policy file narrow the person's grants by it. A token
// with an agent marker is an agent's, never a device's, so it is not split.
func (s *Service) resolveToken(ctx context.Context, raw string, q source.Query) evidence {
	claims, exp, err := s.verifyToken(ctx, raw)
	if err != nil {
		s.logger.WarnContext(ctx, "composite: token is not a verified CWT; it gets no grants", slog.Any("error", err))
		return evidence{
			V:        evidenceVersion,
			Exp:      s.now().Add(invalidEvidenceTTL).Unix(),
			Outcomes: map[string]source.Outcome{tokenOutcome: source.OutcomeInvalid},
		}
	}
	var device *sealedDevice
	if source.KindOf(claims) == source.KindDevice {
		// Seal only what deviceFromClaims read, so the class is one the PDP
		// knows, and an attested device's attestation expiry, so it lapses
		// when the evidence is opened after it.
		d := deviceFromClaims(claims, true, s.now())
		device = &sealedDevice{Class: d.Class, AppIDHash: d.AppIDHash, AppEnv: d.AppEnv}
		if d.Class == chaindevice.ClassAttested {
			device.AttestationExpiry = attestationExpiry(claims)
		}
		claims = personClaims(claims)
	}
	accountID, _ := claims[claimAccountID].(string)
	ev := s.resolveSubject(ctx, source.Subject{
		Claims:    claims,
		AccountID: accountID,
		Trust:     source.TrustVerified,
	}, q, exp)
	ev.Device = device
	ev.Outcomes[tokenOutcome] = source.OutcomeComplete
	return ev
}

// verifyToken reads the issuer from the unverified CWT, verifies the token
// with that issuer's verifier and requires an exp still ahead. Only a CWT
// decodes, so an unsigned JOSE JWT never reaches a verifier.
func (s *Service) verifyToken(ctx context.Context, raw string) (map[string]any, time.Time, error) {
	unverified, err := auth.DecodeCWTClaimsFromToken(raw)
	if err != nil {
		return nil, time.Time{}, fmt.Errorf("not a CWT: %w", err)
	}
	iss, _ := unverified["iss"].(string)
	verifier := s.verifiers[iss]
	if verifier == nil {
		return nil, time.Time{}, fmt.Errorf("issuer %q is not configured", iss)
	}
	claims, err := verifier.VerifyCWTClaims(ctx, raw)
	if err != nil {
		return nil, time.Time{}, fmt.Errorf("verify: %w", err)
	}
	if got, _ := claims["iss"].(string); got != iss {
		return nil, time.Time{}, fmt.Errorf("verified issuer %q is not the token's %q", got, iss)
	}
	exp, ok := numericDate(claims["exp"])
	if !ok {
		return nil, time.Time{}, errors.New("token has no numeric exp")
	}
	if !exp.After(s.now()) {
		return nil, time.Time{}, errors.New("token has expired")
	}
	return claims, exp, nil
}

// resolveEntity resolves one entity of a ResolveEntities request (see
// there); id names it in logs. It also returns the device the entity is, if
// any, still unbound: the device sealed in its evidence, the device its
// device token describes, or, for a PEP's claims that KindOf judges a
// device's, an unverified device. A PEP's claims make a device only from a
// caller on claims_chain_peps. Only claims that do not unpack are an error.
func (s *Service) resolveEntity(ctx context.Context, id string, e *entity.Entity, q source.Query) (evidence, *chaindevice.Device, error) {
	anonymous := source.Subject{Trust: source.TrustNone}
	if _, isClaims := e.GetEntityType().(*entity.Entity_Claims); !isClaims {
		return s.resolveSubject(ctx, anonymous, q, s.now()), nil, nil
	}
	var st structpb.Struct
	if err := e.GetClaims().UnmarshalTo(&st); err != nil {
		return evidence{}, nil, err
	}
	claims := st.AsMap()
	if sealed, carried := claims[evidenceClaim]; carried {
		ev := s.openSealed(ctx, id, sealed)
		return ev, sealedDeviceOf(ev, s.now()), nil
	}
	// A token that is present but not a string is an unverified device, never
	// a PEP's claims.
	if token, carried := claims[chaindevice.TokenClaim]; carried {
		ev, device := s.deviceTokenEntity(ctx, id, token)
		return ev, device, nil
	}
	clientID, allowlisted := callerClientID(ctx, s.peps)
	if !allowlisted {
		s.logger.WarnContext(
			ctx, "composite: unsealed claims chain from a caller not on claims_chain_peps",
			slog.String("entity_id", id),
			slog.String("client_id", clientID),
		)
		return s.resolveSubject(ctx, anonymous, q, s.now()), nil, nil
	}
	// A PEP's word for a device's class is not trusted.
	var device *chaindevice.Device
	if source.KindOf(claims) == source.KindDevice {
		d := deviceFromClaims(claims, false, s.now())
		device = &d
	}
	accountID, _ := claims[claimAccountID].(string)
	return s.resolveSubject(ctx, source.Subject{Claims: claims, AccountID: accountID, Trust: source.TrustPEP}, q, s.now()), device, nil
}

// openSealed opens the arkavo_evidence of the claims entity id. Whatever does
// not open, a value that is not a string included, resolves to nothing: no
// grants and no properties. The refusal names the entity and the caller, and
// the value's type when it is not a string.
func (s *Service) openSealed(ctx context.Context, id string, sealed any) evidence {
	str, isString := sealed.(string)
	if isString {
		ev, err := openEvidence(s.sealKeys, str, s.now())
		if err == nil {
			return ev
		}
		s.logSealRefusal(ctx, id, err)
		return evidence{}
	}
	s.logSealRefusal(ctx, id, errors.New("arkavo_evidence is not a string"),
		slog.String("evidence_type", fmt.Sprintf("%T", sealed)))
	return evidence{}
}

func (s *Service) logSealRefusal(ctx context.Context, id string, err error, extra ...slog.Attr) {
	clientID, _ := callerClientID(ctx, s.peps)
	attrs := append([]slog.Attr{
		slog.String("entity_id", id),
		slog.String("client_id", clientID),
		slog.Any("error", err),
	}, extra...)
	s.logger.LogAttrs(ctx, slog.LevelWarn, "composite: arkavo_evidence does not open; it grants nothing", attrs...)
}

// resolveSubject runs every source that admits subj, unless the agent gate
// withholds it, keeps what each source's capability allows and unions it. The
// evidence expires at exp and records the subject's iss and account ID. A
// subject with no trust keeps no claims, so it records neither. The kind
// is always judged from the claims the sources see, never taken from the
// caller, so discarded claims cannot make a subject a device or an agent,
// and a device cannot pass as a person.
func (s *Service) resolveSubject(ctx context.Context, subj source.Subject, q source.Query, exp time.Time) evidence {
	if subj.Trust == source.TrustNone {
		subj = source.Subject{Claims: map[string]any{}, Trust: source.TrustNone}
	}
	subj.Kind = source.KindOf(subj.Claims)
	sub, _ := subj.Claims["sub"].(string)
	iss, _ := subj.Claims["iss"].(string)
	ev := evidence{
		V:         evidenceVersion,
		Sub:       sub,
		Iss:       iss,
		AccountID: subj.AccountID,
		Exp:       exp.Unix(),
		Outcomes:  map[string]source.Outcome{},
	}
	if s.withheldAgent(ctx, subj) {
		return ev
	}

	runs := s.runSources(ctx, subj, q)
	now := s.now()
	merged := map[string]*sealedGrant{}
	// Configured order, not completion order: the first source to grant an
	// FQN is its provenance.
	for i, cs := range s.sources {
		run := runs[i]
		ev.Outcomes[cs.id] = run.outcome
		if run.err != nil {
			s.logger.WarnContext(
				ctx, "composite: source unavailable; it contributes nothing",
				slog.String("source_id", cs.id),
				slog.Any("error", run.err),
			)
		}
		if run.outcome != source.OutcomeComplete {
			continue
		}
		s.mergeGrants(ctx, merged, cs, run.res.Grants, now, exp)
		if cs.propsKey != "" && len(run.res.Properties) > 0 {
			if ev.Props == nil {
				ev.Props = map[string]map[string]any{}
			}
			ev.Props[cs.propsKey] = safeProperties(run.res.Properties)
		}
	}
	ev.Grants = s.withholdSuspendedPublishing(ctx, subj, sortedGrants(merged))
	return ev
}

// mergeGrants adds the grants cs's capability allows to merged, keyed by the
// lowercased FQN. A grant with no actions takes the source's. A grant whose
// own expiry is at or before now, to the second as openEvidence judges it, is
// dropped: on the unsealed routes nothing else would. One that outlives the
// evidence is clamped to expire with it at evExp; one with no expiry already
// does. A repeated FQN merges its actions and keeps its first source and its
// earliest expiry, so no action outlives a grant that carried it.
func (s *Service) mergeGrants(ctx context.Context, merged map[string]*sealedGrant, cs configuredSource, grants []source.Grant, now, evExp time.Time) {
	for _, g := range grants {
		if len(g.Actions) == 0 {
			g.Actions = cs.cap.actions
		}
		if !cs.cap.allows(g) {
			s.logger.WarnContext(
				ctx, "composite: dropped a grant outside its capability",
				slog.String("source_id", cs.id),
				slog.String("fqn", g.FQN),
				slog.Any("actions", g.Actions),
			)
			continue
		}
		fqn, _ := source.ParseFQN(g.FQN) // allows has parsed it
		key := fqn.String()
		var exp int64
		if !g.ExpiresAt.IsZero() {
			exp = g.ExpiresAt.Unix()
			if exp <= now.Unix() {
				s.logger.DebugContext(
					ctx, "composite: dropped an expired grant",
					slog.String("source_id", cs.id),
					slog.String("fqn", key),
					slog.Time("expires_at", g.ExpiresAt),
				)
				continue
			}
			exp = min(exp, evExp.Unix())
		}
		prev, seen := merged[key]
		if !seen {
			merged[key] = &sealedGrant{FQN: key, Actions: slices.Clone(g.Actions), Source: cs.id, Exp: exp}
			continue
		}
		prev.Actions = append(prev.Actions, g.Actions...)
		if exp != 0 && (prev.Exp == 0 || exp < prev.Exp) {
			prev.Exp = exp
		}
	}
}

// runSources runs every source that admits subj, each in its own goroutine,
// under one deadline, and returns how each ended, indexed like s.sources. A
// source not admitted is not applicable. One that has not answered by the
// deadline is unavailable; its goroutine later finishes into the buffered
// channel, which nobody reads.
func (s *Service) runSources(ctx context.Context, subj source.Subject, q source.Query) []sourceRun {
	ctx, cancel := context.WithTimeout(ctx, s.cfg.Deadline)
	defer cancel()
	runs := make([]sourceRun, len(s.sources))
	done := make(chan sourceRun, len(s.sources))
	pending := map[int]bool{}
	for i, cs := range s.sources {
		if !cs.cap.admits(subj) {
			runs[i] = sourceRun{idx: i, outcome: source.OutcomeNotApplicable}
			continue
		}
		pending[i] = true
		go func() {
			defer func() {
				if r := recover(); r != nil {
					done <- sourceRun{idx: i, outcome: source.OutcomeUnavailable, err: fmt.Errorf("source panicked: %v", r)}
				}
			}()
			done <- runSource(ctx, i, cs.src, subj, q)
		}()
	}
	for len(pending) > 0 {
		select {
		case run := <-done:
			runs[run.idx] = run
			delete(pending, run.idx)
		case <-ctx.Done():
			for i := range pending {
				runs[i] = sourceRun{
					idx:     i,
					outcome: source.OutcomeUnavailable,
					err:     fmt.Errorf("no answer within %s: %w", s.cfg.Deadline, ctx.Err()),
				}
			}
			return runs
		}
	}
	return runs
}

// requestedFQNs returns the attribute value FQNs of the requested resources,
// lowercased as the PDP compares them.
func requestedFQNs(resources []*authzV2.Resource) []string {
	var out []string
	for _, r := range resources {
		for _, fqn := range r.GetAttributeValues().GetFqns() {
			out = append(out, strings.ToLower(fqn))
		}
	}
	return out
}

// callerClientID returns the client ID the platform recorded for the caller,
// and whether it is one of peps. A caller with no client ID is "none" and
// one with several is "conflict"; neither is ever allowlisted.
func callerClientID(ctx context.Context, peps map[string]bool) (string, bool) {
	id, err := ctxAuth.GetClientIDFromContext(ctx, true)
	switch {
	case errors.Is(err, ctxAuth.ErrConflictClientID):
		return clientIDConflict, false
	case err != nil: // ErrNoMetadataFound or ErrMissingClientID
		return clientIDNone, false
	}
	return id, peps[id]
}

// representation is the EntityRepresentation of ev: its grants as direct
// entitlements and its properties, each under its properties key, in one
// struct, omitted when there are none. A device also carries its marker
// under chaindevice.PropKey, which only the composite writes: properties
// under that key are dropped (Validate refuses it as a properties_key, but
// evidence sealed under an older config could carry it). Nothing else of the
// entity counts.
func representation(id string, ev evidence, device *chaindevice.Device) (*entityresolutionV2.EntityRepresentation, error) {
	rep := &entityresolutionV2.EntityRepresentation{OriginalId: id}
	for _, g := range ev.Grants {
		rep.DirectEntitlements = append(rep.DirectEntitlements, &entityresolutionV2.DirectEntitlement{
			AttributeValueFqn: g.FQN,
			Actions:           slices.Clone(g.Actions),
		})
	}
	props := make(map[string]any, len(ev.Props)+1)
	for key, p := range ev.Props {
		if key == chaindevice.PropKey {
			continue
		}
		props[key] = p
	}
	if device != nil {
		props[chaindevice.PropKey] = device.Props()
	}
	if len(props) == 0 {
		return rep, nil
	}
	st, err := structpb.NewStruct(props)
	if err != nil {
		return nil, err
	}
	rep.AdditionalProps = []*structpb.Struct{st}
	return rep, nil
}

// numericDate reads a NumericDate claim as the CWT decoder renders it. A
// timestamp tag (time.Time) is accepted too; its expiry is then checked by
// verifyToken alone.
func numericDate(v any) (time.Time, bool) {
	switch x := v.(type) {
	case int64:
		return time.Unix(x, 0), true
	case int:
		return time.Unix(int64(x), 0), true
	case float64:
		return time.Unix(int64(x), 0), true
	case time.Time:
		return x, true
	}
	return time.Time{}, false
}

// sortedGrants orders the grants, and each grant's actions, so the evidence
// does not depend on the order the sources are configured in.
func sortedGrants(merged map[string]*sealedGrant) []sealedGrant {
	out := make([]sealedGrant, 0, len(merged))
	for _, g := range merged {
		slices.Sort(g.Actions)
		g.Actions = slices.Compact(g.Actions)
		out = append(out, *g)
	}
	slices.SortFunc(out, func(a, b sealedGrant) int { return cmp.Compare(a.FQN, b.FQN) })
	return out
}

// safeProperties drops what the evidence cannot carry and renders
// timestamps and byte strings as the rest of the ERS does
// (auth.StructpbSafe), so no source's properties can break the seal.
func safeProperties(props map[string]any) map[string]any {
	safe, _ := auth.StructpbSafe(props)
	m, _ := safe.(map[string]any)
	return m
}

// sourceRun is how one source's resolution ended. res is set only when the
// outcome is complete; err says why a source is unavailable.
type sourceRun struct {
	idx     int
	res     source.Resolution
	outcome source.Outcome
	err     error
}

// runSource resolves one source. An error, an answer after the context ended
// or an outcome nobody defined makes it unavailable, and only a complete
// answer keeps its resolution. runSources recovers a panic.
func runSource(ctx context.Context, idx int, src source.Source, subj source.Subject, q source.Query) sourceRun {
	run := sourceRun{idx: idx, outcome: source.OutcomeUnavailable}
	res, err := src.Resolve(ctx, subj, q)
	switch {
	case err != nil:
		run.err = err
	case ctx.Err() != nil:
		run.err = fmt.Errorf("answered after the context ended: %w", ctx.Err())
	default:
		switch res.Outcome {
		case source.OutcomeComplete:
			run.res, run.outcome = res, res.Outcome
		case source.OutcomeNotApplicable, source.OutcomeUnavailable, source.OutcomeInvalid:
			run.outcome = res.Outcome
		default:
			run.err = fmt.Errorf("unknown outcome %q", res.Outcome)
		}
	}
	return run
}
