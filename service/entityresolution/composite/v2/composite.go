package composite

import (
	"cmp"
	"context"
	"errors"
	"fmt"
	"log/slog"
	"slices"
	"strings"
	"time"

	"connectrpc.com/connect"
	authzV2 "github.com/opentdf/platform/protocol/go/authorization/v2"
	"github.com/opentdf/platform/protocol/go/entity"
	entityresolutionV2 "github.com/opentdf/platform/protocol/go/entityresolution/v2"
	"github.com/opentdf/platform/service/entityresolution/source"
	"github.com/opentdf/platform/service/internal/agentstatus"
	"github.com/opentdf/platform/service/internal/auth"
	"github.com/opentdf/platform/service/logger"
	"go.opentelemetry.io/otel/trace"
	"google.golang.org/protobuf/types/known/anypb"
	"google.golang.org/protobuf/types/known/structpb"
)

const (
	// subjectEphemeralID names the one entity of every chain the token route
	// returns.
	subjectEphemeralID = "composite-subject"
	// tokenOutcome is the Outcomes key of the token itself.
	tokenOutcome = "_token"
	// invalidEvidenceTTL is how long the evidence of an invalid token lasts.
	invalidEvidenceTTL = 60 * time.Second
	// claimAccountID holds the subject's stable account ID, and an agent's
	// owner.
	claimAccountID = "arkavo_account_id"
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
	// caps maps a device class to the value FQNs it is capped to.
	caps   map[string]map[string]bool
	now    func() time.Time
	logger *logger.Logger
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
	caps := make(map[string]map[string]bool, len(cfg.Constraints.DeviceClassCaps))
	for class, fqns := range cfg.Constraints.DeviceClassCaps {
		allowed := make(map[string]bool, len(fqns))
		for _, raw := range fqns {
			if fqn, ok := source.ParseFQN(raw); ok {
				allowed[fqn.String()] = true
			}
		}
		caps[class] = allowed
	}
	return &Service{
		cfg:         cfg,
		verifiers:   verifiers,
		sources:     sources,
		sealKeys:    keys,
		peps:        peps,
		agentStatus: checker,
		caps:        caps,
		now:         time.Now,
		logger:      log,
	}, nil
}

// CreateEntityChainsFromTokens resolves each token on the licence and KAS
// rewrap routes and returns one chain per token, holding one subject entity:
// the resolution, sealed as arkavo_evidence. A token that is not a verified
// CWT seals an evidence with no grants, so it is denied rather than failing
// the decision.
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
		EphemeralId: subjectEphemeralID,
		Category:    entity.Entity_CATEGORY_SUBJECT,
	}, nil
}

// resolveToken verifies raw and resolves its subject until the token
// expires. Anything but a verified CWT with an exp still ahead resolves to
// no grants, recorded as an invalid token, for invalidEvidenceTTL.
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
	accountID, _ := claims[claimAccountID].(string)
	ev := s.resolveSubject(ctx, source.Subject{
		Claims:    claims,
		Kind:      source.KindOf(claims),
		AccountID: accountID,
		Trust:     source.TrustVerified,
	}, q, exp)
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

// resolveSubject runs every source that admits subj, keeps what each
// source's capability allows, unions it and applies the constraints. The
// evidence expires at exp. A subject with no trust keeps no claims, and its
// kind is judged from the claims the sources see, so discarded claims cannot
// make it a device or an agent.
func (s *Service) resolveSubject(ctx context.Context, subj source.Subject, q source.Query, exp time.Time) evidence {
	if subj.Trust == source.TrustNone {
		none := map[string]any{}
		subj = source.Subject{Claims: none, Kind: source.KindOf(none), Trust: source.TrustNone}
	}
	sub, _ := subj.Claims["sub"].(string)
	ev := evidence{V: evidenceVersion, Sub: sub, Exp: exp.Unix(), Outcomes: map[string]source.Outcome{}}
	if s.withheldAgent(ctx, subj) {
		return ev
	}

	runs := s.runSources(ctx, subj, q)
	merged := map[string]*sealedGrant{}
	// Configured order, not completion order: the first source to grant an
	// FQN is its provenance.
	for i, cs := range s.sources {
		run := runs[i]
		ev.Outcomes[cs.id] = run.outcome
		if run.err != nil {
			s.logger.WarnContext(ctx, "composite: source unavailable; it contributes nothing",
				slog.String("source_id", cs.id),
				slog.Any("error", run.err),
			)
		}
		if run.outcome != source.OutcomeComplete {
			continue
		}
		s.mergeGrants(ctx, merged, cs, run.res.Grants)
		if cs.propsKey != "" && len(run.res.Properties) > 0 {
			if ev.Props == nil {
				ev.Props = map[string]map[string]any{}
			}
			ev.Props[cs.propsKey] = safeProperties(run.res.Properties)
		}
	}
	ev.Grants = capGrants(s.caps, subj, sortedGrants(merged))
	return ev
}

// mergeGrants adds the grants cs's capability allows to merged, keyed by the
// lowercased FQN. A grant with no actions takes the source's. A repeated FQN
// merges its actions and keeps its first source and its earliest expiry, so
// no action outlives a grant that carried it.
func (s *Service) mergeGrants(ctx context.Context, merged map[string]*sealedGrant, cs configuredSource, grants []source.Grant) {
	for _, g := range grants {
		if len(g.Actions) == 0 {
			g.Actions = cs.cap.actions
		}
		if !cs.cap.allows(g) {
			s.logger.WarnContext(ctx, "composite: dropped a grant outside its capability",
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
