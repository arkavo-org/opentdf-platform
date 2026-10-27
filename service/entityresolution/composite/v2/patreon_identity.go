package composite

import (
	"context"
	"errors"
	"log/slog"
	"slices"
	"sync"
	"time"

	"github.com/opentdf/platform/service/entityresolution/source"
	"github.com/opentdf/platform/service/internal/identityentities"
	"github.com/opentdf/platform/service/logger"
)

const (
	// compareEvery is how often one account's token grants are compared
	// with identity's, at most.
	compareEvery = time.Minute
	// compareSweepThreshold bounds the memory of when each account was last
	// compared.
	compareSweepThreshold = 4096
)

// patreonIdentitySource grants a person's Patreon campaign and campaign-tier
// values, and the .patreon properties, the way the patreon-token source
// does, from claims it reads either from the token or from identity's
// GET /entities. Serving from the token, it compares each person's grants
// with identity's on the side and logs any difference, so the switch to
// identity can be checked in production first. Serving from identity, a
// person whose lookup fails with no answer young enough to serve stale gets
// nothing from it.
type patreonIdentitySource struct {
	patreon source.Source
	looker  identityentities.Looker
	serve   string
	log     *logger.Logger
	now     func() time.Time

	mu       sync.Mutex
	compared map[string]time.Time // account id -> when last compared
}

func newPatreonIdentitySource(patreonSrc source.Source, looker identityentities.Looker, serve string, log *logger.Logger) *patreonIdentitySource {
	return &patreonIdentitySource{
		patreon:  patreonSrc,
		looker:   looker,
		serve:    serve,
		log:      log,
		now:      time.Now,
		compared: make(map[string]time.Time),
	}
}

// Resolve implements source.Source.
func (s *patreonIdentitySource) Resolve(ctx context.Context, subj source.Subject, q source.Query) (source.Resolution, error) {
	person := subj.Kind == source.KindPerson && subj.AccountID != ""
	if s.serve != serveIdentity {
		res, err := s.patreon.Resolve(ctx, subj, q)
		if person && err == nil && s.dueForComparison(subj.AccountID) {
			// Detached: runSources cancels ctx as soon as the decision is made.
			go s.compare(context.WithoutCancel(ctx), subj.AccountID, res, q)
		}
		return res, err
	}
	if !person {
		return source.Resolution{Outcome: source.OutcomeNotApplicable}, nil
	}
	answer, err := s.looker.Lookup(ctx, subj.AccountID)
	if err != nil {
		s.logLookupFailure(ctx, subj.AccountID, err)
		return source.Resolution{Outcome: source.OutcomeUnavailable}, nil
	}
	if answer.Stale {
		s.log.DebugContext(
			ctx, "patreon-identity: serving a stale identity answer",
			slog.String("account_id", subj.AccountID),
			slog.Time("fetched_at", answer.FetchedAt),
		)
	}
	return s.patreon.Resolve(ctx, fromIdentity(subj, answer), q)
}

// fromIdentity is subj with identity's claims for it. An account identity
// does not know has no claims, so the patreon logic sees no membership.
func fromIdentity(subj source.Subject, answer identityentities.Answer) source.Subject {
	claims := answer.Claims
	if claims == nil {
		claims = map[string]any{}
	}
	return source.Subject{Claims: claims, Kind: subj.Kind, AccountID: subj.AccountID, Trust: subj.Trust}
}

// dueForComparison reports whether account was not compared within
// compareEvery, and if so marks it compared now.
func (s *patreonIdentitySource) dueForComparison(account string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := s.now()
	if last, seen := s.compared[account]; seen && now.Sub(last) < compareEvery {
		return false
	}
	if len(s.compared) >= compareSweepThreshold {
		for k, t := range s.compared {
			if now.Sub(t) >= compareEvery {
				delete(s.compared, k)
			}
		}
	}
	s.compared[account] = now
	return true
}

// compare resolves account from identity and logs how its grants differ
// from fromToken's. It never changes a decision.
func (s *patreonIdentitySource) compare(ctx context.Context, account string, fromToken source.Resolution, q source.Query) {
	answer, err := s.looker.Lookup(ctx, account)
	if err != nil {
		s.logLookupFailure(ctx, account, err)
		return
	}
	fromIdentityRes, err := s.patreon.Resolve(ctx, fromIdentity(source.Subject{Kind: source.KindPerson, AccountID: account}, answer), q)
	if err != nil {
		return
	}
	onlyToken, onlyIdentity := grantDifference(fromToken.Grants, fromIdentityRes.Grants)
	if len(onlyToken) == 0 && len(onlyIdentity) == 0 {
		s.log.DebugContext(
			ctx, "patreon-identity: identity agrees with the token",
			slog.String("account_id", account),
			slog.Bool("stale", answer.Stale),
		)
		return
	}
	s.log.InfoContext(
		ctx, "patreon-identity: identity and the token grant differently",
		slog.String("account_id", account),
		slog.Any("only_token", onlyToken),
		slog.Any("only_identity", onlyIdentity),
		slog.Bool("stale", answer.Stale),
		slog.Time("fetched_at", answer.FetchedAt),
	)
}

// grantDifference returns the FQNs only in a, and only in b, sorted.
func grantDifference(a, b []source.Grant) ([]string, []string) {
	inA := map[string]bool{}
	for _, g := range a {
		inA[g.FQN] = true
	}
	inB := map[string]bool{}
	for _, g := range b {
		inB[g.FQN] = true
	}
	var onlyA, onlyB []string
	for fqn := range inA {
		if !inB[fqn] {
			onlyA = append(onlyA, fqn)
		}
	}
	for fqn := range inB {
		if !inA[fqn] {
			onlyB = append(onlyB, fqn)
		}
	}
	slices.Sort(onlyA)
	slices.Sort(onlyB)
	return onlyA, onlyB
}

// logLookupFailure logs a misconfiguration at WARN, since it fails every
// account, and an outage at DEBUG, since stale answers and failure_backoff
// already bound its effect.
func (s *patreonIdentitySource) logLookupFailure(ctx context.Context, account string, err error) {
	var lookupErr *identityentities.Error
	if errors.As(err, &lookupErr) && lookupErr.Misconfiguration() {
		s.log.WarnContext(ctx, "patreon-identity: identity lookup failed", slog.String("reason", lookupErr.Reason))
		return
	}
	s.log.DebugContext(
		ctx, "patreon-identity: identity lookup failed",
		slog.String("account_id", account),
		slog.Any("error", err),
	)
}
