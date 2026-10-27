package composite

import (
	"bytes"
	"context"
	"log/slog"
	"strings"
	"sync"
	"testing"
	"time"

	patreon "github.com/opentdf/platform/service/entityresolution/patreon/v2"
	"github.com/opentdf/platform/service/entityresolution/source"
	"github.com/opentdf/platform/service/internal/identityentities"
	"github.com/opentdf/platform/service/logger"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const identityAccount = "0715eaff-3d61-49e0-b553-c0cda78410b0"

// fakeLooker answers every lookup with answer or err, and counts lookups.
type fakeLooker struct {
	mu      sync.Mutex
	answer  identityentities.Answer
	err     error
	lookups []string
}

func (f *fakeLooker) Lookup(_ context.Context, accountID string) (identityentities.Answer, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.lookups = append(f.lookups, accountID)
	return f.answer, f.err
}

func (f *fakeLooker) count() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.lookups)
}

// syncBuffer is a bytes.Buffer safe for the comparison goroutine to write
// while the test reads.
type syncBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *syncBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *syncBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

func syncLogger() (*logger.Logger, *syncBuffer) {
	buf := &syncBuffer{}
	return &logger.Logger{Logger: slog.New(slog.NewJSONHandler(buf, &slog.HandlerOptions{Level: slog.LevelDebug}))}, buf
}

// patronOf is a patron's claims of campaign at tier, as identity mints them.
func patronOf(account, campaign, tier string) map[string]any {
	return map[string]any{
		"arkavo_account_id": account,
		"arkavo_patreon": map[string]any{"role": "consumer", "memberships": []any{map[string]any{
			"campaign_id": campaign, "patron_status": "active_patron", "tier_slugs": []any{tier},
		}}},
		"arkavo_entitlements": []any{
			patreonAttrNS + "campaign/value/" + campaign,
			patreonAttrNS + "campaign-tier/value/" + campaign + "_" + tier,
		},
	}
}

func personSubject(claims map[string]any) source.Subject {
	return source.Subject{Claims: claims, Kind: source.KindPerson, AccountID: identityAccount, Trust: source.TrustVerified}
}

func resolvedFQNs(t *testing.T, res source.Resolution) []string {
	t.Helper()
	out := make([]string, 0, len(res.Grants))
	for _, g := range res.Grants {
		out = append(out, g.FQN)
	}
	return out
}

func newIdentitySource(looker identityentities.Looker, serve string) (*patreonIdentitySource, *syncBuffer) {
	log, buf := syncLogger()
	return newPatreonIdentitySource(patreon.NewTokenSource(patreon.SourceConfig{}), looker, serve, log), buf
}

func TestPatreonIdentity_ServeIdentityGrantsFromIdentity(t *testing.T) {
	looker := &fakeLooker{answer: identityentities.Answer{Claims: patronOf(identityAccount, "13167240", "supporter"), FetchedAt: time.Now()}}
	src, _ := newIdentitySource(looker, serveIdentity)

	// The token says the person backs another campaign; identity wins.
	res, err := src.Resolve(t.Context(), personSubject(patronOf(identityAccount, "7237273", "vip")), source.Query{})
	require.NoError(t, err)
	assert.Equal(t, source.OutcomeComplete, res.Outcome)
	assert.ElementsMatch(t, []string{
		patreonAttrNS + "campaign/value/13167240",
		patreonAttrNS + "campaign-tier/value/13167240_supporter",
	}, resolvedFQNs(t, res))
	assert.Equal(t, "active", res.Properties["status"], "the .patreon view comes from identity too")
	assert.Equal(t, []string{identityAccount}, looker.lookups)
}

func TestPatreonIdentity_ServeIdentityFailureGrantsNothing(t *testing.T) {
	for name, err := range map[string]error{
		"outage":           &identityentities.Error{Reason: identityentities.ReasonPatreonUnavailable},
		"misconfiguration": &identityentities.Error{Reason: identityentities.ReasonForbidden},
	} {
		t.Run(name, func(t *testing.T) {
			src, buf := newIdentitySource(&fakeLooker{err: err}, serveIdentity)
			res, rErr := src.Resolve(t.Context(), personSubject(patronOf(identityAccount, "13167240", "supporter")), source.Query{})
			require.NoError(t, rErr)
			assert.Equal(t, source.OutcomeUnavailable, res.Outcome)
			assert.Empty(t, res.Grants, "the token's claims are not a fallback")
			if name == "misconfiguration" {
				assert.Contains(t, buf.String(), `"level":"WARN"`)
				assert.Contains(t, buf.String(), "ENTITY_CLIENT_IDS")
			}
		})
	}
}

func TestPatreonIdentity_ServeIdentityUnknownAccount(t *testing.T) {
	src, _ := newIdentitySource(&fakeLooker{answer: identityentities.Answer{FetchedAt: time.Now()}}, serveIdentity)
	res, err := src.Resolve(t.Context(), personSubject(patronOf(identityAccount, "13167240", "supporter")), source.Query{})
	require.NoError(t, err)
	assert.Empty(t, res.Grants)
}

func TestPatreonIdentity_ServeIdentityOnlyLooksUpPersons(t *testing.T) {
	looker := &fakeLooker{answer: identityentities.Answer{Claims: patronOf(identityAccount, "13167240", "supporter")}}
	src, _ := newIdentitySource(looker, serveIdentity)
	for name, subj := range map[string]source.Subject{
		"agent":         {Kind: source.KindAgent, AccountID: identityAccount, Claims: map[string]any{}},
		"device":        {Kind: source.KindDevice, AccountID: identityAccount, Claims: map[string]any{}},
		"no account id": {Kind: source.KindPerson, Claims: map[string]any{}},
	} {
		res, err := src.Resolve(t.Context(), subj, source.Query{})
		require.NoError(t, err, name)
		assert.Equal(t, source.OutcomeNotApplicable, res.Outcome, name)
	}
	assert.Zero(t, looker.count())
}

func TestPatreonIdentity_ServeTokenGrantsFromTokenAndCompares(t *testing.T) {
	// Identity knows a tier the token predates.
	fromIdentity := patronOf(identityAccount, "13167240", "supporter")
	fromIdentity["arkavo_entitlements"] = []any{
		patreonAttrNS + "campaign/value/13167240",
		patreonAttrNS + "campaign-tier/value/13167240_supporter",
		patreonAttrNS + "campaign-tier/value/13167240_vip",
	}
	looker := &fakeLooker{answer: identityentities.Answer{Claims: fromIdentity, FetchedAt: time.Now()}}
	src, buf := newIdentitySource(looker, serveToken)

	res, err := src.Resolve(t.Context(), personSubject(patronOf(identityAccount, "13167240", "supporter")), source.Query{})
	require.NoError(t, err)
	assert.ElementsMatch(t, []string{
		patreonAttrNS + "campaign/value/13167240",
		patreonAttrNS + "campaign-tier/value/13167240_supporter",
	}, resolvedFQNs(t, res), "serving the token, identity changes nothing")

	require.Eventually(t, func() bool { return strings.Contains(buf.String(), "grant differently") }, time.Second, time.Millisecond)
	logs := buf.String()
	assert.Contains(t, logs, `"level":"INFO"`)
	assert.Contains(t, logs, `"only_identity":["`+patreonAttrNS+`campaign-tier/value/13167240_vip"]`)
	assert.Contains(t, logs, `"only_token":null`)
	assert.Contains(t, logs, identityAccount)
}

func TestPatreonIdentity_ServeTokenComparesEachAccountOncePerMinute(t *testing.T) {
	looker := &fakeLooker{answer: identityentities.Answer{Claims: patronOf(identityAccount, "13167240", "supporter")}}
	src, buf := newIdentitySource(looker, serveToken)
	now := time.Unix(1_800_000_000, 0)
	src.now = func() time.Time { return now }
	subj := personSubject(patronOf(identityAccount, "13167240", "supporter"))

	for range 5 {
		_, err := src.Resolve(t.Context(), subj, source.Query{})
		require.NoError(t, err)
	}
	require.Eventually(t, func() bool { return strings.Contains(buf.String(), "agrees with the token") }, time.Second, time.Millisecond)
	assert.Equal(t, 1, looker.count())

	now = now.Add(compareEvery)
	_, err := src.Resolve(t.Context(), subj, source.Query{})
	require.NoError(t, err)
	require.Eventually(t, func() bool { return looker.count() == 2 }, time.Second, time.Millisecond)
}

func TestPatreonIdentity_ServeTokenNeverWaitsForIdentity(t *testing.T) {
	block := make(chan struct{})
	t.Cleanup(func() { close(block) })
	src, _ := newIdentitySource(blockingLooker{block}, serveToken)
	start := time.Now()
	res, err := src.Resolve(t.Context(), personSubject(patronOf(identityAccount, "13167240", "supporter")), source.Query{})
	require.NoError(t, err)
	assert.Equal(t, source.OutcomeComplete, res.Outcome)
	assert.Less(t, time.Since(start), 100*time.Millisecond)
}

type blockingLooker struct{ block chan struct{} }

func (b blockingLooker) Lookup(ctx context.Context, _ string) (identityentities.Answer, error) {
	select {
	case <-b.block:
	case <-ctx.Done():
	}
	return identityentities.Answer{}, &identityentities.Error{Reason: identityentities.ReasonUnavailable}
}

func TestGrantDifference(t *testing.T) {
	a := []source.Grant{{FQN: "x"}, {FQN: "y"}, {FQN: "y"}}
	b := []source.Grant{{FQN: "y"}, {FQN: "z"}}
	onlyA, onlyB := grantDifference(a, b)
	assert.Equal(t, []string{"x"}, onlyA)
	assert.Equal(t, []string{"z"}, onlyB)
}
