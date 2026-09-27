package agentstatus

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const (
	fakeClientID     = "opentdf"
	fakeClientSecret = "s3cret-client-value"
	fakeTokenPrefix  = "svc-cwt-"
	testIncident     = "inc-9"
)

// fakeIdentity stands in for authnz-rs: POST /oauth/token (client_credentials,
// HTTP Basic) and GET /agents/workloads/{id}/status behind X-Auth-Token. Both
// bodies are written from explicit JSON maps in authnz-rs's shape
// (oidc.rs TokenResponse, workload.rs WorkloadStatus), so these tests do not
// lean on Status's own JSON tags.
type fakeIdentity struct {
	mu          sync.Mutex
	status      map[string]any
	rawStatus   string // when set, sent as the 200 status body verbatim
	statusCode  int    // when set, the status endpoint answers only this code
	successCode int    // when set, the status body is sent with this code
	tokenCode   int    // when set, the token endpoint answers only this code
	tokenBody   map[string]any
	reject401   int
	redirectTo  string
	tokenCalls  int
	statusCalls int
	paths       []string
	issued      map[string]bool // every CWT minted; like authnz-rs, any of them is accepted
}

func (f *fakeIdentity) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	switch {
	case r.Method == http.MethodPost && r.URL.Path == "/oauth/token":
		f.serveToken(w, r)
	case r.Method == http.MethodGet && strings.HasPrefix(r.URL.EscapedPath(), "/agents/workloads/"):
		f.serveStatus(w, r)
	default:
		http.NotFound(w, r)
	}
}

func (f *fakeIdentity) serveToken(w http.ResponseWriter, r *http.Request) {
	id, secret, ok := r.BasicAuth()
	if !ok || id != fakeClientID || secret != fakeClientSecret || r.FormValue("grant_type") != "client_credentials" {
		w.WriteHeader(http.StatusUnauthorized)
		return
	}
	f.tokenCalls++
	if f.tokenCode != 0 {
		w.WriteHeader(f.tokenCode)
		return
	}
	token := fmt.Sprintf("%s%d", fakeTokenPrefix, f.tokenCalls)
	if f.issued == nil {
		f.issued = make(map[string]bool)
	}
	f.issued[token] = true
	body := map[string]any{
		"access_token": token,
		"token_type":   "Bearer",
		"expires_in":   3600,
		"id_token":     "eyJ.id.token",
		"scope":        "openid",
	}
	for k, v := range f.tokenBody {
		body[k] = v
	}
	w.Header().Set("Cache-Control", "no-store")
	_ = json.NewEncoder(w).Encode(body)
}

func (f *fakeIdentity) serveStatus(w http.ResponseWriter, r *http.Request) {
	f.statusCalls++
	f.paths = append(f.paths, r.URL.EscapedPath())
	if f.redirectTo != "" {
		http.Redirect(w, r, f.redirectTo, http.StatusFound)
		return
	}
	if f.reject401 > 0 || !f.issued[r.Header.Get("X-Auth-Token")] {
		if f.reject401 > 0 {
			f.reject401--
		}
		w.WriteHeader(http.StatusUnauthorized)
		return
	}
	if f.statusCode != 0 {
		w.WriteHeader(f.statusCode)
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	if f.successCode != 0 {
		w.WriteHeader(f.successCode)
	}
	if f.rawStatus != "" {
		_, _ = w.Write([]byte(f.rawStatus))
		return
	}
	_ = json.NewEncoder(w).Encode(f.status)
}

func (f *fakeIdentity) set(st map[string]any) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.status = st
}

func (f *fakeIdentity) calls() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.statusCalls
}

func (f *fakeIdentity) tokens() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.tokenCalls
}

func (f *fakeIdentity) requested() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]string(nil), f.paths...)
}

// clock is the test's time source; Check may read it from other goroutines.
type clock struct {
	mu  sync.Mutex
	now time.Time
}

func (c *clock) get() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.now
}

func (c *clock) advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.now = c.now.Add(d)
}

func newTestClient(t *testing.T, f http.Handler) (*Client, *clock, *httptest.Server) {
	t.Helper()
	srv := httptest.NewServer(f)
	t.Cleanup(srv.Close)
	c, err := New(Config{URL: srv.URL, ClientID: fakeClientID, ClientSecret: fakeClientSecret})
	require.NoError(t, err)
	clk := &clock{now: time.Unix(1_790_000_000, 0)}
	c.now = clk.get
	return c, clk, srv
}

// wireStatus is a contract v1 status body for the test workload, as
// authnz-rs's WorkloadStatus serializes it.
func wireStatus(validUntil time.Time, mutate ...func(map[string]any)) map[string]any {
	st := map[string]any{
		"workload":    testWorkload,
		"owner":       "owner-1",
		"current_did": testDID,
		"swarm":       testSwarm,
		"state":       "eligible",
		"generation":  3,
		"incident":    nil,
		"valid_until": validUntil.Unix(),
	}
	for _, m := range mutate {
		m(st)
	}
	return st
}

func withGeneration(g int) func(map[string]any) {
	return func(st map[string]any) { st["generation"] = g }
}

func quarantined(g int) func(map[string]any) {
	return func(st map[string]any) {
		st["state"] = "quarantined"
		st["incident"] = testIncident
		st["generation"] = g
	}
}

func denial(t *testing.T, err error) *DenialError {
	t.Helper()
	var d *DenialError
	require.ErrorAs(t, err, &d)
	return d
}

func denialReason(t *testing.T, err error) string {
	t.Helper()
	return denial(t, err).Reason
}

var _ Checker = (*Client)(nil)

func TestNew(t *testing.T) {
	t.Run("disabled config yields no client", func(t *testing.T) {
		c, err := New(Config{})
		require.Error(t, err)
		assert.Nil(t, c)
	})
	t.Run("enabled config is validated", func(t *testing.T) {
		c, err := New(Config{URL: "http://identity.arkavo.net", ClientID: fakeClientID, ClientSecret: fakeClientSecret})
		require.Error(t, err)
		assert.Nil(t, c)
	})
	t.Run("valid config", func(t *testing.T) {
		c, err := New(Config{URL: "https://identity.arkavo.net", ClientID: fakeClientID, ClientSecret: fakeClientSecret})
		require.NoError(t, err)
		assert.NotNil(t, c)
	})
}

func TestCheck_EligibleAgentPasses(t *testing.T) {
	f := &fakeIdentity{}
	c, clk, _ := newTestClient(t, f)
	f.set(wireStatus(clk.get().Add(5 * time.Second)))

	require.NoError(t, c.Check(t.Context(), subject()), "an eligible check must return a true nil")
	assert.Equal(t, []string{"/agents/workloads/" + testWorkload + "/status"}, f.requested())
	assert.Equal(t, 1, f.tokens())
}

func TestCheck_DeniesQuarantineAndMismatches(t *testing.T) {
	for name, tt := range map[string]struct {
		mutate func(map[string]any)
		reason string
	}{
		"quarantined":       {quarantined(4), ReasonNotEligible},
		"DID mismatch":      {func(s map[string]any) { s["current_did"] = "did:key:z6Mkrotated" }, ReasonDIDMismatch},
		"swarm mismatch":    {func(s map[string]any) { s["swarm"] = "kit-other" }, ReasonSwarmMismatch},
		"owner mismatch":    {func(s map[string]any) { s["owner"] = "owner-2" }, ReasonOwnerMismatch},
		"workload mismatch": {func(s map[string]any) { s["workload"] = "wl-8" }, ReasonWorkloadMismatch},
		// Contract v1: recovery sets current_did to "" (and generation+1)
		// until the owner authorizes again.
		"recovered, not yet re-authorized": {func(s map[string]any) { s["current_did"] = ""; s["generation"] = 4 }, ReasonDIDMismatch},
		// Contract v1: swarm is "" while the workload has no swarm.
		"workload has no swarm": {func(s map[string]any) { s["swarm"] = "" }, ReasonSwarmMismatch},
		"generation absent":     {func(s map[string]any) { delete(s, "generation") }, ReasonMissingGeneration},
	} {
		t.Run(name, func(t *testing.T) {
			f := &fakeIdentity{}
			c, clk, _ := newTestClient(t, f)
			f.set(wireStatus(clk.get().Add(5*time.Second), tt.mutate))
			assert.Equal(t, tt.reason, denialReason(t, c.Check(t.Context(), subject())))
		})
	}
}

func TestCheck_QuarantineCarriesIncident(t *testing.T) {
	f := &fakeIdentity{}
	c, clk, _ := newTestClient(t, f)
	f.set(wireStatus(clk.get().Add(5*time.Second), quarantined(4)))
	d := denial(t, c.Check(t.Context(), subject()))
	assert.Equal(t, ReasonNotEligible, d.Reason)
	assert.Equal(t, testIncident, d.Incident)
	assert.Equal(t, uint64(4), d.Generation)
	assert.Equal(t, testWorkload, d.Workload)
}

func TestCheck_UnreachableDenies(t *testing.T) {
	t.Run("server down", func(t *testing.T) {
		f := &fakeIdentity{}
		c, _, srv := newTestClient(t, f)
		srv.Close()
		assert.Equal(t, ReasonUnreachable, denialReason(t, c.Check(t.Context(), subject())))
	})
	for _, code := range []int{http.StatusInternalServerError, http.StatusNoContent, http.StatusBadRequest} {
		t.Run(http.StatusText(code), func(t *testing.T) {
			f := &fakeIdentity{statusCode: code}
			c, _, _ := newTestClient(t, f)
			assert.Equal(t, ReasonUnreachable, denialReason(t, c.Check(t.Context(), subject())))
		})
	}
	// Only 200 carries a status; any other code denies even with a valid body.
	for _, code := range []int{http.StatusCreated, http.StatusAccepted, http.StatusNonAuthoritativeInfo, http.StatusPartialContent} {
		t.Run(http.StatusText(code)+" with a valid body", func(t *testing.T) {
			f := &fakeIdentity{successCode: code}
			c, clk, _ := newTestClient(t, f)
			f.set(wireStatus(clk.get().Add(5 * time.Second)))
			assert.Equal(t, ReasonUnreachable, denialReason(t, c.Check(t.Context(), subject())))
		})
	}
	t.Run("context canceled", func(t *testing.T) {
		f := &fakeIdentity{}
		c, clk, _ := newTestClient(t, f)
		f.set(wireStatus(clk.get().Add(5 * time.Second)))
		ctx, cancel := context.WithCancel(t.Context())
		cancel()
		assert.Equal(t, ReasonUnreachable, denialReason(t, c.Check(ctx, subject())))
	})
}

// Every body that does not decode as a status denies.
func TestCheck_UndecodableStatusDenies(t *testing.T) {
	for name, tt := range map[string]struct {
		body   func(validUntil int64) string
		reason string
	}{
		"not JSON":            {func(int64) string { return "<html>ok</html>" }, ReasonUnreachable},
		"negative generation": {func(v int64) string { return statusJSON(`"generation":-1`, v) }, ReasonUnreachable},
		"generation a string": {func(v int64) string { return statusJSON(`"generation":"7"`, v) }, ReasonUnreachable},
		"truncated":           {func(int64) string { return `{"workload":"` + testWorkload + `"` }, ReasonUnreachable},
		// The object only closes past the body limit, so the read is cut short.
		"larger than the body limit": {func(v int64) string {
			return `{"pad":"` + strings.Repeat("x", maxBodyBytes) + `",` + statusJSON(`"generation":3`, v)[1:]
		}, ReasonUnreachable},
		// null decodes to a zero Status, which binds to nothing.
		"null": {func(int64) string { return "null" }, ReasonWorkloadMismatch},
	} {
		t.Run(name, func(t *testing.T) {
			f := &fakeIdentity{}
			c, clk, _ := newTestClient(t, f)
			f.rawStatus = tt.body(clk.get().Add(5 * time.Second).Unix())
			assert.Equal(t, tt.reason, denialReason(t, c.Check(t.Context(), subject())))
		})
	}
}

func statusJSON(generation string, validUntil int64) string {
	return fmt.Sprintf(`{"workload":%q,"owner":"owner-1","current_did":%q,"swarm":%q,"state":"eligible",%s,"incident":null,"valid_until":%d}`,
		testWorkload, testDID, testSwarm, generation, validUntil)
}

// The largest body that fits the limit is still accepted.
func TestCheck_BodyWithinLimitAccepted(t *testing.T) {
	f := &fakeIdentity{}
	c, clk, _ := newTestClient(t, f)
	body := statusJSON(`"generation":3`, clk.get().Add(5*time.Second).Unix())
	f.rawStatus = body + strings.Repeat(" ", maxBodyBytes-len(body))
	require.NoError(t, c.Check(t.Context(), subject()))
}

func TestCheck_GenerationHighWater(t *testing.T) {
	t.Run("regression denied and not cached", func(t *testing.T) {
		f := &fakeIdentity{}
		c, clk, _ := newTestClient(t, f)
		f.set(wireStatus(clk.get().Add(5*time.Second), withGeneration(5)))
		require.NoError(t, c.Check(t.Context(), subject()))

		clk.advance(6 * time.Second)
		f.set(wireStatus(clk.get().Add(5*time.Second), withGeneration(4)))
		assert.Equal(t, ReasonGenerationRegressed, denialReason(t, c.Check(t.Context(), subject())))
		assert.Equal(t, ReasonGenerationRegressed, denialReason(t, c.Check(t.Context(), subject())))
		assert.Equal(t, 3, f.calls(), "a regressed status must never be cached")

		// The mark stayed at 5: generation 5 is accepted again, 4 never was.
		f.set(wireStatus(clk.get().Add(5*time.Second), withGeneration(5)))
		require.NoError(t, c.Check(t.Context(), subject()))
	})
	t.Run("a denied status still raises the mark", func(t *testing.T) {
		f := &fakeIdentity{}
		c, clk, _ := newTestClient(t, f)
		f.set(wireStatus(clk.get().Add(5*time.Second), quarantined(6)))
		assert.Equal(t, ReasonNotEligible, denialReason(t, c.Check(t.Context(), subject())))
		assert.Equal(t, ReasonNotEligible, denialReason(t, c.Check(t.Context(), subject())))
		assert.Equal(t, 2, f.calls(), "a denied status must never be cached")

		// A replay of the pre-quarantine eligible status is refused.
		f.set(wireStatus(clk.get().Add(5*time.Second), withGeneration(5)))
		assert.Equal(t, ReasonGenerationRegressed, denialReason(t, c.Check(t.Context(), subject())))
		assert.Equal(t, 3, f.calls())

		f.set(wireStatus(clk.get().Add(5*time.Second), withGeneration(7)))
		require.NoError(t, c.Check(t.Context(), subject()))
		assert.Equal(t, 4, f.calls())
	})
	t.Run("a status for another workload does not move the mark", func(t *testing.T) {
		f := &fakeIdentity{}
		c, clk, _ := newTestClient(t, f)
		f.set(wireStatus(clk.get().Add(5*time.Second), withGeneration(99), func(s map[string]any) {
			s["workload"] = "wl-ffffffffffffffffffffffffffffffff"
		}))
		assert.Equal(t, ReasonWorkloadMismatch, denialReason(t, c.Check(t.Context(), subject())))
		f.set(wireStatus(clk.get().Add(5*time.Second), withGeneration(3)))
		require.NoError(t, c.Check(t.Context(), subject()))
	})
	t.Run("a cache hit is judged against the current mark", func(t *testing.T) {
		f := &fakeIdentity{}
		c, clk, _ := newTestClient(t, f)
		f.set(wireStatus(clk.get().Add(5*time.Second), withGeneration(5)))
		require.NoError(t, c.Check(t.Context(), subject()))
		// Stands in for a concurrent fetch that saw a later generation while
		// generation 5 was still cached.
		c.mu.Lock()
		c.highWater[testWorkload] = 6
		c.mu.Unlock()
		assert.Equal(t, ReasonGenerationRegressed, denialReason(t, c.Check(t.Context(), subject())))
		assert.Equal(t, 1, f.calls())
	})
}

func TestCheck_CacheHonoursValidUntil(t *testing.T) {
	t.Run("cached until valid_until", func(t *testing.T) {
		f := &fakeIdentity{}
		c, clk, _ := newTestClient(t, f)
		f.set(wireStatus(clk.get().Add(2 * time.Second)))
		require.NoError(t, c.Check(t.Context(), subject()))
		require.NoError(t, c.Check(t.Context(), subject()))
		assert.Equal(t, 1, f.calls())
		clk.advance(3 * time.Second)
		require.NoError(t, c.Check(t.Context(), subject()))
		assert.Equal(t, 2, f.calls())
	})
	t.Run("never longer than 5 s", func(t *testing.T) {
		f := &fakeIdentity{}
		c, clk, _ := newTestClient(t, f)
		f.set(wireStatus(clk.get().Add(time.Minute)))
		require.NoError(t, c.Check(t.Context(), subject()))
		clk.advance(4 * time.Second)
		require.NoError(t, c.Check(t.Context(), subject()))
		assert.Equal(t, 1, f.calls())
		clk.advance(2 * time.Second)
		require.NoError(t, c.Check(t.Context(), subject()))
		assert.Equal(t, 2, f.calls())
	})
	// A live answer decides the request it was fetched for, even when this
	// host's clock is past valid_until; it is just not reused.
	for name, validUntil := range map[string]func(now time.Time) map[string]any{
		"valid_until already past (clock skew)": func(now time.Time) map[string]any { return wireStatus(now.Add(-time.Second)) },
		"valid_until equal to now":              func(now time.Time) map[string]any { return wireStatus(now) },
		"valid_until missing": func(now time.Time) map[string]any {
			st := wireStatus(now)
			delete(st, "valid_until")
			return st
		},
	} {
		t.Run(name+": used once, not cached", func(t *testing.T) {
			f := &fakeIdentity{}
			c, clk, _ := newTestClient(t, f)
			f.set(validUntil(clk.get()))
			require.NoError(t, c.Check(t.Context(), subject()))
			require.NoError(t, c.Check(t.Context(), subject()))
			assert.Equal(t, 2, f.calls())
		})
	}
	t.Run("quarantine lands within one lease", func(t *testing.T) {
		f := &fakeIdentity{}
		c, clk, _ := newTestClient(t, f)
		f.set(wireStatus(clk.get().Add(5 * time.Second)))
		require.NoError(t, c.Check(t.Context(), subject()))
		f.set(wireStatus(clk.get().Add(10*time.Second), quarantined(4)))
		clk.advance(5 * time.Second)
		assert.Equal(t, ReasonNotEligible, denialReason(t, c.Check(t.Context(), subject())))
	})
	t.Run("a cached status is judged against each subject", func(t *testing.T) {
		f := &fakeIdentity{}
		c, clk, _ := newTestClient(t, f)
		f.set(wireStatus(clk.get().Add(5 * time.Second)))
		require.NoError(t, c.Check(t.Context(), subject()))
		stale := subject()
		stale.DID = "did:key:z6Mkold"
		assert.Equal(t, ReasonDIDMismatch, denialReason(t, c.Check(t.Context(), stale)))
		assert.Equal(t, 1, f.calls())
	})
}

func TestCheck_ServiceToken(t *testing.T) {
	t.Run("reused until shortly before it expires", func(t *testing.T) {
		f := &fakeIdentity{}
		c, clk, _ := newTestClient(t, f)
		f.set(wireStatus(clk.get().Add(5 * time.Second)))
		require.NoError(t, c.Check(t.Context(), subject()))
		clk.advance(6 * time.Second)
		f.set(wireStatus(clk.get().Add(5 * time.Second)))
		require.NoError(t, c.Check(t.Context(), subject()))
		assert.Equal(t, 1, f.tokens())

		clk.advance(time.Hour - time.Minute)
		f.set(wireStatus(clk.get().Add(5 * time.Second)))
		require.NoError(t, c.Check(t.Context(), subject()))
		assert.Equal(t, 2, f.tokens())
	})
	t.Run("retried once with a fresh token after a 401", func(t *testing.T) {
		f := &fakeIdentity{reject401: 1}
		c, clk, _ := newTestClient(t, f)
		f.set(wireStatus(clk.get().Add(5 * time.Second)))
		require.NoError(t, c.Check(t.Context(), subject()))
		assert.Equal(t, 2, f.tokens())
		assert.Equal(t, 2, f.calls())
	})
	t.Run("a second 401 denies without another retry", func(t *testing.T) {
		f := &fakeIdentity{reject401: 5}
		c, clk, _ := newTestClient(t, f)
		f.set(wireStatus(clk.get().Add(5 * time.Second)))
		assert.Equal(t, ReasonUnreachable, denialReason(t, c.Check(t.Context(), subject())))
		assert.Equal(t, 2, f.tokens())
		assert.Equal(t, 2, f.calls())
	})
	// The token endpoint's own 404 or 403 says nothing about the workload.
	for _, code := range []int{http.StatusNotFound, http.StatusForbidden, http.StatusUnauthorized, http.StatusInternalServerError} {
		t.Run(fmt.Sprintf("token endpoint %d denies as unreachable", code), func(t *testing.T) {
			f := &fakeIdentity{tokenCode: code}
			c, _, _ := newTestClient(t, f)
			assert.Equal(t, ReasonUnreachable, denialReason(t, c.Check(t.Context(), subject())))
			assert.Equal(t, 1, f.tokens(), "a token failure is not retried")
			assert.Equal(t, 0, f.calls())
		})
	}
	t.Run("wrong client secret denies", func(t *testing.T) {
		f := &fakeIdentity{}
		srv := httptest.NewServer(f)
		t.Cleanup(srv.Close)
		c, err := New(Config{URL: srv.URL, ClientID: fakeClientID, ClientSecret: "wrong"})
		require.NoError(t, err)
		assert.Equal(t, ReasonUnreachable, denialReason(t, c.Check(t.Context(), subject())))
		assert.Equal(t, 0, f.calls())
	})
	for name, body := range map[string]map[string]any{
		"empty access_token":  {"access_token": ""},
		"access_token absent": {"access_token": nil},
	} {
		t.Run(name, func(t *testing.T) {
			f := &fakeIdentity{tokenBody: body}
			c, _, _ := newTestClient(t, f)
			assert.Equal(t, ReasonUnreachable, denialReason(t, c.Check(t.Context(), subject())))
			assert.Equal(t, 0, f.calls())
		})
	}
	for name, expiresIn := range map[string]any{
		"expires_in absent": nil,
		"expires_in a week": 7 * 24 * 3600,
		"expires_in huge":   int64(1) << 62,
	} {
		t.Run(name, func(t *testing.T) {
			f := &fakeIdentity{tokenBody: map[string]any{"expires_in": expiresIn}}
			c, clk, _ := newTestClient(t, f)
			f.set(wireStatus(clk.get().Add(5 * time.Second)))
			require.NoError(t, c.Check(t.Context(), subject()))
			clk.advance(48 * time.Hour)
			f.set(wireStatus(clk.get().Add(5 * time.Second)))
			require.NoError(t, c.Check(t.Context(), subject()))
			assert.Equal(t, 2, f.tokens(), "a token is never trusted past maxTokenLifetime")
		})
	}
}

// A redirect is a non-200 answer: it denies, and the service CWT is never
// forwarded to wherever it points.
func TestCheck_RedirectNotFollowed(t *testing.T) {
	var elsewhere sync.Mutex
	var seen []string
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		elsewhere.Lock()
		defer elsewhere.Unlock()
		seen = append(seen, r.Header.Get("X-Auth-Token"))
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(target.Close)
	f := &fakeIdentity{redirectTo: target.URL + "/collect"}
	c, _, _ := newTestClient(t, f)
	assert.Equal(t, ReasonUnreachable, denialReason(t, c.Check(t.Context(), subject())))
	elsewhere.Lock()
	defer elsewhere.Unlock()
	assert.Empty(t, seen)
}

func TestCheck_RefusesUnscopedTokensWithoutCalling(t *testing.T) {
	f := &fakeIdentity{}
	c, _, _ := newTestClient(t, f)
	for _, tt := range []struct {
		s      Subject
		reason string
	}{
		{Subject{Workload: testWorkload, Swarm: testSwarm, Owner: "owner-1"}, ReasonMissingSubject},
		{Subject{DID: testDID, Swarm: testSwarm, Owner: "owner-1"}, ReasonMissingWorkload},
		{Subject{DID: testDID, Workload: testWorkload, Owner: "owner-1"}, ReasonMissingSwarm},
		{Subject{DID: testDID, Workload: testWorkload, Swarm: testSwarm}, ReasonMissingOwner},
		{Subject{DID: testDID, Workload: "..", Swarm: testSwarm, Owner: "owner-1"}, ReasonMalformedWorkload},
		{Subject{DID: testDID, Workload: "a/b", Swarm: testSwarm, Owner: "owner-1"}, ReasonMalformedWorkload},
		{Subject{DID: testDID, Workload: "wl-00112233445566778899aabbccddeeff%2f", Swarm: testSwarm, Owner: "owner-1"}, ReasonMalformedWorkload},
		{Subject{DID: testDID, Owner: "owner-1", Workload: "wl-7", Swarm: testSwarm}, ReasonMalformedWorkload},
	} {
		assert.Equal(t, tt.reason, denialReason(t, c.Check(t.Context(), tt.s)), "%+v", tt.s)
	}
	assert.Equal(t, 0, f.calls())
	assert.Equal(t, 0, f.tokens())
}

// The fetch path refuses a malformed id on its own too, so no future caller
// can put an unchecked id into the status URL.
func TestStatusRefusesMalformedWorkload(t *testing.T) {
	f := &fakeIdentity{}
	c, _, _ := newTestClient(t, f)
	_, err := c.fetchOnce(t.Context(), "../../oauth/token", false)
	require.Error(t, err)
	assert.Equal(t, 0, f.calls())
	assert.Equal(t, 0, f.tokens())
}

// Contract v1 errors: 404 unknown workload and 403 (this platform's client
// is not in AGENT_STATUS_CLIENT_IDS) both deny, each with its own reason so
// the log names the misconfiguration.
func TestCheck_NotFoundAndForbiddenDeny(t *testing.T) {
	for code, reason := range map[int]string{
		http.StatusNotFound:  ReasonUnknownWorkload,
		http.StatusForbidden: ReasonStatusForbidden,
	} {
		t.Run(http.StatusText(code), func(t *testing.T) {
			f := &fakeIdentity{statusCode: code}
			c, _, _ := newTestClient(t, f)
			assert.Equal(t, reason, denialReason(t, c.Check(t.Context(), subject())))
		})
	}
}

func TestCheck_Concurrent(t *testing.T) {
	other := "wl-ffeeddccbbaa99887766554433221100"
	f := &fakeIdentity{}
	c, clk, _ := newTestClient(t, f)
	f.set(wireStatus(clk.get().Add(5 * time.Second)))

	var wg sync.WaitGroup
	errs := make(chan error, 64)
	for i := range 64 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			s := subject()
			if i%2 == 1 {
				s.Workload = other
			}
			if i%8 == 0 {
				clk.advance(time.Second)
			}
			errs <- c.Check(t.Context(), s)
		}()
	}
	wg.Wait()
	close(errs)
	var allowed, workloadMismatch int
	for err := range errs {
		if err == nil {
			allowed++
			continue
		}
		// The fake answers with testWorkload's status for every id.
		require.Equal(t, ReasonWorkloadMismatch, denialReason(t, err))
		workloadMismatch++
	}
	assert.Equal(t, 32, allowed)
	assert.Equal(t, 32, workloadMismatch)
}

// Neither the client secret nor the service CWT reaches an error, a log line
// or a formatted Client.
func TestSecretsNeverRendered(t *testing.T) {
	var errs []error
	for _, f := range []*fakeIdentity{
		{tokenCode: http.StatusUnauthorized},
		{reject401: 5},
		{statusCode: http.StatusInternalServerError},
		{rawStatus: "not json"},
		{tokenBody: map[string]any{"expires_in": "soon"}},
	} {
		c, clk, _ := newTestClient(t, f)
		f.set(wireStatus(clk.get().Add(5 * time.Second)))
		err := c.Check(t.Context(), subject())
		require.Error(t, err)
		errs = append(errs, err)
	}

	f := &fakeIdentity{}
	c, clk, _ := newTestClient(t, f)
	f.set(wireStatus(clk.get().Add(5 * time.Second)))
	require.NoError(t, c.Check(t.Context(), subject()))
	c.mu.Lock()
	require.Equal(t, fakeTokenPrefix+"1", string(c.token), "the client holds a token to leak")
	c.mu.Unlock()

	var rendered []string
	for _, err := range errs {
		for _, verb := range []string{"%v", "%+v", "%#v", "%s", "%q"} {
			rendered = append(rendered, fmt.Sprintf(verb, err))
		}
	}
	for _, verb := range []string{"%v", "%+v", "%#v", "%s", "%d", "%q", "%x"} {
		rendered = append(rendered, fmt.Sprintf(verb, c))
	}
	var buf bytes.Buffer
	for _, h := range []slog.Handler{slog.NewTextHandler(&buf, nil), slog.NewJSONHandler(&buf, nil)} {
		slog.New(h).Info("checker",
			slog.Any("client", c),
			slog.Any("err", errs[0]),
		)
	}
	rendered = append(rendered, buf.String())
	for _, r := range rendered {
		assert.NotContains(t, r, fakeClientSecret)
		assert.NotContains(t, r, fakeTokenPrefix)
	}
}
