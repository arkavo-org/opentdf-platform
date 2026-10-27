package identityentities

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/opentdf/platform/service/internal/servicetoken"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const (
	testAccount      = "0715eaff-3d61-49e0-b553-c0cda78410b0"
	fakeClientID     = "opentdf-platform"
	fakeClientSecret = "s3cret-client-value"
	fakeTokenPrefix  = "svc-cwt-"
	campaignValue    = "https://patreon.arkavo.com/attr/campaign/value/13167240"
)

// fakeIdentity serves the token endpoint and GET /entities/arkavo:<uuid>.
// handler, when set, replaces the default entities answer (200, the
// account's claims with one campaign value).
type fakeIdentity struct {
	mu        sync.Mutex
	tokenCode int
	mints     int
	lookups   int
	handler   func(w http.ResponseWriter, r *http.Request, n int)
	headers   []http.Header
}

func (f *fakeIdentity) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path == "/oauth/token" {
		f.mu.Lock()
		defer f.mu.Unlock()
		id, secret, ok := r.BasicAuth()
		if !ok || id != fakeClientID || secret != fakeClientSecret {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		if f.tokenCode != 0 {
			w.WriteHeader(f.tokenCode)
			return
		}
		f.mints++
		_ = json.NewEncoder(w).Encode(map[string]any{
			"access_token": fmt.Sprintf("%s%d", fakeTokenPrefix, f.mints),
			"expires_in":   3600,
		})
		return
	}
	f.mu.Lock()
	f.lookups++
	n := f.lookups
	f.headers = append(f.headers, r.Header.Clone())
	h := f.handler
	f.mu.Unlock()
	if h != nil {
		h(w, r, n)
		return
	}
	writeEntity(w, strings.TrimPrefix(r.URL.Path, entitiesPath))
}

func (f *fakeIdentity) count() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.lookups
}

func writeEntity(w http.ResponseWriter, account string) {
	_ = json.NewEncoder(w).Encode(map[string]any{
		"id":       "arkavo:" + account,
		"category": "subject",
		"npe_type": nil,
		"claims": map[string]any{
			"sub":                 "arkavo:" + account,
			"arkavo_account_id":   account,
			"arkavo_roles":        []string{"user"},
			"arkavo_entitlements": []string{campaignValue},
		},
	})
}

func status(code int, body string) func(http.ResponseWriter, *http.Request, int) {
	return func(w http.ResponseWriter, _ *http.Request, _ int) {
		w.WriteHeader(code)
		_, _ = w.Write([]byte(body))
	}
}

type clock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *clock) now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.t
}

func (c *clock) advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.t = c.t.Add(d)
}

func newClient(t *testing.T, mutate func(*Config)) (*Client, *fakeIdentity, *clock) {
	t.Helper()
	f := &fakeIdentity{}
	srv := httptest.NewServer(f)
	t.Cleanup(srv.Close)
	cfg := Config{URL: srv.URL, ClientID: fakeClientID, ClientSecret: fakeClientSecret}
	if mutate != nil {
		mutate(&cfg)
	}
	c, err := New(cfg)
	require.NoError(t, err)
	clk := &clock{t: time.Unix(1_800_000_000, 0)}
	c.WithClock(clk.now)
	return c, f, clk
}

func lookupErr(t *testing.T, err error) *Error {
	t.Helper()
	var e *Error
	require.ErrorAs(t, err, &e)
	return e
}

func TestLookup_ReturnsClaims(t *testing.T) {
	c, f, _ := newClient(t, nil)
	a, err := c.Lookup(t.Context(), testAccount)
	require.NoError(t, err)
	assert.False(t, a.Stale)
	assert.Equal(t, testAccount, a.Claims["arkavo_account_id"])
	assert.Equal(t, []any{campaignValue}, a.Claims["arkavo_entitlements"])
	require.Len(t, f.headers, 1)
	assert.Equal(t, fakeTokenPrefix+"1", f.headers[0].Get(authHeader), "the service CWT goes in X-Auth-Token")
	assert.Empty(t, f.headers[0].Get("Authorization"))
}

func TestLookup_CachesForCacheTTL(t *testing.T) {
	c, f, clk := newClient(t, func(c *Config) { c.CacheTTL = 10 * time.Second })
	for range 3 {
		_, err := c.Lookup(t.Context(), testAccount)
		require.NoError(t, err)
	}
	assert.Equal(t, 1, f.count())
	clk.advance(10 * time.Second)
	_, err := c.Lookup(t.Context(), testAccount)
	require.NoError(t, err)
	assert.Equal(t, 2, f.count(), "asked again once cache_ttl passes")
}

func TestLookup_UnknownAccountIsAFreshAnswer(t *testing.T) {
	c, f, _ := newClient(t, nil)
	f.handler = status(http.StatusNotFound, "")
	a, err := c.Lookup(t.Context(), testAccount)
	require.NoError(t, err)
	assert.Nil(t, a.Claims)
	assert.False(t, a.Stale)
}

func TestLookup_Failures(t *testing.T) {
	for name, tc := range map[string]struct {
		handler func(http.ResponseWriter, *http.Request, int)
		reason  string
	}{
		"503 patreon_unavailable": {status(http.StatusServiceUnavailable, `{"error":"patreon_unavailable"}`), ReasonPatreonUnavailable},
		"503 other":               {status(http.StatusServiceUnavailable, ``), ReasonUnavailable},
		"500":                     {status(http.StatusInternalServerError, ``), ReasonUnavailable},
		"403":                     {status(http.StatusForbidden, ``), ReasonForbidden},
		"302 is not followed":     {status(http.StatusFound, ``), ReasonUnavailable},
		"not JSON":                {status(http.StatusOK, `nope`), ReasonMalformed},
		"trailing data":           {status(http.StatusOK, `{"claims":{"arkavo_account_id":"`+testAccount+`"}} {}`), ReasonMalformed},
		"another account": {func(w http.ResponseWriter, _ *http.Request, _ int) {
			writeEntity(w, "00000000-0000-0000-0000-000000000001")
		}, ReasonMalformed},
	} {
		t.Run(name, func(t *testing.T) {
			c, f, _ := newClient(t, nil)
			f.handler = tc.handler
			_, err := c.Lookup(t.Context(), testAccount)
			assert.Equal(t, tc.reason, lookupErr(t, err).Reason)
		})
	}
}

func TestLookup_403IsMisconfiguration(t *testing.T) {
	c, f, _ := newClient(t, nil)
	f.handler = status(http.StatusForbidden, ``)
	_, err := c.Lookup(t.Context(), testAccount)
	assert.True(t, lookupErr(t, err).Misconfiguration())
}

func TestLookup_401RemintsOnce(t *testing.T) {
	t.Run("recovers", func(t *testing.T) {
		c, f, _ := newClient(t, nil)
		f.handler = func(w http.ResponseWriter, r *http.Request, n int) {
			if n == 1 {
				w.WriteHeader(http.StatusUnauthorized)
				return
			}
			writeEntity(w, strings.TrimPrefix(r.URL.Path, entitiesPath))
		}
		_, err := c.Lookup(t.Context(), testAccount)
		require.NoError(t, err)
		assert.Equal(t, fakeTokenPrefix+"2", f.headers[1].Get(authHeader))
	})
	t.Run("always 401", func(t *testing.T) {
		c, f, _ := newClient(t, nil)
		f.handler = status(http.StatusUnauthorized, ``)
		_, err := c.Lookup(t.Context(), testAccount)
		assert.Equal(t, ReasonUnauthorized, lookupErr(t, err).Reason)
		assert.Equal(t, 2, f.count())
	})
}

func TestLookup_TokenRejected(t *testing.T) {
	c, f, _ := newClient(t, nil)
	f.tokenCode = http.StatusUnauthorized
	_, err := c.Lookup(t.Context(), testAccount)
	e := lookupErr(t, err)
	assert.Equal(t, ReasonCredentialsRejected, e.Reason)
	require.ErrorIs(t, err, servicetoken.ErrCredentialsRejected)
	assert.Zero(t, f.count())
}

func TestLookup_StaleOnError(t *testing.T) {
	c, f, clk := newClient(t, func(c *Config) {
		c.CacheTTL = 10 * time.Second
		c.StaleMaxAge = time.Hour
		c.FailureBackoff = 30 * time.Second
	})
	first, err := c.Lookup(t.Context(), testAccount)
	require.NoError(t, err)

	f.handler = status(http.StatusServiceUnavailable, `{"error":"patreon_unavailable"}`)
	clk.advance(time.Minute)
	a, err := c.Lookup(t.Context(), testAccount)
	require.NoError(t, err, "identity is down: the last answer is served")
	assert.True(t, a.Stale)
	assert.Equal(t, first.FetchedAt, a.FetchedAt)
	assert.Equal(t, first.Claims, a.Claims)

	// Within failure_backoff identity is not asked again.
	asked := f.count()
	clk.advance(10 * time.Second)
	a, err = c.Lookup(t.Context(), testAccount)
	require.NoError(t, err)
	assert.True(t, a.Stale)
	assert.Equal(t, asked, f.count(), "failure_backoff holds off identity")

	// Past stale_max_age nothing is served.
	clk.advance(time.Hour)
	_, err = c.Lookup(t.Context(), testAccount)
	assert.Equal(t, ReasonPatreonUnavailable, lookupErr(t, err).Reason)
}

func TestLookup_FailureBackoffWithNothingStale(t *testing.T) {
	c, f, clk := newClient(t, func(c *Config) { c.FailureBackoff = 30 * time.Second })
	f.handler = status(http.StatusServiceUnavailable, `{"error":"patreon_unavailable"}`)
	_, err := c.Lookup(t.Context(), testAccount)
	assert.Equal(t, ReasonPatreonUnavailable, lookupErr(t, err).Reason)
	_, err = c.Lookup(t.Context(), testAccount)
	assert.Equal(t, ReasonBackoff, lookupErr(t, err).Reason, "a second decision is refused at once")
	assert.Equal(t, 1, f.count())

	f.handler = nil
	clk.advance(30 * time.Second)
	_, err = c.Lookup(t.Context(), testAccount)
	require.NoError(t, err, "identity is asked again once failure_backoff passes")
}

func TestLookup_OneCallPerAccountInFlight(t *testing.T) {
	c, f, _ := newClient(t, nil)
	release := make(chan struct{})
	f.handler = func(w http.ResponseWriter, r *http.Request, _ int) {
		<-release
		writeEntity(w, strings.TrimPrefix(r.URL.Path, entitiesPath))
	}
	var wg sync.WaitGroup
	errs := make(chan error, 8)
	for range 8 {
		wg.Go(func() {
			_, err := c.Lookup(t.Context(), testAccount)
			errs <- err
		})
	}
	require.Eventually(t, func() bool { return f.count() == 1 }, time.Second, time.Millisecond)
	close(release)
	wg.Wait()
	close(errs)
	for err := range errs {
		require.NoError(t, err)
	}
	assert.Equal(t, 1, f.count(), "concurrent lookups for one account share one call")
}

func TestLookup_CallerGivingUpDoesNotFailOthers(t *testing.T) {
	c, f, _ := newClient(t, nil)
	release := make(chan struct{})
	f.handler = func(w http.ResponseWriter, r *http.Request, _ int) {
		<-release
		writeEntity(w, strings.TrimPrefix(r.URL.Path, entitiesPath))
	}
	ctx, cancel := context.WithCancel(t.Context())
	done := make(chan error, 1)
	go func() {
		_, err := c.Lookup(ctx, testAccount)
		done <- err
	}()
	require.Eventually(t, func() bool { return f.count() == 1 }, time.Second, time.Millisecond)
	cancel()
	assert.Equal(t, ReasonUnavailable, lookupErr(t, <-done).Reason)

	waiter := make(chan error, 1)
	go func() {
		_, err := c.Lookup(t.Context(), testAccount)
		waiter <- err
	}()
	close(release)
	require.NoError(t, <-waiter)
	assert.Equal(t, 1, f.count(), "the flight kept going for the caller still waiting")
}

func TestLookup_Timeout(t *testing.T) {
	c, f, _ := newClient(t, func(c *Config) { c.Timeout = 50 * time.Millisecond })
	f.handler = func(_ http.ResponseWriter, r *http.Request, _ int) {
		select {
		case <-r.Context().Done():
		case <-time.After(time.Second):
		}
	}
	_, err := c.Lookup(t.Context(), testAccount)
	assert.Equal(t, ReasonUnavailable, lookupErr(t, err).Reason)
}

func TestLookup_RefusesANonCanonicalAccountID(t *testing.T) {
	c, f, _ := newClient(t, nil)
	for _, id := range []string{"", "arkavo:" + testAccount, strings.ToUpper(testAccount), "{" + testAccount + "}", "../admin"} {
		_, err := c.Lookup(t.Context(), id)
		assert.Equal(t, ReasonMalformed, lookupErr(t, err).Reason, id)
	}
	assert.Zero(t, f.count())
}

func TestClient_NeverPrintsTheSecret(t *testing.T) {
	c, _, _ := newClient(t, nil)
	for _, s := range []string{fmt.Sprintf("%v", c), fmt.Sprintf("%+v", c), fmt.Sprintf("%#v", c), c.LogValue().String()} {
		assert.NotContains(t, s, fakeClientSecret)
	}
	cfg := Config{URL: "https://identity.example", ClientID: fakeClientID, ClientSecret: fakeClientSecret}
	assert.NotContains(t, cfg.LogValue().String(), fakeClientSecret)
	assert.NotContains(t, fmt.Sprintf("%+v", cfg), fakeClientSecret)
}

func TestConfig_Validate(t *testing.T) {
	ok := Config{URL: "https://identity.arkavo.net", ClientID: fakeClientID, ClientSecret: fakeClientSecret}
	require.NoError(t, ok.Validate())
	loopback := ok
	loopback.URL = "http://127.0.0.1:8443"
	require.NoError(t, loopback.Validate())
	for name, mutate := range map[string]func(*Config){
		"no url":                 func(c *Config) { c.URL = "" },
		"plain http off-host":    func(c *Config) { c.URL = "http://identity.arkavo.net" },
		"userinfo":               func(c *Config) { c.URL = "https://u:p@identity.arkavo.net" },
		"query":                  func(c *Config) { c.URL = "https://identity.arkavo.net/?x=1" },
		"no client id":           func(c *Config) { c.ClientID = "" },
		"no client secret":       func(c *Config) { c.ClientSecret = "" },
		"cache_ttl above 60s":    func(c *Config) { c.CacheTTL = 61 * time.Second },
		"stale_max_age above 1h": func(c *Config) { c.StaleMaxAge = time.Hour + time.Second },
		"negative timeout":       func(c *Config) { c.Timeout = -1 },
	} {
		t.Run(name, func(t *testing.T) {
			cfg := ok
			mutate(&cfg)
			err := cfg.Validate()
			require.Error(t, err)
			assert.NotContains(t, err.Error(), fakeClientSecret)
		})
	}
	assert.False(t, Config{}.Enabled())
	assert.True(t, Config{ClientID: "x"}.Enabled())
}

var _ Looker = (*Client)(nil)
