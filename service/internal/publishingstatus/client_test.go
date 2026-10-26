package publishingstatus

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/opentdf/platform/service/internal/servicetoken"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const (
	testSub          = "arkavo:abc"
	fakeClientID     = "opentdf"
	fakeClientSecret = "s3cret-client-value"
	fakeTokenPrefix  = "svc-cwt-"
	suspPrefix       = "/moderation/v1/suspensions/"
)

// fakeIdentity stands in for authnz-rs's token endpoint.
type fakeIdentity struct {
	mu        sync.Mutex
	tokenCode int
	mints     int
}

func (f *fakeIdentity) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	id, secret, ok := r.BasicAuth()
	if r.URL.Path != "/oauth/token" || !ok || id != fakeClientID || secret != fakeClientSecret {
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
		"token_type":   "Bearer",
		"expires_in":   3600,
	})
}

func (f *fakeIdentity) minted() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.mints
}

// fakeArks serves the suspension read. handler, when set, replaces the
// default answer (200 not suspended, echoing the subject from the path).
type fakeArks struct {
	mu       sync.Mutex
	handler  func(w http.ResponseWriter, r *http.Request, n int)
	requests int
	headers  []http.Header
	paths    []string
}

func (f *fakeArks) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	f.requests++
	n := f.requests
	f.headers = append(f.headers, r.Header.Clone())
	f.paths = append(f.paths, r.URL.EscapedPath())
	h := f.handler
	f.mu.Unlock()
	if h != nil {
		h(w, r, n)
		return
	}
	writeAnswer(w, subjectOf(r), false)
}

func (f *fakeArks) count() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.requests
}

func subjectOf(r *http.Request) string {
	seg := strings.TrimPrefix(r.URL.EscapedPath(), suspPrefix)
	sub, err := url.PathUnescape(seg)
	if err != nil {
		return ""
	}
	return sub
}

func writeAnswer(w http.ResponseWriter, sub string, suspended bool) {
	body := map[string]any{"subject": sub, "suspended": suspended}
	if suspended {
		body["since"] = "2026-10-25T00:00:00Z"
		body["reportId"] = "r1"
	}
	_ = json.NewEncoder(w).Encode(body)
}

type env struct {
	client   *Client
	identity *fakeIdentity
	arks     *fakeArks
}

func newEnv(t *testing.T, mutate func(*Config)) *env {
	t.Helper()
	e := &env{identity: &fakeIdentity{}, arks: &fakeArks{}}
	idSrv := httptest.NewServer(e.identity)
	t.Cleanup(idSrv.Close)
	arksSrv := httptest.NewServer(e.arks)
	t.Cleanup(arksSrv.Close)
	cfg := Config{
		URL:          arksSrv.URL,
		IdentityURL:  idSrv.URL,
		ClientID:     fakeClientID,
		ClientSecret: fakeClientSecret,
	}
	if mutate != nil {
		mutate(&cfg)
	}
	c, err := New(cfg)
	require.NoError(t, err)
	e.client = c
	return e
}

func denial(t *testing.T, err error) *DenialError {
	t.Helper()
	var d *DenialError
	require.ErrorAs(t, err, &d)
	return d
}

func TestCheck_NotSuspended(t *testing.T) {
	e := newEnv(t, nil)
	require.NoError(t, e.client.Check(t.Context(), testSub))
	require.Equal(t, 1, e.arks.count())
	h := e.arks.headers[0]
	assert.Equal(t, "Bearer "+fakeTokenPrefix+"1", h.Get("Authorization"))
	assert.Equal(t, "application/json", h.Get("Accept"))
	assert.Empty(t, h.Get("X-Auth-Token"))
	assert.Equal(t, suspPrefix+url.PathEscape(testSub), e.arks.paths[0])
}

func TestCheck_Suspended(t *testing.T) {
	e := newEnv(t, nil)
	e.arks.handler = func(w http.ResponseWriter, r *http.Request, _ int) {
		writeAnswer(w, subjectOf(r), true)
	}
	d := denial(t, e.client.Check(t.Context(), testSub))
	assert.Equal(t, ReasonSuspended, d.Reason)
	assert.Equal(t, testSub, d.Subject)
	assert.Equal(t, "2026-10-25T00:00:00Z", d.Since)
	assert.Equal(t, "r1", d.ReportID)
}

func TestCheck_FailClosed(t *testing.T) {
	bigBody := strings.Repeat(" ", 70<<10) + `{"subject":"` + testSub + `","suspended":false}`
	body := func(s string) func(http.ResponseWriter, *http.Request, int) {
		return func(w http.ResponseWriter, _ *http.Request, _ int) { _, _ = w.Write([]byte(s)) }
	}
	status := func(code int) func(http.ResponseWriter, *http.Request, int) {
		return func(w http.ResponseWriter, _ *http.Request, _ int) { w.WriteHeader(code) }
	}
	cases := []struct {
		name    string
		reason  string
		handler func(http.ResponseWriter, *http.Request, int)
	}{
		{"404", ReasonUnreachable, status(http.StatusNotFound)},
		{"400", ReasonUnreachable, status(http.StatusBadRequest)},
		{"503", ReasonUnreachable, status(http.StatusServiceUnavailable)},
		{"500", ReasonUnreachable, status(http.StatusInternalServerError)},
		{"not json", ReasonMalformedAnswer, body("not json")},
		{"empty object", ReasonMalformedAnswer, body("{}")},
		{"suspended is a string", ReasonMalformedAnswer, body(`{"suspended":"false","subject":"` + testSub + `"}`)},
		{"suspended is null", ReasonMalformedAnswer, body(`{"suspended":null,"subject":"` + testSub + `"}`)},
		{"other subject", ReasonMalformedAnswer, body(`{"suspended":false,"subject":"other"}`)},
		{"oversized body", ReasonMalformedAnswer, body(bigBody)},
		{"trailing data", ReasonMalformedAnswer, body(`{"subject":"` + testSub + `","suspended":false}garbage`)},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			e := newEnv(t, nil)
			e.arks.handler = tc.handler
			d := denial(t, e.client.Check(t.Context(), testSub))
			assert.Equal(t, tc.reason, d.Reason)
		})
	}

	t.Run("302 is not followed", func(t *testing.T) {
		var mu sync.Mutex
		hits := 0
		other := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			mu.Lock()
			hits++
			mu.Unlock()
			writeAnswer(w, testSub, false)
		}))
		defer other.Close()
		e := newEnv(t, nil)
		e.arks.handler = func(w http.ResponseWriter, r *http.Request, _ int) {
			http.Redirect(w, r, other.URL+"/x", http.StatusFound)
		}
		d := denial(t, e.client.Check(t.Context(), testSub))
		assert.Equal(t, ReasonUnreachable, d.Reason)
		mu.Lock()
		defer mu.Unlock()
		assert.Zero(t, hits)
	})
}

func TestCheck_MalformedReasons(t *testing.T) {
	e := newEnv(t, nil)
	e.arks.handler = func(w http.ResponseWriter, _ *http.Request, _ int) {
		_, _ = w.Write([]byte(`{"subject":"other","suspended":false}`))
	}
	assert.Equal(t, ReasonMalformedAnswer, denial(t, e.client.Check(t.Context(), testSub)).Reason)
}

func TestCheck_Timeout(t *testing.T) {
	e := newEnv(t, func(c *Config) { c.Timeout = 100 * time.Millisecond })
	e.arks.handler = func(w http.ResponseWriter, r *http.Request, _ int) {
		select {
		case <-time.After(2 * time.Second):
		case <-r.Context().Done():
		}
		writeAnswer(w, subjectOf(r), false)
	}
	start := time.Now()
	d := denial(t, e.client.Check(t.Context(), testSub))
	assert.Equal(t, ReasonUnreachable, d.Reason)
	assert.Less(t, time.Since(start), 700*time.Millisecond)
}

func TestCheck_401RemintsOnce(t *testing.T) {
	t.Run("recovers", func(t *testing.T) {
		e := newEnv(t, nil)
		e.arks.handler = func(w http.ResponseWriter, r *http.Request, n int) {
			if n == 1 {
				w.WriteHeader(http.StatusUnauthorized)
				return
			}
			writeAnswer(w, subjectOf(r), false)
		}
		require.NoError(t, e.client.Check(t.Context(), testSub))
		assert.Equal(t, 2, e.identity.minted())
		assert.Equal(t, "Bearer "+fakeTokenPrefix+"2", e.arks.headers[1].Get("Authorization"))
	})
	t.Run("always 401", func(t *testing.T) {
		e := newEnv(t, nil)
		e.arks.handler = func(w http.ResponseWriter, _ *http.Request, _ int) { w.WriteHeader(http.StatusUnauthorized) }
		d := denial(t, e.client.Check(t.Context(), testSub))
		assert.Equal(t, ReasonUnauthorized, d.Reason)
		assert.Equal(t, 2, e.arks.count())
	})
}

func TestCheck_403(t *testing.T) {
	e := newEnv(t, nil)
	e.arks.handler = func(w http.ResponseWriter, _ *http.Request, _ int) { w.WriteHeader(http.StatusForbidden) }
	assert.Equal(t, ReasonForbidden, denial(t, e.client.Check(t.Context(), testSub)).Reason)
	assert.Equal(t, 1, e.arks.count())
}

func TestCheck_TokenRejected(t *testing.T) {
	e := newEnv(t, nil)
	e.identity.tokenCode = http.StatusUnauthorized
	d := denial(t, e.client.Check(t.Context(), testSub))
	assert.Equal(t, ReasonCredentialsRejected, d.Reason)
	require.ErrorIs(t, d, servicetoken.ErrCredentialsRejected)
	assert.Zero(t, e.arks.count())
}

func TestCheck_EmptySub(t *testing.T) {
	e := newEnv(t, nil)
	assert.Equal(t, ReasonMissingSubject, denial(t, e.client.Check(t.Context(), "")).Reason)
	assert.Zero(t, e.arks.count())
	assert.Zero(t, e.identity.minted())
}

func TestCheck_SubEncoding(t *testing.T) {
	for _, sub := range []string{"arkavo:abc", "a/b", "a%2Fb", "a b", "ü", "..", "a?b#c"} {
		t.Run(sub, func(t *testing.T) {
			e := newEnv(t, nil)
			require.NoError(t, e.client.Check(t.Context(), sub))
			require.Equal(t, 1, e.arks.count())
			assert.Equal(t, suspPrefix+url.PathEscape(sub), e.arks.paths[0])
		})
	}
}

func TestCheck_CachesOnlyNotSuspended(t *testing.T) {
	t.Run("not suspended is cached until the ttl", func(t *testing.T) {
		e := newEnv(t, nil)
		now := time.Unix(1_000_000, 0)
		e.client.now = func() time.Time { return now }
		require.NoError(t, e.client.Check(t.Context(), testSub))
		require.NoError(t, e.client.Check(t.Context(), testSub))
		assert.Equal(t, 1, e.arks.count())
		now = now.Add(defaultCacheTTL + time.Millisecond)
		require.NoError(t, e.client.Check(t.Context(), testSub))
		assert.Equal(t, 2, e.arks.count())
	})
	t.Run("cache is per exact sub", func(t *testing.T) {
		e := newEnv(t, nil)
		require.NoError(t, e.client.Check(t.Context(), testSub))
		require.NoError(t, e.client.Check(t.Context(), testSub+"x"))
		assert.Equal(t, 2, e.arks.count())
	})
	t.Run("suspended is never cached", func(t *testing.T) {
		e := newEnv(t, nil)
		e.arks.handler = func(w http.ResponseWriter, r *http.Request, _ int) { writeAnswer(w, subjectOf(r), true) }
		require.Error(t, e.client.Check(t.Context(), testSub))
		require.Error(t, e.client.Check(t.Context(), testSub))
		assert.Equal(t, 2, e.arks.count())
	})
	t.Run("503 is never cached", func(t *testing.T) {
		e := newEnv(t, nil)
		e.arks.handler = func(w http.ResponseWriter, _ *http.Request, _ int) { w.WriteHeader(http.StatusServiceUnavailable) }
		require.Error(t, e.client.Check(t.Context(), testSub))
		require.Error(t, e.client.Check(t.Context(), testSub))
		assert.Equal(t, 2, e.arks.count())
	})
	t.Run("a failure for another sub leaves an entry alone and adds none", func(t *testing.T) {
		e := newEnv(t, nil)
		require.NoError(t, e.client.Check(t.Context(), testSub))
		e.client.mu.Lock()
		before := e.client.cache[testSub]
		e.client.mu.Unlock()
		e.arks.handler = func(w http.ResponseWriter, _ *http.Request, _ int) { w.WriteHeader(http.StatusServiceUnavailable) }
		require.Error(t, e.client.Check(t.Context(), "other"))
		e.client.mu.Lock()
		defer e.client.mu.Unlock()
		assert.Equal(t, before, e.client.cache[testSub])
		assert.NotContains(t, e.client.cache, "other")
	})
}

func TestCheck_CacheTTLDefaultAndCap(t *testing.T) {
	e := newEnv(t, nil)
	assert.Equal(t, 5*time.Second, e.client.cacheTTL)
	assert.Equal(t, 3*time.Second, e.client.timeout)

	e = newEnv(t, func(c *Config) { c.CacheTTL = time.Second })
	assert.Equal(t, time.Second, e.client.cacheTTL)

	_, err := New(Config{
		URL: "https://a.example", IdentityURL: "https://i.example", ClientID: "x", ClientSecret: "y",
		CacheTTL: 6 * time.Second,
	})
	require.Error(t, err)
}

func TestCheck_ContextCancelled(t *testing.T) {
	e := newEnv(t, nil)
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	err := e.client.Check(ctx, testSub)
	require.Error(t, err)
	d := denial(t, err)
	assert.Equal(t, ReasonUnreachable, d.Reason)
	assert.Zero(t, e.arks.count())
}

func TestClient_RenderingHidesSecret(t *testing.T) {
	e := newEnv(t, nil)
	require.NoError(t, e.client.Check(t.Context(), testSub))
	var sb strings.Builder
	h := slog.NewTextHandler(&sb, nil)
	slog.New(h).Info("client", slog.Any("c", e.client))
	out := fmt.Sprintf("%v|%+v|%#v|%s|", e.client, e.client, e.client, e.client) + sb.String()
	assert.NotContains(t, out, fakeClientSecret)
	assert.NotContains(t, out, fakeTokenPrefix)
	assert.Contains(t, out, fakeClientID)
}

func TestDenialError_Strings(t *testing.T) {
	cause := errors.New("arks returned HTTP 503")
	d := &DenialError{Reason: ReasonUnreachable, Cause: cause}
	assert.Contains(t, d.Error(), ReasonUnreachable)
	assert.Contains(t, d.Error(), "HTTP 503")
	require.ErrorIs(t, d, cause)
}

func TestCheck_CancelledCtxDeniesOnCacheHit(t *testing.T) {
	e := newEnv(t, nil)
	require.NoError(t, e.client.Check(t.Context(), testSub))
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	d := denial(t, e.client.Check(ctx, testSub))
	assert.Equal(t, ReasonUnreachable, d.Reason)
	require.ErrorIs(t, d, context.Canceled)
}

func TestCheck_ExpiredEntryEvicted(t *testing.T) {
	e := newEnv(t, nil)
	now := time.Unix(1_000_000, 0)
	e.client.now = func() time.Time { return now }
	require.NoError(t, e.client.Check(t.Context(), testSub))
	now = now.Add(defaultCacheTTL + time.Millisecond)
	e.arks.handler = func(w http.ResponseWriter, _ *http.Request, _ int) { w.WriteHeader(http.StatusServiceUnavailable) }
	require.Error(t, e.client.Check(t.Context(), testSub))
	e.client.mu.Lock()
	defer e.client.mu.Unlock()
	assert.NotContains(t, e.client.cache, testSub)
}

func TestCheck_SweepsExpiredOnWrite(t *testing.T) {
	e := newEnv(t, nil)
	now := time.Unix(1_000_000, 0)
	e.client.now = func() time.Time { return now }
	e.client.mu.Lock()
	for i := range sweepThreshold {
		e.client.cache[fmt.Sprintf("old-%d", i)] = now.Add(-time.Second)
	}
	e.client.mu.Unlock()
	require.NoError(t, e.client.Check(t.Context(), testSub))
	e.client.mu.Lock()
	defer e.client.mu.Unlock()
	assert.Len(t, e.client.cache, 1)
}

func TestCheck_TokenErrorHidesURLAndSubject(t *testing.T) {
	assertClean := func(t *testing.T, err error) {
		t.Helper()
		d := denial(t, err)
		require.Error(t, d.Cause)
		assert.NotContains(t, d.Cause.Error(), "://")
		assert.NotContains(t, d.Cause.Error(), testSub)
	}
	t.Run("cancelled", func(t *testing.T) {
		e := newEnv(t, nil)
		ctx, cancel := context.WithCancel(t.Context())
		cancel()
		assertClean(t, e.client.Check(ctx, testSub))
	})
	t.Run("identity unreachable", func(t *testing.T) {
		dead := httptest.NewServer(http.NotFoundHandler())
		dead.Close()
		e := newEnv(t, func(c *Config) { c.IdentityURL = dead.URL })
		err := e.client.Check(t.Context(), testSub)
		assertClean(t, err)
		assert.Equal(t, ReasonUnreachable, denial(t, err).Reason)
	})
}

func TestCheck_IdentityRedirectRefused(t *testing.T) {
	var mu sync.Mutex
	hits := 0
	other := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		mu.Lock()
		hits++
		mu.Unlock()
		_, _ = w.Write([]byte(`{"access_token":"x","expires_in":3600}`))
	}))
	defer other.Close()
	redirector := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, other.URL+"/oauth/token", http.StatusTemporaryRedirect)
	}))
	defer redirector.Close()
	e := newEnv(t, func(c *Config) { c.IdentityURL = redirector.URL })
	require.Error(t, e.client.Check(t.Context(), testSub))
	assert.Zero(t, e.arks.count())
	mu.Lock()
	defer mu.Unlock()
	assert.Zero(t, hits)
}
