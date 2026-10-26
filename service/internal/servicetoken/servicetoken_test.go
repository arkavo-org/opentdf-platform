package servicetoken

import (
	"bytes"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strconv"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const (
	testClientID     = "opentdf"
	testClientSecret = "s3cret-client-value"
	testTokenPrefix  = "cwt-secret-"
)

type testClock struct {
	mu  sync.Mutex
	now time.Time
}

func (c *testClock) get() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.now
}

func (c *testClock) advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.now = c.now.Add(d)
}

// newTestMinter serves handler as the token endpoint.
func newTestMinter(t *testing.T, handler http.Handler) (*Minter, *testClock) {
	t.Helper()
	srv := httptest.NewServer(handler)
	t.Cleanup(srv.Close)
	m := New(Config{TokenURL: srv.URL + "/oauth/token", ClientID: testClientID, ClientSecret: testClientSecret}, srv.Client())
	clk := &testClock{now: time.Unix(1_790_000_000, 0)}
	m.now = clk.get
	return m, clk
}

// countingEndpoint answers every request with a fresh token and expires_in.
func countingEndpoint(expiresIn any, calls *atomic.Int32) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		n := calls.Add(1)
		_ = json.NewEncoder(w).Encode(map[string]any{
			"access_token": fmt.Sprintf("%s%d", testTokenPrefix, n),
			"expires_in":   expiresIn,
		})
	})
}

func TestToken_CachedUntilRefreshSlack(t *testing.T) {
	var calls atomic.Int32
	m, clk := newTestMinter(t, countingEndpoint(600, &calls))
	first, err := m.Token(t.Context(), false)
	require.NoError(t, err)
	second, err := m.Token(t.Context(), false)
	require.NoError(t, err)
	assert.Equal(t, first, second)
	assert.Equal(t, int32(1), calls.Load())

	clk.advance(540 * time.Second)
	third, err := m.Token(t.Context(), false)
	require.NoError(t, err)
	assert.NotEqual(t, first, third)
	assert.Equal(t, int32(2), calls.Load())
}

func TestToken_FreshForcesMint(t *testing.T) {
	var calls atomic.Int32
	m, _ := newTestMinter(t, countingEndpoint(600, &calls))
	_, err := m.Token(t.Context(), false)
	require.NoError(t, err)
	_, err = m.Token(t.Context(), true)
	require.NoError(t, err)
	assert.Equal(t, int32(2), calls.Load())
}

func TestToken_CredentialsRejected(t *testing.T) {
	for _, code := range []int{http.StatusUnauthorized, http.StatusForbidden} {
		t.Run(strconv.Itoa(code), func(t *testing.T) {
			m, _ := newTestMinter(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.WriteHeader(code)
			}))
			_, err := m.Token(t.Context(), false)
			require.ErrorIs(t, err, ErrCredentialsRejected)
		})
	}
}

func TestToken_OtherFailureIsNotRejection(t *testing.T) {
	m, _ := newTestMinter(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	_, err := m.Token(t.Context(), false)
	require.Error(t, err)
	assert.NotErrorIs(t, err, ErrCredentialsRejected)
}

func TestToken_LifetimeCappedAtHour(t *testing.T) {
	var calls atomic.Int32
	m, clk := newTestMinter(t, countingEndpoint(999999, &calls))
	_, err := m.Token(t.Context(), false)
	require.NoError(t, err)
	clk.advance(58 * time.Minute)
	_, err = m.Token(t.Context(), false)
	require.NoError(t, err)
	assert.Equal(t, int32(1), calls.Load())
	clk.advance(time.Minute)
	_, err = m.Token(t.Context(), false)
	require.NoError(t, err)
	assert.Equal(t, int32(2), calls.Load(), "re-minted after 59 minutes")
}

func TestToken_NegativeExpiresIn(t *testing.T) {
	var calls atomic.Int32
	m, clk := newTestMinter(t, countingEndpoint(-5, &calls))
	_, err := m.Token(t.Context(), false)
	require.NoError(t, err)
	clk.advance(58 * time.Minute)
	_, err = m.Token(t.Context(), false)
	require.NoError(t, err)
	assert.Equal(t, int32(1), calls.Load(), "treated as one hour")
	clk.advance(time.Minute)
	_, err = m.Token(t.Context(), false)
	require.NoError(t, err)
	assert.Equal(t, int32(2), calls.Load())
}

func TestToken_EmptyAccessToken(t *testing.T) {
	m, _ := newTestMinter(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{"access_token": "", "expires_in": 600})
	}))
	_, err := m.Token(t.Context(), false)
	require.Error(t, err)
}

func TestToken_FormAndBasicAuth(t *testing.T) {
	var checked atomic.Bool
	m, _ := newTestMinter(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		id, secret, ok := r.BasicAuth()
		assert.True(t, ok)
		assert.Equal(t, testClientID, id)
		assert.Equal(t, testClientSecret, secret)
		assert.Equal(t, http.MethodPost, r.Method)
		assert.Equal(t, "/oauth/token", r.URL.Path)
		assert.NoError(t, r.ParseForm())
		assert.Equal(t, "client_credentials", r.PostForm.Get("grant_type"))
		assert.Len(t, r.PostForm, 1, "no audience, scope or other parameters")
		assert.Empty(t, r.URL.RawQuery)
		checked.Store(true)
		_ = json.NewEncoder(w).Encode(map[string]any{"access_token": testTokenPrefix + "1", "expires_in": 600})
	}))
	_, err := m.Token(t.Context(), false)
	require.NoError(t, err)
	assert.True(t, checked.Load())
}

func TestMinter_RenderingHidesSecret(t *testing.T) {
	var calls atomic.Int32
	m, _ := newTestMinter(t, countingEndpoint(600, &calls))
	_, err := m.Token(t.Context(), false)
	require.NoError(t, err)
	require.Equal(t, testTokenPrefix+"1", string(m.token), "the minter holds a token to leak")

	var rendered []string
	for _, verb := range []string{"%v", "%+v", "%#v", "%s", "%d", "%q", "%x"} {
		rendered = append(rendered, fmt.Sprintf(verb, m))
	}
	var buf bytes.Buffer
	for _, h := range []slog.Handler{slog.NewTextHandler(&buf, nil), slog.NewJSONHandler(&buf, nil)} {
		slog.New(h).Info(
			"minter",
			slog.Any("minter", m),
			slog.Any("secret", m.cfg.ClientSecret),
		)
	}
	rendered = append(rendered, buf.String())
	for _, r := range rendered {
		assert.NotContains(t, r, testClientSecret)
		assert.NotContains(t, r, testTokenPrefix)
	}
	assert.Contains(t, fmt.Sprintf("%v", m), testClientID)
}
