// Package servicetoken mints the service CWT this platform presents to
// authnz-rs (client_credentials against its token endpoint) and caches it
// until shortly before it expires. The callers (agentstatus,
// publishingstatus) own the header the token travels in and what to do when
// a peer refuses it.
package servicetoken

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

const (
	redacted     = "[REDACTED]"
	maxBodyBytes = 64 << 10
	// refreshSlack is how long before expiry a cached token stops being reused.
	refreshSlack = time.Minute
	// maxLifetime caps a service CWT's reuse whatever expires_in says;
	// authnz-rs issues them for an hour.
	maxLifetime = time.Hour
)

// ErrCredentialsRejected is the token endpoint answering 401 or 403:
// identity refuses this platform's client_id/client_secret.
var ErrCredentialsRejected = errors.New("service token: identity rejected the client credentials")

// Secret keeps the client secret and the service CWT out of every rendering:
// server.Config.LogValue logs the whole auth block.
type Secret string

func (Secret) String() string       { return redacted }
func (Secret) LogValue() slog.Value { return slog.StringValue(redacted) }

// Format covers the verbs String does not, such as %#v and %d, also for a
// Config embedded in a larger struct. It cannot cover %p: fmt handles that
// verb before consulting any Formatter, and on a non-pointer (a Secret, or a
// Config holding one) prints a bad-verb marker followed by the raw value.
// go vet flags %p on a non-pointer; never silence it for these types.
func (Secret) Format(f fmt.State, _ rune) { _, _ = io.WriteString(f, redacted) }

// MarshalJSON renders an unset secret as "": a config seeded from the JSON
// of a zero config must not carry "[REDACTED]" as a default, which would
// stand in for a missing client_secret and get past validate().
func (s Secret) MarshalJSON() ([]byte, error) {
	if s == "" {
		return []byte(`""`), nil
	}
	return []byte(`"` + redacted + `"`), nil
}

// Config names the token endpoint and the client credentials.
type Config struct {
	// TokenURL is the full token endpoint, e.g. https://identity.arkavo.net/oauth/token.
	TokenURL     string
	ClientID     string
	ClientSecret Secret
}

// Minter mints and caches a service CWT. It is safe for concurrent use.
type Minter struct {
	cfg  Config
	http *http.Client
	now  func() time.Time

	mu       sync.Mutex
	token    Secret
	tokenExp time.Time
}

// New returns a Minter that calls the token endpoint with hc. hc must not
// follow redirects: the token request carries the client secret.
func New(cfg Config, hc *http.Client) *Minter {
	return &Minter{cfg: cfg, http: hc, now: time.Now}
}

// WithClock replaces the time source and returns m; for tests that move time.
func (m *Minter) WithClock(now func() time.Time) *Minter {
	m.now = now
	return m
}

// Format renders only the token endpoint and client id. fmt does not call
// Secret's methods on unexported fields, so the default rendering of a
// Minter would print the client secret and the service CWT.
func (m *Minter) Format(f fmt.State, _ rune) {
	_, _ = fmt.Fprintf(f, "servicetoken.Minter{token_url: %s, client_id: %s}", m.cfg.TokenURL, m.cfg.ClientID)
}

// LogValue keeps slog from reflecting over the secret-bearing fields.
func (m *Minter) LogValue() slog.Value {
	return slog.GroupValue(slog.String("token_url", m.cfg.TokenURL), slog.String("client_id", m.cfg.ClientID))
}

type tokenResponse struct {
	AccessToken string `json:"access_token"`
	ExpiresIn   int64  `json:"expires_in"`
}

// httpStatusError is a non-200 answer from the token endpoint.
type httpStatusError struct{ code int }

func (e *httpStatusError) Error() string { return fmt.Sprintf("identity returned HTTP %d", e.code) }

// Token returns the cached service CWT, or mints one when none is cached,
// the cached one is within a minute of expiring, or fresh is set (the caller
// saw the peer refuse the cached one).
func (m *Minter) Token(ctx context.Context, fresh bool) (Secret, error) {
	m.mu.Lock()
	if !fresh && m.token != "" && m.now().Before(m.tokenExp) {
		token := m.token
		m.mu.Unlock()
		return token, nil
	}
	issued := m.now()
	m.mu.Unlock()

	form := url.Values{"grant_type": {"client_credentials"}}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, m.cfg.TokenURL, strings.NewReader(form.Encode()))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.SetBasicAuth(m.cfg.ClientID, string(m.cfg.ClientSecret))
	var body tokenResponse
	if err := m.doJSON(req, &body); err != nil {
		var hse *httpStatusError
		if errors.As(err, &hse) {
			// Dropped as a type: the token endpoint's 404 or 403 says nothing
			// about the agent, and its 401 must not look like a stale CWT
			// (a caller would retry it).
			if hse.code == http.StatusUnauthorized || hse.code == http.StatusForbidden {
				return "", fmt.Errorf("%w (HTTP %d)", ErrCredentialsRejected, hse.code)
			}
			return "", fmt.Errorf("service token: identity returned HTTP %d", hse.code)
		}
		return "", fmt.Errorf("service token: %w", err)
	}
	if body.AccessToken == "" {
		return "", errors.New("service token: empty access_token")
	}
	// Only a positive expires_in below the cap is used: a negative one would
	// overflow to a lifetime of centuries once multiplied out.
	lifetime := maxLifetime
	if body.ExpiresIn > 0 && body.ExpiresIn < int64(maxLifetime/time.Second) {
		lifetime = time.Duration(body.ExpiresIn) * time.Second
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	m.token = Secret(body.AccessToken)
	m.tokenExp = issued.Add(lifetime - refreshSlack)
	return m.token, nil
}

func (m *Minter) doJSON(req *http.Request, into any) error {
	req.Header.Set("Accept", "application/json")
	resp, err := m.http.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return &httpStatusError{code: resp.StatusCode}
	}
	return json.NewDecoder(io.LimitReader(resp.Body, maxBodyBytes)).Decode(into)
}
