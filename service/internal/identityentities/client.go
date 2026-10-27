package identityentities

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

	"github.com/google/uuid"
	"github.com/opentdf/platform/service/internal/servicetoken"
	"golang.org/x/sync/singleflight"
)

const (
	tokenPath    = "/oauth/token" //nolint:gosec // G101 false positive: an endpoint path, not a credential
	entitiesPath = "/entities/arkavo:"
	// authHeader is where identity reads a service CWT on /entities.
	authHeader = "X-Auth-Token"
	// entityNotFound is identity's whole body for an unknown account.
	entityNotFound = "Entity not found"
	// maxBodyBytes bounds an answer: a creator with many tiers is a few KiB.
	maxBodyBytes   = 256 << 10
	sweepThreshold = 4096
	// lookupCalls is how many calls one lookup may make: a token mint and
	// the read.
	lookupCalls = 2
)

// Reasons a lookup failed. Misconfiguration reasons name the setting to fix,
// since they would otherwise look like an outage.
const (
	ReasonUnavailable         = "identity unavailable"
	ReasonPatreonUnavailable  = "identity has a Patreon link but no snapshot (503 patreon_unavailable)"
	ReasonMalformed           = "identity answer is malformed"
	ReasonForbidden           = "misconfiguration: this platform's client is not on identity's ENTITY_CLIENT_IDS (403)"
	ReasonUnauthorized        = "misconfiguration: identity rejected the service CWT after a fresh mint (401)"
	ReasonCredentialsRejected = "misconfiguration: identity rejected identity_entities.client_id/client_secret at /oauth/token"
	ReasonBackoff             = "identity failed recently; not asked again until failure_backoff passes"
)

// Error is a failed lookup. Misconfiguration reports whether the reason is
// a setting to fix rather than an outage.
type Error struct {
	Reason string
	Cause  error
}

func (e *Error) Error() string {
	if e.Cause != nil {
		return e.Reason + ": " + e.Cause.Error()
	}
	return e.Reason
}

func (e *Error) Unwrap() error { return e.Cause }

// Misconfiguration reports whether the failure is a setting to fix.
func (e *Error) Misconfiguration() bool { return strings.HasPrefix(e.Reason, "misconfiguration:") }

// Answer is what identity says about an account.
type Answer struct {
	// Claims are the claims a fresh token for the account would carry; nil
	// when identity does not know the account (404).
	Claims map[string]any
	// FetchedAt is when identity gave this answer.
	FetchedAt time.Time
	// Stale is set when identity is unavailable and an older answer, within
	// stale_max_age, is served instead.
	Stale bool
}

// Looker reads an account's claims from identity.
type Looker interface {
	Lookup(ctx context.Context, accountID string) (Answer, error)
}

type entry struct {
	answer      Answer
	good        bool      // answer holds a successful lookup
	failedUntil time.Time // a failure is remembered until then
}

// Client asks identity for an account's claims, with a per-account cache,
// stale-on-error and one lookup in flight per account. It is safe for
// concurrent use.
type Client struct {
	cfg    Config
	http   *http.Client
	minter *servicetoken.Minter
	now    func() time.Time
	group  singleflight.Group

	mu    sync.Mutex
	cache map[string]*entry
}

// New validates cfg; an empty Config fails validation too, so callers check
// Enabled first. The service CWT is minted on first use.
func New(cfg Config) (*Client, error) {
	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	cfg = cfg.withDefaults()
	// Redirects are not followed: Go forwards custom headers, so a 3xx would
	// carry the service CWT, and must not turn into an answer from elsewhere.
	refuse := func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	hc := &http.Client{Timeout: cfg.Timeout, CheckRedirect: refuse}
	base := strings.TrimRight(cfg.URL, "/")
	return &Client{
		cfg:  cfg,
		http: hc,
		minter: servicetoken.New(servicetoken.Config{
			TokenURL:     base + tokenPath,
			ClientID:     cfg.ClientID,
			ClientSecret: cfg.ClientSecret,
		}, hc),
		now:   time.Now,
		cache: make(map[string]*entry),
	}, nil
}

// WithClock replaces the time source and returns c; for tests that move time.
func (c *Client) WithClock(now func() time.Time) *Client {
	c.now = now
	c.minter.WithClock(now)
	return c
}

// Format renders only the endpoint and client id. fmt does not call Secret's
// methods on unexported fields, so the default rendering would print the
// client secret and the service CWT.
func (c *Client) Format(f fmt.State, _ rune) {
	_, _ = fmt.Fprintf(f, "identityentities.Client{url: %s, client_id: %s}", c.cfg.URL, c.cfg.ClientID)
}

// LogValue keeps slog from reflecting over the secret-bearing fields.
func (c *Client) LogValue() slog.Value {
	return slog.GroupValue(slog.String("url", c.cfg.URL), slog.String("client_id", c.cfg.ClientID))
}

// Lookup returns identity's answer for accountID, a bare UUID. A cached
// answer younger than cache_ttl is reused. Otherwise identity is asked,
// unless it failed for this account within failure_backoff. When it is not
// asked, or the call fails, an answer younger than stale_max_age is served
// with Stale set; with none, the result is an *Error.
func (c *Client) Lookup(ctx context.Context, accountID string) (Answer, error) {
	id, err := uuid.Parse(accountID)
	if err != nil || id.String() != accountID {
		return Answer{}, &Error{Reason: ReasonMalformed, Cause: errors.New("account id is not a bare lowercase UUID")}
	}
	now := c.now()
	c.mu.Lock()
	e := c.cache[accountID]
	if e != nil && e.good && now.Before(e.answer.FetchedAt.Add(c.cfg.CacheTTL)) {
		a := e.answer
		c.mu.Unlock()
		return a, nil
	}
	backoff := e != nil && now.Before(e.failedUntil)
	c.mu.Unlock()
	if backoff {
		return c.staleOr(accountID, now, &Error{Reason: ReasonBackoff})
	}

	// One call per account at a time, detached from any one caller's ctx so
	// a caller giving up does not fail the others; each caller still waits
	// only as long as its own ctx allows.
	ch := c.group.DoChan(accountID, func() (any, error) {
		// Two calls' worth: the first lookup after a restart mints the
		// service CWT before it asks.
		callCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), lookupCalls*c.cfg.Timeout)
		defer cancel()
		return c.fetch(callCtx, accountID)
	})
	select {
	case <-ctx.Done():
		return c.staleOr(accountID, c.now(), &Error{Reason: ReasonUnavailable, Cause: ctx.Err()})
	case res := <-ch:
		if res.Err != nil {
			c.remember(accountID, nil)
			var lookupErr *Error
			if !errors.As(res.Err, &lookupErr) {
				lookupErr = &Error{Reason: ReasonUnavailable, Cause: res.Err}
			}
			return c.staleOr(accountID, c.now(), lookupErr)
		}
		claims, _ := res.Val.(map[string]any)
		a := Answer{Claims: claims, FetchedAt: c.now()}
		c.remember(accountID, &a)
		return a, nil
	}
}

// remember records a good answer, or a failure when a is nil. A failure
// keeps the last good answer for stale serving.
func (c *Client) remember(accountID string, a *Answer) {
	c.mu.Lock()
	defer c.mu.Unlock()
	now := c.now()
	if len(c.cache) >= sweepThreshold {
		// Memory stays bounded by the accounts seen within stale_max_age.
		for k, e := range c.cache {
			if !now.Before(e.answer.FetchedAt.Add(c.cfg.StaleMaxAge)) && !now.Before(e.failedUntil) {
				delete(c.cache, k)
			}
		}
	}
	e := c.cache[accountID]
	if e == nil {
		e = &entry{}
		c.cache[accountID] = e
	}
	if a != nil {
		e.answer, e.good, e.failedUntil = *a, true, time.Time{}
		return
	}
	e.failedUntil = now.Add(c.cfg.FailureBackoff)
}

// staleOr serves the last good answer if it is younger than stale_max_age,
// and otherwise returns failure.
func (c *Client) staleOr(accountID string, now time.Time, failure *Error) (Answer, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if e := c.cache[accountID]; e != nil && e.good && now.Before(e.answer.FetchedAt.Add(c.cfg.StaleMaxAge)) {
		a := e.answer
		a.Stale = true
		return a, nil
	}
	return Answer{}, failure
}

// httpStatusError is a non-200, non-404 answer from identity.
type httpStatusError struct{ code int }

func (e *httpStatusError) Error() string { return fmt.Sprintf("identity returned HTTP %d", e.code) }

// entityBody is identity's answer; only the claims are read.
type entityBody struct {
	Claims map[string]any `json:"claims"`
}

// errorBody is identity's error answer.
type errorBody struct {
	Error string `json:"error"`
}

func (c *Client) fetch(ctx context.Context, accountID string) (map[string]any, error) {
	claims, err := c.fetchOnce(ctx, accountID, false)
	var hse *httpStatusError
	if errors.As(err, &hse) && hse.code == http.StatusUnauthorized {
		// The cached service CWT was refused (expired early, or identity
		// rotated keys): mint a fresh one and try once more.
		claims, err = c.fetchOnce(ctx, accountID, true)
	}
	if err != nil {
		return nil, classify(err)
	}
	return claims, nil
}

// classify turns a fetch error into an *Error with its reason.
func classify(err error) *Error {
	var e *Error
	if errors.As(err, &e) {
		return e
	}
	if errors.Is(err, servicetoken.ErrCredentialsRejected) {
		return &Error{Reason: ReasonCredentialsRejected, Cause: err}
	}
	var hse *httpStatusError
	if errors.As(err, &hse) {
		switch hse.code {
		case http.StatusForbidden:
			return &Error{Reason: ReasonForbidden, Cause: err}
		case http.StatusUnauthorized:
			return &Error{Reason: ReasonUnauthorized, Cause: err}
		}
	}
	return &Error{Reason: ReasonUnavailable, Cause: err}
}

func (c *Client) fetchOnce(ctx context.Context, accountID string, freshToken bool) (map[string]any, error) {
	token, err := c.minter.Token(ctx, freshToken)
	if err != nil {
		// servicetoken wraps a *url.Error, which carries the identity URL.
		var ue *url.Error
		if !errors.Is(err, servicetoken.ErrCredentialsRejected) && errors.As(err, &ue) {
			err = fmt.Errorf("service token: %w", ue.Err)
		}
		return nil, err
	}
	endpoint := strings.TrimRight(c.cfg.URL, "/") + entitiesPath + accountID
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set(authHeader, string(token))
	req.Header.Set("Accept", "application/json")
	resp, err := c.http.Do(req)
	if err != nil {
		var ue *url.Error
		if errors.As(err, &ue) {
			err = ue.Err
		}
		return nil, fmt.Errorf("entities read: %w", err)
	}
	defer resp.Body.Close()
	body := io.LimitReader(resp.Body, maxBodyBytes)
	switch resp.StatusCode {
	case http.StatusOK:
	case http.StatusNotFound:
		// Only identity's own answer means an unknown or deleted account. Any
		// other 404 (a wrong base URL, a proxy) is a failure, so it shows in
		// the logs instead of quietly caching "no such account".
		raw, _ := io.ReadAll(io.LimitReader(body, int64(len(entityNotFound))+1))
		if strings.TrimSpace(string(raw)) != entityNotFound {
			return nil, &httpStatusError{code: resp.StatusCode}
		}
		return nil, nil //nolint:nilnil // a definite "no such account", not a failure
	case http.StatusServiceUnavailable:
		var eb errorBody
		if json.NewDecoder(body).Decode(&eb) == nil && eb.Error == "patreon_unavailable" {
			return nil, &Error{Reason: ReasonPatreonUnavailable}
		}
		return nil, &httpStatusError{code: resp.StatusCode}
	default:
		return nil, &httpStatusError{code: resp.StatusCode}
	}
	var eb entityBody
	dec := json.NewDecoder(body)
	if err := dec.Decode(&eb); err != nil {
		return nil, &Error{Reason: ReasonMalformed, Cause: errors.New("body does not decode")}
	}
	if err := dec.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return nil, &Error{Reason: ReasonMalformed, Cause: errors.New("trailing data after the answer")}
	}
	// An answer about another account proves nothing about this one.
	if got, _ := eb.Claims["arkavo_account_id"].(string); got != accountID {
		return nil, &Error{Reason: ReasonMalformed, Cause: errors.New("arkavo_account_id differs from the account asked about")}
	}
	return eb.Claims, nil
}
