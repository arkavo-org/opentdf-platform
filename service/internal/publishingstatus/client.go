package publishingstatus

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

	"github.com/opentdf/platform/service/internal/servicetoken"
)

const (
	tokenPath        = "/oauth/token" //nolint:gosec // G101 false positive: an endpoint path, not a credential
	suspensionsPath  = "/moderation/v1/suspensions/"
	defaultTimeout   = 3 * time.Second
	defaultCacheTTL  = 5 * time.Second
	maxBodyBytes     = 64 << 10
	checkTimeouts    = 2 // a token call and a suspension call
	bearerAuthPrefix = "Bearer "
)

// Reasons a subject's grants are withheld. Misconfiguration reasons name the
// setting to fix, since they would otherwise look like an outage.
const (
	ReasonSuspended           = "suspended by moderation"
	ReasonMissingSubject      = "subject has no sub"
	ReasonUnreachable         = "suspension service unreachable"
	ReasonMalformedAnswer     = "suspension service answer is not a clear not-suspended"
	ReasonForbidden           = "misconfiguration: this platform's client is not in arks MODERATION_SUSPENSION_READER_IDS (403)"
	ReasonUnauthorized        = "misconfiguration: arks rejected the service CWT after a fresh mint (401)"
	ReasonCredentialsRejected = "misconfiguration: identity rejected publishing_status.client_id/client_secret at /oauth/token"
)

// Checker decides whether a subject may keep its publishing grants: nil when
// arks says it is not suspended, a *DenialError otherwise.
type Checker interface {
	Check(ctx context.Context, sub string) error
}

// DenialError explains a withheld subject for logs and audit.
type DenialError struct {
	Reason   string
	Subject  string
	Since    string
	ReportID string
	Cause    error
}

func (d *DenialError) Error() string {
	if d.Cause != nil {
		return "publishing denied: " + d.Reason + ": " + d.Cause.Error()
	}
	return "publishing denied: " + d.Reason
}

func (d *DenialError) Unwrap() error { return d.Cause }

// answer is arks's body. suspended is a pointer so a missing or null field
// is distinguishable from false.
type answer struct {
	Subject   string `json:"subject"`
	Suspended *bool  `json:"suspended"`
	Since     string `json:"since"`
	ReportID  string `json:"reportId"`
}

// Client asks arks whether a subject is suspended from publishing. Only a
// clear not-suspended answer is cached, and only for CacheTTL.
type Client struct {
	cfg      Config
	http     *http.Client
	now      func() time.Time
	timeout  time.Duration
	cacheTTL time.Duration

	minter *servicetoken.Minter

	mu    sync.Mutex
	cache map[string]time.Time // sub -> expiry of a not-suspended answer
}

// New validates cfg; an unconfigured (empty) Config fails validation too, so
// callers check Enabled first. The service CWT is minted on first use.
func New(cfg Config) (*Client, error) {
	if err := cfg.validate(); err != nil {
		return nil, err
	}
	timeout := cfg.Timeout
	if timeout <= 0 {
		timeout = defaultTimeout
	}
	cacheTTL := cfg.CacheTTL
	if cacheTTL <= 0 {
		cacheTTL = defaultCacheTTL
	}
	// Redirects are not followed: Go forwards custom headers, and a 3xx must
	// not turn into an answer from somewhere else.
	refuse := func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	c := &Client{
		cfg:      cfg,
		http:     &http.Client{Transport: cfg.transport(), Timeout: timeout, CheckRedirect: refuse},
		now:      time.Now,
		timeout:  timeout,
		cacheTTL: cacheTTL,
		cache:    make(map[string]time.Time),
	}
	// Identity is another host: it must not be dialed through the arks
	// override in cfg.transport().
	identity := &http.Client{Timeout: timeout, CheckRedirect: refuse}
	c.minter = servicetoken.New(servicetoken.Config{
		TokenURL:     strings.TrimRight(cfg.IdentityURL, "/") + tokenPath,
		ClientID:     cfg.ClientID,
		ClientSecret: cfg.ClientSecret,
	}, identity)
	return c, nil
}

// Format renders only the endpoint and client id. fmt does not call Secret's
// methods on unexported fields, so the default rendering of a Client would
// print the client secret and the service CWT.
func (c *Client) Format(f fmt.State, _ rune) {
	_, _ = fmt.Fprintf(f, "publishingstatus.Client{url: %s, client_id: %s}", c.cfg.URL, c.cfg.ClientID)
}

// LogValue keeps slog from reflecting over the secret-bearing fields.
func (c *Client) LogValue() slog.Value {
	return slog.GroupValue(slog.String("url", c.cfg.URL), slog.String("client_id", c.cfg.ClientID))
}

// Check implements Checker. It bounds itself at twice the per-call timeout
// (derived from ctx, so a caller that gives up sooner wins). Denials are
// returned through explicit nil checks: returning a nil *DenialError as
// error would be a non-nil interface and read as a suspension of everyone.
func (c *Client) Check(ctx context.Context, sub string) error {
	if sub == "" {
		return &DenialError{Reason: ReasonMissingSubject}
	}
	if c.cached(sub) {
		return nil
	}
	ctx, cancel := context.WithTimeout(ctx, checkTimeouts*c.timeout)
	defer cancel()
	if d := c.decide(ctx, sub); d != nil {
		return d
	}
	return nil
}

func (c *Client) cached(sub string) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	exp, ok := c.cache[sub]
	return ok && c.now().Before(exp)
}

// httpStatusError is a non-200 answer from arks.
type httpStatusError struct{ code int }

func (e *httpStatusError) Error() string { return fmt.Sprintf("arks returned HTTP %d", e.code) }

// malformedError marks a 200 whose body is not a clear answer about sub.
type malformedError struct{ why string }

func (e *malformedError) Error() string { return "malformed answer: " + e.why }

// failureReason: every failure withholds. A 403 and rejected client
// credentials are misconfiguration and get their own reasons; a malformed
// 200 is told apart from an outage; everything else, including a 404, a
// redirect or a timeout, is "unreachable". A 401 reaching here survived the
// fresh-token retry.
func failureReason(err error) string {
	if errors.Is(err, servicetoken.ErrCredentialsRejected) {
		return ReasonCredentialsRejected
	}
	var m *malformedError
	if errors.As(err, &m) {
		return ReasonMalformedAnswer
	}
	var hse *httpStatusError
	if errors.As(err, &hse) {
		switch hse.code {
		case http.StatusForbidden:
			return ReasonForbidden
		case http.StatusUnauthorized:
			return ReasonUnauthorized
		}
	}
	return ReasonUnreachable
}

func (c *Client) decide(ctx context.Context, sub string) *DenialError {
	a, err := c.fetch(ctx, sub)
	if err != nil {
		return &DenialError{Reason: failureReason(err), Subject: sub, Cause: err}
	}
	if *a.Suspended {
		return &DenialError{Reason: ReasonSuspended, Subject: sub, Since: a.Since, ReportID: a.ReportID}
	}
	// Only this branch writes the cache. A suspended or failed answer
	// neither creates an entry nor removes an existing one early.
	c.mu.Lock()
	c.cache[sub] = c.now().Add(c.cacheTTL)
	c.mu.Unlock()
	return nil
}

func (c *Client) fetch(ctx context.Context, sub string) (answer, error) {
	a, err := c.fetchOnce(ctx, sub, false)
	var hse *httpStatusError
	if errors.As(err, &hse) && hse.code == http.StatusUnauthorized {
		// The cached service CWT was refused (expired early, or identity
		// rotated keys): mint a fresh one and try once more.
		return c.fetchOnce(ctx, sub, true)
	}
	return a, err
}

func (c *Client) fetchOnce(ctx context.Context, sub string, freshToken bool) (answer, error) {
	token, err := c.minter.Token(ctx, freshToken)
	if err != nil {
		return answer{}, err
	}
	endpoint := strings.TrimRight(c.cfg.URL, "/") + suspensionsPath + url.PathEscape(sub)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return answer{}, err
	}
	req.Header.Set("Authorization", bearerAuthPrefix+string(token))
	req.Header.Set("Accept", "application/json")
	resp, err := c.http.Do(req)
	if err != nil {
		// A *url.Error carries the URL; the subject is in it.
		var ue *url.Error
		if errors.As(err, &ue) {
			err = ue.Err
		}
		return answer{}, fmt.Errorf("suspension read: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return answer{}, &httpStatusError{code: resp.StatusCode}
	}
	var a answer
	if err := json.NewDecoder(io.LimitReader(resp.Body, maxBodyBytes)).Decode(&a); err != nil {
		return answer{}, &malformedError{why: "body does not decode"}
	}
	if a.Suspended == nil {
		return answer{}, &malformedError{why: "no boolean suspended"}
	}
	// A body about another subject proves nothing about this one.
	if a.Subject != sub {
		return answer{}, &malformedError{why: "subject differs from the one asked about"}
	}
	return a, nil
}
