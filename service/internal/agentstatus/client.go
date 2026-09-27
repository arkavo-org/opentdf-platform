package agentstatus

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
	tokenPath        = "/oauth/token" //nolint:gosec // G101 false positive: an endpoint path, not a credential
	statusPathPrefix = "/agents/workloads/"
	statusPathSuffix = "/status"
	// serviceTokenHeader is where authnz-rs's require_service_cwt reads the
	// caller's service CWT.
	serviceTokenHeader = "X-Auth-Token" //nolint:gosec // G101 false positive: a header name, not a credential
	maxStatusTTL       = 5 * time.Second
	tokenRefreshSlack  = time.Minute
	// maxTokenLifetime caps a service CWT's reuse whatever expires_in says;
	// authnz-rs issues them for an hour.
	maxTokenLifetime = time.Hour
	maxBodyBytes     = 64 << 10
	// checkTimeouts is how many per-call timeouts one Check may take: a
	// token call and a status call.
	checkTimeouts = 2
)

var (
	errMalformedWorkload = errors.New("workload id is not contract v1 shaped")
	// errCredentialsRejected is the token endpoint answering 401 or 403:
	// identity refuses this platform's client_id/client_secret.
	errCredentialsRejected = errors.New("service token: identity rejected the client credentials")
)

// Client checks agent workloads against authnz-rs. A status that allows the
// agent is cached for min(valid_until-now, 5 s); a denying one never is. The
// highest generation seen per workload is kept for the process lifetime, so
// a rolled-back or replayed status is refused.
type Client struct {
	cfg     Config
	http    *http.Client
	now     func() time.Time
	timeout time.Duration

	mu        sync.Mutex
	token     Secret
	tokenExp  time.Time
	cache     map[string]cachedStatus
	highWater map[string]uint64
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
	return &Client{
		cfg: cfg,
		// Redirects are not followed: Go forwards custom headers such as
		// X-Auth-Token to the redirect target, even on another host.
		http: &http.Client{
			Timeout:       timeout,
			CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
		},
		now:       time.Now,
		timeout:   timeout,
		cache:     make(map[string]cachedStatus),
		highWater: make(map[string]uint64),
	}, nil
}

// Format renders only the endpoint and client id. fmt does not call Secret's
// methods on unexported fields, so the default rendering of a Client would
// print the client secret and the service CWT.
func (c *Client) Format(f fmt.State, _ rune) {
	_, _ = fmt.Fprintf(f, "agentstatus.Client{url: %s, client_id: %s}", c.cfg.URL, c.cfg.ClientID)
}

// LogValue keeps slog from reflecting over the secret-bearing fields.
func (c *Client) LogValue() slog.Value {
	return slog.GroupValue(slog.String("url", c.cfg.URL), slog.String("client_id", c.cfg.ClientID))
}

// Check implements Checker. It bounds itself at twice the per-call timeout
// (derived from ctx, so a caller that gives up sooner wins): a token call
// and a status call fit, and a retry after a 401 is cut short rather than
// holding the rewrap for four timeouts. Denials are returned through
// explicit nil checks: returning a nil *DenialError as error would be a
// non-nil interface and read as a denial of every eligible agent.
func (c *Client) Check(ctx context.Context, s Subject) error {
	if d := checkSubject(s); d != nil {
		return d
	}
	ctx, cancel := context.WithTimeout(ctx, checkTimeouts*c.timeout)
	defer cancel()
	if d := c.decide(ctx, s); d != nil {
		return d
	}
	return nil
}

type cachedStatus struct {
	status  Status
	expires time.Time
}

type tokenResponse struct {
	AccessToken string `json:"access_token"`
	ExpiresIn   int64  `json:"expires_in"`
}

// httpStatusError is a non-200 answer from the status endpoint.
type httpStatusError struct{ code int }

func (e *httpStatusError) Error() string { return fmt.Sprintf("identity returned HTTP %d", e.code) }

// fetchFailureReason: every failure denies. A 404 (unknown workload), a 403
// (this platform's client is not in AGENT_STATUS_CLIENT_IDS) and a 401 or
// 403 from the token endpoint (wrong client_id/client_secret) get their own
// reasons; the last two are misconfiguration. Everything else, including a
// timeout, another token-endpoint failure or a 401 that survived the retry,
// is "unreachable".
func fetchFailureReason(err error) string {
	if errors.Is(err, errCredentialsRejected) {
		return ReasonStatusCredentialsRejected
	}
	var hse *httpStatusError
	if errors.As(err, &hse) {
		switch hse.code {
		case http.StatusNotFound:
			return ReasonUnknownWorkload
		case http.StatusForbidden:
			return ReasonStatusForbidden
		}
	}
	return ReasonUnreachable
}

// decide judges s against a cached status when one is still leased, else
// against a live one. A cache hit is still evaluated with the current
// high-water mark and this subject's claims.
func (c *Client) decide(ctx context.Context, s Subject) *DenialError {
	if st, hw, ok := c.cached(s.Workload); ok {
		return evaluate(st, s, hw)
	}
	st, err := c.fetch(ctx, s.Workload)
	if err != nil {
		return &DenialError{Reason: fetchFailureReason(err), Workload: s.Workload, Cause: err}
	}
	return c.record(st, s)
}

func (c *Client) cached(workload string) (Status, uint64, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	e, ok := c.cache[workload]
	if !ok {
		return Status{}, 0, false
	}
	if !c.now().Before(e.expires) {
		delete(c.cache, workload)
		return Status{}, 0, false
	}
	return e.status, c.highWater[workload], true
}

// record judges a live status, raises the workload's high-water mark and
// caches the status only if it allowed the agent.
func (c *Client) record(st Status, s Subject) *DenialError {
	c.mu.Lock()
	defer c.mu.Unlock()
	hw := c.highWater[s.Workload]
	d := evaluate(st, s, hw)
	// A denying status raises the mark too: after a quarantine at generation
	// n, a replay of the eligible status below n must fail. A status naming
	// another workload says nothing about this one's generation.
	if st.Workload == s.Workload && st.Generation > hw {
		c.highWater[s.Workload] = st.Generation
		// A cached status below the new mark can only deny now, and would
		// log a regression instead of what identity says (a quarantine and
		// its incident); drop it so the next request asks.
		if e, ok := c.cache[s.Workload]; ok && e.status.Generation < st.Generation {
			delete(c.cache, s.Workload)
		}
	}
	if d != nil {
		return d
	}
	// A live answer decides this request even if valid_until has already
	// passed on this host's clock (skew with identity) or is missing. It is
	// cached only while valid_until is still ahead, and never for more than
	// 5 s.
	now := c.now()
	if ttl := min(time.Unix(st.ValidUntil, 0).Sub(now), maxStatusTTL); ttl > 0 {
		c.cache[s.Workload] = cachedStatus{status: st, expires: now.Add(ttl)}
	}
	return nil
}

func (c *Client) fetch(ctx context.Context, workload string) (Status, error) {
	st, err := c.fetchOnce(ctx, workload, false)
	var hse *httpStatusError
	if errors.As(err, &hse) && hse.code == http.StatusUnauthorized {
		// The cached service CWT was refused (expired early, or identity
		// rotated keys): mint a fresh one and try once more.
		return c.fetchOnce(ctx, workload, true)
	}
	return st, err
}

func (c *Client) fetchOnce(ctx context.Context, workload string, freshToken bool) (Status, error) {
	// Check has already run checkSubject; this keeps an unchecked id out of
	// the URL whoever calls.
	if !validWorkloadID(workload) {
		return Status{}, errMalformedWorkload
	}
	token, err := c.serviceToken(ctx, freshToken)
	if err != nil {
		return Status{}, err
	}
	endpoint := c.endpoint(statusPathPrefix + url.PathEscape(workload) + statusPathSuffix)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return Status{}, err
	}
	req.Header.Set(serviceTokenHeader, string(token))
	var st Status
	if err := c.doJSON(req, &st); err != nil {
		return Status{}, fmt.Errorf("workload status: %w", err)
	}
	return st, nil
}

func (c *Client) serviceToken(ctx context.Context, fresh bool) (Secret, error) {
	c.mu.Lock()
	if !fresh && c.token != "" && c.now().Before(c.tokenExp) {
		token := c.token
		c.mu.Unlock()
		return token, nil
	}
	issued := c.now()
	c.mu.Unlock()

	form := url.Values{"grant_type": {"client_credentials"}}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.endpoint(tokenPath), strings.NewReader(form.Encode()))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.SetBasicAuth(c.cfg.ClientID, string(c.cfg.ClientSecret))
	var body tokenResponse
	if err := c.doJSON(req, &body); err != nil {
		var hse *httpStatusError
		if errors.As(err, &hse) {
			// Dropped as a type: the token endpoint's 404 or 403 says nothing
			// about the workload, and its 401 must not look like a stale CWT
			// (fetch would retry it).
			if hse.code == http.StatusUnauthorized || hse.code == http.StatusForbidden {
				return "", fmt.Errorf("%w (HTTP %d)", errCredentialsRejected, hse.code)
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
	lifetime := maxTokenLifetime
	if body.ExpiresIn > 0 && body.ExpiresIn < int64(maxTokenLifetime/time.Second) {
		lifetime = time.Duration(body.ExpiresIn) * time.Second
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	c.token = Secret(body.AccessToken)
	c.tokenExp = issued.Add(lifetime - tokenRefreshSlack)
	return c.token, nil
}

func (c *Client) doJSON(req *http.Request, into any) error {
	req.Header.Set("Accept", "application/json")
	resp, err := c.http.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return &httpStatusError{code: resp.StatusCode}
	}
	return json.NewDecoder(io.LimitReader(resp.Body, maxBodyBytes)).Decode(into)
}

func (c *Client) endpoint(path string) string {
	return strings.TrimRight(c.cfg.URL, "/") + path
}
