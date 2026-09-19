package jev

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"
)

// maxErrorBody caps how much of a non-200 response body is read back into an
// error message.
const maxErrorBody = 4096

// Errors returned by the client. Callers distinguish these to decide whether a
// failure is retryable and how fail_mode should apply.
var (
	// ErrDisabled is returned by the no-op client. It is not a failure: it
	// means no model was consulted, and callers should proceed on policy alone.
	ErrDisabled = errors.New("jev: client disabled")
	// ErrNoAPIKey means the configured environment variable held no key.
	ErrNoAPIKey = errors.New("jev: api key environment variable is empty")
	// ErrNoQuestions means the caller asked nothing.
	ErrNoQuestions = errors.New("jev: at least one question is required")
)

// Client poses typed questions about some state and returns typed answers.
type Client interface {
	// Decide submits state and questions to the model. Implementations must
	// respect the context deadline; on error the caller applies fail_mode.
	Decide(ctx context.Context, state any, questions map[string]Question) (*Response, error)
}

// request is the Decisions API request body.
type request struct {
	Model     string              `json:"model"`
	State     any                 `json:"state"`
	Questions map[string]Question `json:"questions"`
	SessionID string              `json:"session_id,omitempty"`
}

// HTTPClient calls OpenRouter's Decisions API.
type HTTPClient struct {
	httpDoer  *http.Client
	cache     *responseCache
	baseURL   string
	apiKey    string
	model     string
	threshold float64
}

// NoopClient stands in when Jev is disabled. Every call reports ErrDisabled so
// that a misconfigured seam degrades to policy-only rather than to silence.
type NoopClient struct{}

// Ensure both implementations satisfy the interface.
var (
	_ Client = (*HTTPClient)(nil)
	_ Client = (*NoopClient)(nil)
)

// New builds a Client from config. It returns a NoopClient when Jev is
// disabled, so callers never need to nil-check.
func New(cfg *Config, doer *http.Client) (Client, error) {
	if cfg == nil || !cfg.Enabled {
		return &NoopClient{}, nil
	}
	if err := cfg.Validate(); err != nil {
		return nil, err
	}

	apiKey := strings.TrimSpace(os.Getenv(cfg.APIKeyEnv))
	if apiKey == "" {
		return nil, fmt.Errorf("%w: %s", ErrNoAPIKey, cfg.APIKeyEnv)
	}

	if doer == nil {
		doer = &http.Client{Timeout: cfg.TimeoutDuration()}
	}

	return &HTTPClient{
		httpDoer:  doer,
		cache:     newResponseCache(cfg.CacheTTLDuration(), cfg.CacheMaxEntries),
		baseURL:   strings.TrimSuffix(cfg.BaseURL, "/"),
		apiKey:    apiKey,
		model:     cfg.Model,
		threshold: cfg.ConfidenceThreshold,
	}, nil
}

// Decide implements Client.
func (c *HTTPClient) Decide(ctx context.Context, state any, questions map[string]Question) (*Response, error) {
	if len(questions) == 0 {
		return nil, ErrNoQuestions
	}

	body := request{Model: c.model, State: state, Questions: questions}
	payload, err := json.Marshal(body)
	if err != nil {
		return nil, fmt.Errorf("jev: encode request: %w", err)
	}

	if cached, ok := c.cache.get(payload); ok {
		return cached, nil
	}

	resp, err := c.post(ctx, payload)
	if err != nil {
		return nil, err
	}

	c.cache.put(payload, resp)
	return resp, nil
}

// Decide implements Client, always reporting ErrDisabled.
func (NoopClient) Decide(context.Context, any, map[string]Question) (*Response, error) {
	return nil, ErrDisabled
}

func (c *HTTPClient) post(ctx context.Context, payload []byte) (*Response, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.baseURL+decisionsPath, bytes.NewReader(payload))
	if err != nil {
		return nil, fmt.Errorf("jev: build request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+c.apiKey)

	httpResp, err := c.httpDoer.Do(req)
	if err != nil {
		return nil, fmt.Errorf("jev: call decisions api: %w", err)
	}
	defer httpResp.Body.Close()

	if httpResp.StatusCode != http.StatusOK {
		snippet, _ := io.ReadAll(io.LimitReader(httpResp.Body, maxErrorBody))
		return nil, fmt.Errorf("jev: decisions api status %d: %s", httpResp.StatusCode, strings.TrimSpace(string(snippet)))
	}

	var decoded Response
	if err := json.NewDecoder(httpResp.Body).Decode(&decoded); err != nil {
		return nil, fmt.Errorf("jev: decode response: %w", err)
	}
	return &decoded, nil
}

// responseCache is an optional, bounded, time-based cache. A zero ttl disables
// it entirely, which is the default.
type responseCache struct {
	entries    map[string]cacheEntry
	ttl        time.Duration
	maxEntries int
	mu         sync.Mutex
}

type cacheEntry struct {
	expires  time.Time
	response *Response
}

func newResponseCache(ttl time.Duration, maxEntries int) *responseCache {
	return &responseCache{
		entries:    make(map[string]cacheEntry),
		ttl:        ttl,
		maxEntries: maxEntries,
	}
}

func (c *responseCache) get(key []byte) (*Response, bool) {
	if c == nil || c.ttl <= 0 {
		return nil, false
	}
	c.mu.Lock()
	defer c.mu.Unlock()

	entry, ok := c.entries[string(key)]
	if !ok {
		return nil, false
	}
	if time.Now().After(entry.expires) {
		delete(c.entries, string(key))
		return nil, false
	}
	return entry.response, true
}

func (c *responseCache) put(key []byte, resp *Response) {
	if c == nil || c.ttl <= 0 {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()

	// Bounded rather than evicting cleverly: authorization inputs churn, and a
	// full flush is cheaper to reason about than an LRU under a lock.
	if len(c.entries) >= c.maxEntries {
		c.entries = make(map[string]cacheEntry, c.maxEntries)
	}
	c.entries[string(key)] = cacheEntry{expires: time.Now().Add(c.ttl), response: resp}
}
