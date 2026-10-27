// Package identityentities reads a person's claims from identity's
// GET /entities/arkavo:<uuid>: exactly the claims a token freshly minted for
// that account would carry. The composite entity resolver's patreon-identity
// source grants from them instead of from the token. Contract: authnz-rs
// 0.26.0 (authnz-rs#127).
package identityentities

import (
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/url"
	"time"

	"github.com/opentdf/platform/service/internal/servicetoken"
)

const (
	// defaultTimeout covers identity's wait on a cold Patreon snapshot (up to
	// 3 s, PATREON_MATERIALIZE_DEADLINE_SECONDS) with room for the call.
	defaultTimeout = 3500 * time.Millisecond
	maxTimeout     = 10 * time.Second
	// defaultCacheTTL is how long an answer is reused without asking again.
	// Identity caches Patreon snapshots for 300 s, so this is never staler
	// than a token minted at the same moment.
	defaultCacheTTL = 60 * time.Second
	maxCacheTTL     = 60 * time.Second
	// defaultStaleMaxAge is how old an answer may be and still be served while
	// identity is unavailable: the longest a person token the platform accepts
	// lives, so stale-on-error is never staler than today's token claims.
	defaultStaleMaxAge = time.Hour
	maxStaleMaxAge     = time.Hour
	// defaultFailureBackoff is how long a failed lookup is remembered, so an
	// account whose Patreon link is broken does not cost a full timeout on
	// every decision.
	defaultFailureBackoff = 30 * time.Second
	maxFailureBackoff     = 5 * time.Minute
)

// Config is services.entityresolution.identity_entities (the composite
// resolver). Leaving every field unset turns it off.
type Config struct {
	// URL is identity's base URL, e.g. https://identity.arkavo.net. The
	// service CWT is minted at <url>/oauth/token.
	URL string `mapstructure:"url" json:"url"`
	// ClientID and ClientSecret mint the service CWT (client_credentials).
	// The client must be on identity's ENTITY_CLIENT_IDS.
	ClientID     string              `mapstructure:"client_id" json:"client_id"`
	ClientSecret servicetoken.Secret `mapstructure:"client_secret" json:"client_secret"`
	// Timeout bounds each call to identity; zero means 3.5 s. A lookup that
	// first mints the service CWT may take two calls.
	Timeout time.Duration `mapstructure:"timeout" json:"timeout"`
	// CacheTTL is how long an answer is reused; zero means 60 s, the most allowed.
	CacheTTL time.Duration `mapstructure:"cache_ttl" json:"cache_ttl"`
	// StaleMaxAge is how old an answer may be and still be served while
	// identity is unavailable; zero means 1 h, the most allowed.
	StaleMaxAge time.Duration `mapstructure:"stale_max_age" json:"stale_max_age"`
	// FailureBackoff is how long a failed lookup is remembered before
	// identity is asked again; zero means 30 s.
	FailureBackoff time.Duration `mapstructure:"failure_backoff" json:"failure_backoff"`
}

// Enabled reports whether any field is set. A partial block is enabled too,
// so Validate fails it at startup rather than it silently doing nothing.
func (c Config) Enabled() bool {
	return c.URL != "" || c.ClientID != "" || c.ClientSecret != "" ||
		c.Timeout != 0 || c.CacheTTL != 0 || c.StaleMaxAge != 0 || c.FailureBackoff != 0
}

// LogValue keeps slog from reflecting over the secret-bearing fields.
func (c Config) LogValue() slog.Value {
	return slog.GroupValue(
		slog.String("url", c.URL),
		slog.String("client_id", c.ClientID),
		slog.Duration("timeout", c.Timeout),
		slog.Duration("cache_ttl", c.CacheTTL),
		slog.Duration("stale_max_age", c.StaleMaxAge),
		slog.Duration("failure_backoff", c.FailureBackoff),
	)
}

// Validate reports the first problem with the block. No error names the
// URL, which may carry credentials, or the secret.
func (c Config) Validate() error {
	if c.URL == "" {
		return errors.New("identity_entities.url is required")
	}
	u, err := url.Parse(c.URL)
	switch {
	case err != nil:
		return errors.New("identity_entities.url is not a valid URL")
	case u.User != nil:
		return errors.New("identity_entities.url must not carry userinfo; use client_id and client_secret")
	case u.Host == "":
		return errors.New("identity_entities.url has no host")
	case u.RawQuery != "" || u.ForceQuery || u.Fragment != "":
		return errors.New("identity_entities.url must not carry a query or fragment")
	case u.Scheme != "https" && (u.Scheme != "http" || !isLoopback(u.Hostname())):
		return errors.New("identity_entities.url must be https (plain http only on loopback)")
	}
	if c.ClientID == "" || c.ClientSecret == "" {
		return errors.New("identity_entities.client_id and identity_entities.client_secret are required")
	}
	for _, d := range []struct {
		name     string
		val, max time.Duration
	}{
		{"timeout", c.Timeout, maxTimeout},
		{"cache_ttl", c.CacheTTL, maxCacheTTL},
		{"stale_max_age", c.StaleMaxAge, maxStaleMaxAge},
		{"failure_backoff", c.FailureBackoff, maxFailureBackoff},
	} {
		if d.val < 0 || d.val > d.max {
			return fmt.Errorf("identity_entities.%s must be between 0 and %s", d.name, d.max)
		}
	}
	return nil
}

// withDefaults fills every zero duration.
func (c Config) withDefaults() Config {
	if c.Timeout == 0 {
		c.Timeout = defaultTimeout
	}
	if c.CacheTTL == 0 {
		c.CacheTTL = defaultCacheTTL
	}
	if c.StaleMaxAge == 0 {
		c.StaleMaxAge = defaultStaleMaxAge
	}
	if c.FailureBackoff == 0 {
		c.FailureBackoff = defaultFailureBackoff
	}
	return c
}

func isLoopback(host string) bool {
	if host == "localhost" {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}
