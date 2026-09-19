package jev

import (
	"errors"
	"fmt"
	"log/slog"
	"time"
)

// Mode controls whether a seam's answers affect the outcome.
type Mode string

const (
	// ModeShadow evaluates and records the answer but discards its effect.
	// This is the default for every seam so that enabling Jev anywhere is
	// observable before it is authoritative.
	ModeShadow Mode = "shadow"
	// ModeEnforce lets the answer take effect, within the restrict-only
	// bounds each seam enforces.
	ModeEnforce Mode = "enforce"
)

// FailMode controls what happens when the model cannot be reached in time.
type FailMode string

const (
	// FailOpen ignores the error and proceeds on policy alone. This is safe
	// for restrict-only seams, where losing the answer can only lose a
	// restriction that policy never required.
	FailOpen FailMode = "open"
	// FailClosed turns an unreachable model into a denied decision.
	FailClosed FailMode = "closed"
)

// Defaults for the Jev client. The model is pinned rather than tracking
// "~typesafe/jev-latest" so that decisions stay reproducible across releases.
const (
	DefaultModel               = "typesafe/jev-1.13"
	DefaultBaseURL             = "https://openrouter.ai"
	DefaultAPIKeyEnv           = "OPENROUTER_API_KEY" //nolint:gosec // env var name, not a credential
	DefaultTimeout             = "500ms"
	DefaultConfidenceThreshold = 0.8
	DefaultCacheMaxEntries     = 1024

	decisionsPath = "/api/alpha/decisions"
	minThreshold  = 0.0
	maxThreshold  = 1.0
)

// SeamConfig gates one integration point.
type SeamConfig struct {
	Enabled bool `mapstructure:"enabled" json:"enabled" default:"false"`
	Mode    Mode `mapstructure:"mode" json:"mode" default:"shadow"`
}

// Enforcing reports whether this seam may affect outcomes.
func (s SeamConfig) Enforcing() bool {
	return s.Enabled && s.Mode == ModeEnforce
}

// SeamsConfig collects the supported integration points.
type SeamsConfig struct {
	// ERSClaims derives entity claims from model answers, which then flow
	// through ordinary subject mappings.
	ERSClaims SeamConfig `mapstructure:"ers_claims" json:"ers_claims"`
	// Obligations may add required obligations to a decision.
	Obligations SeamConfig `mapstructure:"obligations" json:"obligations"`
}

// Config configures the Jev client and the seams that consume it.
type Config struct {
	Enabled bool `mapstructure:"enabled" json:"enabled" default:"false"`

	Model     string `mapstructure:"model" json:"model" default:"typesafe/jev-1.13"`
	BaseURL   string `mapstructure:"base_url" json:"base_url" default:"https://openrouter.ai"`
	APIKeyEnv string `mapstructure:"api_key_env" json:"api_key_env" default:"OPENROUTER_API_KEY"`
	Timeout   string `mapstructure:"timeout" json:"timeout" default:"500ms"`

	FailMode FailMode `mapstructure:"fail_mode" json:"fail_mode" default:"open"`

	// ConfidenceThreshold is the minimum certainty below which an answer is
	// treated as absent.
	ConfidenceThreshold float64 `mapstructure:"confidence_threshold" json:"confidence_threshold" default:"0.8"`

	// StateAllowlist names the keys that may leave the platform in a request.
	// Anything not named here is dropped before the call. An empty allowlist
	// means nothing is sent, which disables the client rather than leaking.
	StateAllowlist []string `mapstructure:"state_allowlist" json:"state_allowlist"`

	// CacheTTL enables a short-lived response cache when non-zero. Disabled
	// by default because cached authorization inputs are easy to get wrong.
	CacheTTL        string `mapstructure:"cache_ttl" json:"cache_ttl" default:"0s"`
	CacheMaxEntries int    `mapstructure:"cache_max_entries" json:"cache_max_entries" default:"1024"`

	Seams SeamsConfig `mapstructure:"seams" json:"seams"`
}

// ErrNoStateAllowlist is returned when the client is enabled but no state keys
// are permitted to leave the platform, which would make every call empty.
var ErrNoStateAllowlist = errors.New("jev: enabled but state_allowlist is empty; nothing may be sent")

// Validate checks the configuration and normalizes empty optional fields.
func (c *Config) Validate() error {
	if !c.Enabled {
		return nil
	}

	c.applyDefaults()

	if _, err := time.ParseDuration(c.Timeout); err != nil {
		return fmt.Errorf("jev: invalid timeout %q: %w", c.Timeout, err)
	}
	if _, err := time.ParseDuration(c.CacheTTL); err != nil {
		return fmt.Errorf("jev: invalid cache_ttl %q: %w", c.CacheTTL, err)
	}
	if c.ConfidenceThreshold < minThreshold || c.ConfidenceThreshold > maxThreshold {
		return fmt.Errorf("jev: confidence_threshold %v outside [0,1]", c.ConfidenceThreshold)
	}
	if c.FailMode != FailOpen && c.FailMode != FailClosed {
		return fmt.Errorf("jev: fail_mode %q must be %q or %q", c.FailMode, FailOpen, FailClosed)
	}
	if len(c.StateAllowlist) == 0 {
		return ErrNoStateAllowlist
	}
	for name, seam := range map[string]SeamConfig{
		"ers_claims":  c.Seams.ERSClaims,
		"obligations": c.Seams.Obligations,
	} {
		if seam.Enabled && seam.Mode != ModeShadow && seam.Mode != ModeEnforce {
			return fmt.Errorf("jev: seam %s mode %q must be %q or %q", name, seam.Mode, ModeShadow, ModeEnforce)
		}
	}
	return nil
}

// TimeoutDuration returns the parsed timeout, falling back to the default when
// unset. Validate rejects unparseable values, so this cannot fail in practice.
func (c *Config) TimeoutDuration() time.Duration {
	d, err := time.ParseDuration(c.Timeout)
	if err != nil {
		d, _ = time.ParseDuration(DefaultTimeout)
	}
	return d
}

// CacheTTLDuration returns the parsed cache TTL; zero disables caching.
func (c *Config) CacheTTLDuration() time.Duration {
	d, err := time.ParseDuration(c.CacheTTL)
	if err != nil {
		return 0
	}
	return d
}

// LogValue renders the config for logs. The API key is read from the
// environment and is never held on the config, so there is nothing to redact.
func (c *Config) LogValue() slog.Value {
	return slog.GroupValue(
		slog.Bool("enabled", c.Enabled),
		slog.String("model", c.Model),
		slog.String("base_url", c.BaseURL),
		slog.String("timeout", c.Timeout),
		slog.String("fail_mode", string(c.FailMode)),
		slog.Float64("confidence_threshold", c.ConfidenceThreshold),
		slog.Int("state_allowlist_size", len(c.StateAllowlist)),
		slog.String("cache_ttl", c.CacheTTL),
		slog.Any("seams", slog.GroupValue(
			slog.Bool("ers_claims_enabled", c.Seams.ERSClaims.Enabled),
			slog.String("ers_claims_mode", string(c.Seams.ERSClaims.Mode)),
			slog.Bool("obligations_enabled", c.Seams.Obligations.Enabled),
			slog.String("obligations_mode", string(c.Seams.Obligations.Mode)),
		)),
	)
}

func (c *Config) applyDefaults() {
	if c.Model == "" {
		c.Model = DefaultModel
	}
	if c.BaseURL == "" {
		c.BaseURL = DefaultBaseURL
	}
	if c.APIKeyEnv == "" {
		c.APIKeyEnv = DefaultAPIKeyEnv
	}
	if c.Timeout == "" {
		c.Timeout = DefaultTimeout
	}
	if c.FailMode == "" {
		c.FailMode = FailOpen
	}
	if c.ConfidenceThreshold == 0 {
		c.ConfidenceThreshold = DefaultConfidenceThreshold
	}
	if c.CacheTTL == "" {
		c.CacheTTL = "0s"
	}
	if c.CacheMaxEntries == 0 {
		c.CacheMaxEntries = DefaultCacheMaxEntries
	}
}
