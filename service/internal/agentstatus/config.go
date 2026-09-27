// Package agentstatus asks authnz-rs whether an agent's workload may still
// receive keys, before every agent-token rewrap. Contract: authnz-rs
// docs/agent-credentials-contract.md v1 (GET /agents/workloads/{id}/status).
package agentstatus

import (
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/url"
	"time"
)

const (
	defaultTimeout = 3 * time.Second
	redacted       = "[REDACTED]"
)

// Config is server.auth.agent_status. An empty URL leaves the checker
// unconfigured, and the KAS then refuses every agent-token rewrap.
type Config struct {
	// URL is the authnz-rs base URL, e.g. https://identity.arkavo.net.
	URL string `mapstructure:"url" json:"url"`
	// ClientID and ClientSecret mint the service CWT (client_credentials).
	ClientID     string `mapstructure:"client_id" json:"client_id"`
	ClientSecret Secret `mapstructure:"client_secret" json:"client_secret"`
	// Timeout bounds each call to identity; zero means 3 s.
	Timeout time.Duration `mapstructure:"timeout" json:"timeout"`
}

// Secret keeps the client secret out of every rendering:
// server.Config.LogValue logs the whole auth block.
type Secret string

func (Secret) String() string       { return redacted }
func (Secret) LogValue() slog.Value { return slog.StringValue(redacted) }

// MarshalJSON renders an unset secret as "": pkg/config seeds its defaults
// from the JSON of a zero config, and a "[REDACTED]" default would stand in
// for a missing client_secret and get past validate().
func (s Secret) MarshalJSON() ([]byte, error) {
	if s == "" {
		return []byte(`""`), nil
	}
	return []byte(`"` + redacted + `"`), nil
}

// Enabled reports whether a status endpoint is configured.
func (c Config) Enabled() bool { return c.URL != "" }

func (c Config) validate() error {
	u, err := url.Parse(c.URL)
	if err != nil {
		return fmt.Errorf("agent_status.url: %w", err)
	}
	if u.Host == "" {
		return errors.New("agent_status.url has no host")
	}
	if u.Scheme != "https" && (u.Scheme != "http" || !isLoopback(u.Hostname())) {
		return errors.New("agent_status.url must be https (plain http only on loopback)")
	}
	if c.ClientID == "" || c.ClientSecret == "" {
		return errors.New("agent_status.client_id and agent_status.client_secret are required")
	}
	return nil
}

func isLoopback(host string) bool {
	if host == "localhost" {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}
