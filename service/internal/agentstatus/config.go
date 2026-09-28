// Package agentstatus asks authnz-rs whether an agent identity is still
// eligible. The arkavo entity resolver consults it whenever it resolves an
// agent subject, so an agent that is unassessed, suspended or quarantined
// resolves with no entitlements. Contract: authnz-rs
// docs/agent-credentials-contract.md v2 (GET /agents/{did}/status).
package agentstatus

import (
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/url"
	"time"
)

const (
	defaultTimeout = 3 * time.Second
	redacted       = "[REDACTED]"
)

// Config is services.entityresolution.agent_status (arkavo mode). Leaving
// url, client_id and client_secret all unset leaves the checker
// unconfigured, and every agent subject then resolves with no entitlements.
type Config struct {
	// URL is the authnz-rs base URL, e.g. https://identity.arkavo.net.
	URL string `mapstructure:"url" json:"url"`
	// ClientID and ClientSecret mint the service CWT (client_credentials).
	ClientID     string `mapstructure:"client_id" json:"client_id"`
	ClientSecret Secret `mapstructure:"client_secret" json:"client_secret"`
	// Timeout bounds each call to identity; zero means 3 s. A whole check is
	// bounded at twice this. At most 5 s (the status lease), so a live answer
	// is never older than a cached one could be.
	Timeout time.Duration `mapstructure:"timeout" json:"timeout"`
}

// Secret keeps the client secret out of every rendering:
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

// Enabled reports whether any of url, client_id or client_secret is set.
// A partial block is enabled too, so validate() fails it at startup rather
// than it silently leaving every agent refused.
func (c Config) Enabled() bool { return c.URL != "" || c.ClientID != "" || c.ClientSecret != "" }

func (c Config) validate() error {
	// Neither error names the URL: it may carry credentials.
	u, err := url.Parse(c.URL)
	if err != nil {
		return errors.New("agent_status.url is not a valid URL")
	}
	if u.User != nil {
		return errors.New("agent_status.url must not carry userinfo; use client_id and client_secret")
	}
	if u.Host == "" {
		return errors.New("agent_status.url has no host")
	}
	// The client appends its own paths to the base URL.
	if u.RawQuery != "" || u.ForceQuery || u.Fragment != "" {
		return errors.New("agent_status.url must not carry a query or fragment")
	}
	if u.Scheme != "https" && (u.Scheme != "http" || !isLoopback(u.Hostname())) {
		return errors.New("agent_status.url must be https (plain http only on loopback)")
	}
	if c.ClientID == "" || c.ClientSecret == "" {
		return errors.New("agent_status.client_id and agent_status.client_secret are required")
	}
	if c.Timeout > maxStatusTTL {
		return fmt.Errorf("agent_status.timeout must be at most %s (the status lease)", maxStatusTTL)
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
