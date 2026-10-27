// Package publishingstatus asks arks whether an account is suspended from
// publishing. The composite entity resolver's constraints.publishing_status
// consults it and withholds only the account's
// https://patreon.arkavo.com/attr/arkavo-creator grants on a suspension or any
// unclear answer. Contract: arks GET /moderation/v1/suspensions/{sub}.
package publishingstatus

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"path/filepath"
	"strconv"
	"time"

	"github.com/opentdf/platform/service/internal/servicetoken"
)

// maxDuration caps both timeout and cache_ttl at 5 s, so a new suspension
// takes effect within about 5 s.
const maxDuration = 5 * time.Second

// Config is services.entityresolution.constraints.publishing_status (the
// composite resolver). Leaving every field unset turns the constraint off.
type Config struct {
	// URL is the arks base URL, e.g. https://platform.arkavo.net. TLS
	// verification, SNI and the Host header always follow this host name,
	// whatever DialAddress or DialSocket say.
	URL string `mapstructure:"url" json:"url"`
	// DialAddress (host:port) sends every connection to arks there instead of
	// resolving URL's host, e.g. 127.0.0.1:443 when arks is on this host.
	DialAddress string `mapstructure:"dial_address" json:"dial_address"`
	// DialSocket is an absolute Unix socket path doing the same job. It
	// excludes DialAddress. It is the only case where URL may be plain http
	// on a non-loopback host name, because the request cannot leave the host.
	DialSocket string `mapstructure:"dial_socket" json:"dial_socket"`
	// IdentityURL is the authnz-rs base URL that mints the service CWT. It is
	// never dialed through the override above.
	IdentityURL string `mapstructure:"identity_url" json:"identity_url"`
	// ClientID and ClientSecret mint the service CWT (client_credentials).
	ClientID     string              `mapstructure:"client_id" json:"client_id"`
	ClientSecret servicetoken.Secret `mapstructure:"client_secret" json:"client_secret"`
	// Timeout bounds each call to arks; zero means 3 s. At most 5 s.
	Timeout time.Duration `mapstructure:"timeout" json:"timeout"`
	// CacheTTL is how long a not-suspended answer is reused; zero means 5 s. At most 5 s.
	CacheTTL time.Duration `mapstructure:"cache_ttl" json:"cache_ttl"`
}

// Enabled reports whether any field is set. A partial block is enabled too,
// so validate() fails it at startup rather than it silently doing nothing.
func (c Config) Enabled() bool {
	return c.URL != "" || c.DialAddress != "" || c.DialSocket != "" ||
		c.IdentityURL != "" || c.ClientID != "" || c.ClientSecret != "" ||
		c.Timeout != 0 || c.CacheTTL != 0
}

// LogValue keeps slog from reflecting over the secret-bearing fields.
func (c Config) LogValue() slog.Value {
	return slog.GroupValue(
		slog.String("url", c.URL),
		slog.String("dial_address", c.DialAddress),
		slog.String("dial_socket", c.DialSocket),
		slog.String("identity_url", c.IdentityURL),
		slog.String("client_id", c.ClientID),
		slog.Duration("timeout", c.Timeout),
		slog.Duration("cache_ttl", c.CacheTTL),
	)
}

func (c Config) validate() error {
	if c.DialAddress != "" && c.DialSocket != "" {
		return errors.New("publishing_status.dial_address and publishing_status.dial_socket are mutually exclusive")
	}
	if c.DialAddress != "" {
		_, port, err := net.SplitHostPort(c.DialAddress)
		if n, convErr := strconv.Atoi(port); err != nil || convErr != nil || n < 1 || n > 65535 {
			return errors.New("publishing_status.dial_address must be host:port with a numeric port")
		}
	}
	if c.DialSocket != "" && !filepath.IsAbs(c.DialSocket) {
		return errors.New("publishing_status.dial_socket must be an absolute path")
	}
	// Plain http must never leave the host: a socket, or loopback on both the
	// URL and the dial address.
	// noPlain: the dial target is off-host, so plain http is forbidden outright.
	noPlain := false
	if c.DialAddress != "" {
		host, _, _ := net.SplitHostPort(c.DialAddress)
		noPlain = !isLoopback(host)
	}
	plainOK := c.DialSocket != ""
	// No error names a URL: it may carry credentials.
	if err := checkURL("publishing_status.url", c.URL, plainOK, noPlain); err != nil {
		return err
	}
	// The identity endpoint is not dialed through the override, so only
	// loopback may be plain http.
	if err := checkURL("publishing_status.identity_url", c.IdentityURL, false, false); err != nil {
		return err
	}
	if c.ClientID == "" || c.ClientSecret == "" {
		return errors.New("publishing_status.client_id and publishing_status.client_secret are required")
	}
	if c.Timeout < 0 || c.Timeout > maxDuration {
		return fmt.Errorf("publishing_status.timeout must be between 0 and %s", maxDuration)
	}
	if c.CacheTTL < 0 || c.CacheTTL > maxDuration {
		return fmt.Errorf("publishing_status.cache_ttl must be between 0 and %s", maxDuration)
	}
	return nil
}

// checkURL validates a base URL. Plain http is allowed on loopback, and also
// when plainOK says the connection stays on this host regardless of the name;
// noPlain forbids it outright (the dial target is off-host).
func checkURL(field, raw string, plainOK, noPlain bool) error {
	if raw == "" {
		return fmt.Errorf("%s is required", field)
	}
	u, err := url.Parse(raw)
	if err != nil {
		return fmt.Errorf("%s is not a valid URL", field)
	}
	if u.User != nil {
		return fmt.Errorf("%s must not carry userinfo; use client_id and client_secret", field)
	}
	if u.Host == "" {
		return fmt.Errorf("%s has no host", field)
	}
	// The client appends its own paths to the base URL.
	if u.RawQuery != "" || u.ForceQuery || u.Fragment != "" {
		return fmt.Errorf("%s must not carry a query or fragment", field)
	}
	if u.Scheme != "https" && (u.Scheme != "http" || noPlain || (!plainOK && !isLoopback(u.Hostname()))) {
		return fmt.Errorf("%s must be https (plain http only on loopback or with dial_socket)", field)
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

// transport returns the transport for calls to arks. With dial_address or
// dial_socket it dials that target for every address, while the request URL
// still decides TLS ServerName and Host, so verification is unchanged.
func (c Config) transport() *http.Transport {
	t, ok := http.DefaultTransport.(*http.Transport)
	if !ok {
		t = &http.Transport{}
	}
	t = t.Clone()
	// arks is reached directly: a proxy from the environment would misroute
	// the call and could carry the service CWT.
	t.Proxy = nil
	network, target := "", ""
	switch {
	case c.DialSocket != "":
		network, target = "unix", c.DialSocket
	case c.DialAddress != "":
		network, target = "tcp", c.DialAddress
	default:
		return t
	}
	var d net.Dialer
	t.DialContext = func(ctx context.Context, _, _ string) (net.Conn, error) {
		return d.DialContext(ctx, network, target)
	}
	return t
}
