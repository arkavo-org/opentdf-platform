package publishingstatus

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"fmt"
	"log/slog"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func validConfig() Config {
	return Config{
		URL:          "https://platform.arkavo.net",
		DialAddress:  "127.0.0.1:443",
		IdentityURL:  "https://identity.arkavo.net",
		ClientID:     "opentdf",
		ClientSecret: "s3cret-value",
	}
}

func TestValidate(t *testing.T) {
	tests := []struct {
		name    string
		mutate  func(*Config)
		wantErr bool
		// notContain is text the error must not echo.
		notContain string
	}{
		{name: "valid prod block", mutate: func(*Config) {}},
		{name: "valid with socket", mutate: func(c *Config) { c.DialAddress = ""; c.DialSocket = "/run/arks.sock" }},
		{name: "valid with timeouts", mutate: func(c *Config) { c.Timeout = 5 * time.Second; c.CacheTTL = 5 * time.Second }},
		{name: "http non-loopback without socket", mutate: func(c *Config) { c.URL = "http://platform.arkavo.net"; c.DialAddress = "" }, wantErr: true},
		{name: "http non-loopback with dial_address", mutate: func(c *Config) { c.URL = "http://platform.arkavo.net" }, wantErr: true},
		{name: "http non-loopback with socket", mutate: func(c *Config) {
			c.URL = "http://platform.arkavo.net"
			c.DialAddress = ""
			c.DialSocket = "/run/arks.sock"
		}},
		{name: "http loopback", mutate: func(c *Config) { c.URL = "http://127.0.0.1:9000"; c.DialAddress = "" }},
		{name: "dial_address and dial_socket", mutate: func(c *Config) { c.DialSocket = "/run/arks.sock" }, wantErr: true},
		{name: "url userinfo", mutate: func(c *Config) { c.URL = "https://u:hunter2@platform.arkavo.net" }, wantErr: true, notContain: "hunter2"},
		{name: "url query", mutate: func(c *Config) { c.URL = "https://platform.arkavo.net?k=hunter2" }, wantErr: true, notContain: "hunter2"},
		{name: "url empty query", mutate: func(c *Config) { c.URL = "https://platform.arkavo.net?" }, wantErr: true},
		{name: "url fragment", mutate: func(c *Config) { c.URL = "https://platform.arkavo.net#hunter2" }, wantErr: true, notContain: "hunter2"},
		{name: "identity_url userinfo", mutate: func(c *Config) { c.IdentityURL = "https://u:hunter2@identity.arkavo.net" }, wantErr: true, notContain: "hunter2"},
		{name: "identity_url query", mutate: func(c *Config) { c.IdentityURL = "https://identity.arkavo.net?k=hunter2" }, wantErr: true, notContain: "hunter2"},
		{name: "identity_url fragment", mutate: func(c *Config) { c.IdentityURL = "https://identity.arkavo.net#hunter2" }, wantErr: true, notContain: "hunter2"},
		{name: "identity_url plain http non-loopback", mutate: func(c *Config) { c.IdentityURL = "http://identity.arkavo.net" }, wantErr: true},
		{name: "identity_url http loopback", mutate: func(c *Config) { c.IdentityURL = "http://localhost:8080" }},
		{name: "identity_url http ignores socket", mutate: func(c *Config) {
			c.IdentityURL = "http://identity.arkavo.net"
			c.DialAddress = ""
			c.DialSocket = "/run/arks.sock"
		}, wantErr: true},
		{name: "unparseable url", mutate: func(c *Config) { c.URL = "http://[::1" }, wantErr: true, notContain: "[::1"},
		{name: "missing client_id", mutate: func(c *Config) { c.ClientID = "" }, wantErr: true},
		{name: "missing client_secret", mutate: func(c *Config) { c.ClientSecret = "" }, wantErr: true},
		{name: "missing url", mutate: func(c *Config) { c.URL = "" }, wantErr: true},
		{name: "missing identity_url", mutate: func(c *Config) { c.IdentityURL = "" }, wantErr: true},
		{name: "timeout too long", mutate: func(c *Config) { c.Timeout = 6 * time.Second }, wantErr: true},
		{name: "cache_ttl too long", mutate: func(c *Config) { c.CacheTTL = 6 * time.Second }, wantErr: true},
		{name: "negative timeout", mutate: func(c *Config) { c.Timeout = -time.Second }, wantErr: true},
		{name: "negative cache_ttl", mutate: func(c *Config) { c.CacheTTL = -time.Second }, wantErr: true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			c := validConfig()
			tc.mutate(&c)
			err := c.validate()
			if !tc.wantErr {
				require.NoError(t, err)
				return
			}
			require.Error(t, err)
			if tc.notContain != "" {
				assert.NotContains(t, err.Error(), tc.notContain)
			}
			assert.NotContains(t, err.Error(), "s3cret-value")
		})
	}
}

func TestEnabled(t *testing.T) {
	assert.False(t, Config{}.Enabled())
	assert.True(t, Config{ClientID: "x"}.Enabled())
	assert.True(t, Config{DialSocket: "/run/arks.sock"}.Enabled())
	assert.True(t, Config{CacheTTL: time.Second}.Enabled())
	assert.True(t, validConfig().Enabled())
}

func TestConfigRenderingHidesSecret(t *testing.T) {
	c := validConfig()
	var buf bytes.Buffer
	slog.New(slog.NewJSONHandler(&buf, nil)).Info("cfg", slog.Any("cfg", c))
	slog.New(slog.NewTextHandler(&buf, nil)).Info("cfg", slog.Any("cfg", c))
	js, err := json.Marshal(c)
	require.NoError(t, err)
	buf.Write(js)
	for _, s := range []string{
		fmt.Sprintf("%v", c), fmt.Sprintf("%+v", c), fmt.Sprintf("%#v", c),
		fmt.Sprintf("%v", &c), fmt.Sprintf("%s", c.ClientSecret), buf.String(),
	} {
		assert.NotContains(t, s, "s3cret-value")
	}
	assert.Contains(t, buf.String(), "opentdf")
}

// testCert returns a self-signed certificate for example.test and a pool
// that trusts it.
func testCert(t *testing.T) (tls.Certificate, *x509.CertPool) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "example.test"},
		DNSNames:     []string{"example.test"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	require.NoError(t, err)
	leaf, err := x509.ParseCertificate(der)
	require.NoError(t, err)
	pool := x509.NewCertPool()
	pool.AddCert(leaf)
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key, Leaf: leaf}, pool
}

func TestTransport_DialAddress(t *testing.T) {
	cert, pool := testCert(t)
	var gotHost string
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotHost = r.Host
		w.WriteHeader(http.StatusOK)
	}))
	srv.TLS = &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS12}
	srv.StartTLS()
	defer srv.Close()

	c := Config{URL: "https://example.test", DialAddress: srv.Listener.Addr().String()}
	tr := c.transport()
	tr.TLSClientConfig = &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS12}
	client := &http.Client{Transport: tr}

	resp, err := client.Get(c.URL + "/moderation/v1/suspensions/x")
	require.NoError(t, err)
	defer resp.Body.Close()
	assert.Equal(t, http.StatusOK, resp.StatusCode)
	assert.Equal(t, "example.test", gotHost)
}

func TestTransport_DialSocket(t *testing.T) {
	sock := filepath.Join(t.TempDir(), "s")
	ln, err := net.Listen("unix", sock)
	require.NoError(t, err)
	srv := &http.Server{
		ReadHeaderTimeout: time.Second,
		Handler: http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusOK)
		}),
	}
	go func() { _ = srv.Serve(ln) }()
	defer srv.Close()

	c := Config{URL: "http://platform.test", DialSocket: sock}
	client := &http.Client{Transport: c.transport()}
	resp, err := client.Get(c.URL + "/x")
	require.NoError(t, err)
	defer resp.Body.Close()
	assert.Equal(t, http.StatusOK, resp.StatusCode)
}

func TestTransport_NoOverrideDialsNormally(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	defer srv.Close()
	client := &http.Client{Transport: Config{URL: srv.URL}.transport()}
	resp, err := client.Get(srv.URL)
	require.NoError(t, err)
	resp.Body.Close()
}
