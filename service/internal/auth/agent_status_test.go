package auth

import (
	"bytes"
	"encoding/json"
	"log/slog"
	"testing"
	"time"

	"github.com/opentdf/platform/service/internal/agentstatus"
	"github.com/opentdf/platform/service/logger"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestAuthentication_AgentStatus(t *testing.T) {
	srv, _, _ := fakeIDP(t)
	build := func(status agentstatus.Config) (*Authentication, error) {
		return NewAuthenticator(t.Context(), Config{
			AuthNConfig: AuthNConfig{Issuer: srv.URL, Audience: "test", DPoPSkew: time.Hour},
			AgentStatus: status,
		}, logger.CreateTestLogger(), func(string, any) error { return nil })
	}

	t.Run("unconfigured is an untyped nil so the KAS fails closed", func(t *testing.T) {
		a, err := build(agentstatus.Config{})
		require.NoError(t, err)
		if a.AgentStatus() != nil {
			t.Fatal("AgentStatus() must be a nil interface when agent_status is unset")
		}
		var none *Authentication
		if none.AgentStatus() != nil {
			t.Fatal("nil *Authentication must yield a nil Checker")
		}
	})

	t.Run("configured returns a checker", func(t *testing.T) {
		a, err := build(agentstatus.Config{URL: "https://identity.test", ClientID: "opentdf", ClientSecret: "s"})
		require.NoError(t, err)
		assert.NotNil(t, a.AgentStatus())
	})

	t.Run("partial config (credentials without url) fails startup", func(t *testing.T) {
		_, err := build(agentstatus.Config{ClientID: "opentdf", ClientSecret: "s"})
		require.ErrorContains(t, err, "agent_status")
	})

	// Only the KAS refuses agents, so only the KAS warns when it has no
	// checker (kas.NewRegistration); the authenticator stays quiet.
	t.Run("unconfigured does not warn from the authenticator", func(t *testing.T) {
		var buf bytes.Buffer
		_, err := NewAuthenticator(t.Context(), Config{
			AuthNConfig: AuthNConfig{Issuer: srv.URL, Audience: "test", DPoPSkew: time.Hour},
		}, &logger.Logger{Logger: slog.New(slog.NewJSONHandler(&buf, nil))}, func(string, any) error { return nil })
		require.NoError(t, err)
		assert.NotContains(t, buf.String(), "agent_status")
	})

	t.Run("invalid config fails startup", func(t *testing.T) {
		_, err := build(agentstatus.Config{URL: "ftp://identity.test", ClientID: "opentdf", ClientSecret: "s"})
		require.ErrorContains(t, err, "agent_status")
	})

	t.Run("client secret never reaches JSON or logs of the auth block", func(t *testing.T) {
		cfg := Config{AgentStatus: agentstatus.Config{URL: "https://identity.test", ClientID: "opentdf", ClientSecret: "s3cret-value"}}
		raw, err := json.Marshal(cfg)
		require.NoError(t, err)
		var buf bytes.Buffer
		slog.New(slog.NewJSONHandler(&buf, nil)).Info("config", slog.Any("auth_config", cfg))
		slog.New(slog.NewTextHandler(&buf, nil)).Info("config", slog.Any("auth_config", cfg))
		assert.NotContains(t, string(raw), "s3cret-value")
		assert.NotContains(t, buf.String(), "s3cret-value")
	})
}
