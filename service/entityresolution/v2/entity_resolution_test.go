package entityresolution

import (
	"testing"

	"github.com/opentdf/platform/service/pkg/config"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestRegisterFunc_ModeAndSourcesIsFatal(t *testing.T) {
	sources := []any{map[string]any{"id": "patreon", "type": "patreon-token"}}
	tests := []struct {
		name         string
		cfg          config.ServiceConfig
		wantComposed bool
		wantErr      string
	}{
		{"sources only", config.ServiceConfig{"sources": sources}, true, ""},
		{"empty mode and sources", config.ServiceConfig{"mode": "", "sources": sources}, true, ""},
		{"mode only", config.ServiceConfig{"mode": "keycloak"}, false, ""},
		{"neither", config.ServiceConfig{}, false, ""},
		{"nil", nil, false, ""},
		{"mode and sources", config.ServiceConfig{"mode": "patreon", "sources": sources}, false, "mode"},
		{"keycloak mode and sources", config.ServiceConfig{"mode": "keycloak", "sources": sources}, false, "sources"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			useComposite, err := selectResolver(tc.cfg)
			if tc.wantErr != "" {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tc.wantErr)
				assert.False(t, useComposite)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, tc.wantComposed, useComposite)
		})
	}
}
