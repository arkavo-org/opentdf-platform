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
		{"claims mode only", config.ServiceConfig{"mode": "claims"}, false, ""},
		{"multi-strategy mode only", config.ServiceConfig{"mode": "multi-strategy"}, false, ""},
		{"neither", config.ServiceConfig{}, false, ""},
		{"nil", nil, false, ""},
		{"mode and sources", config.ServiceConfig{"mode": "claims", "sources": sources}, false, "mode"},
		{"keycloak mode and sources", config.ServiceConfig{"mode": "keycloak", "sources": sources}, false, "sources"},
		// The removed modes are refused, not left to fall through to Keycloak.
		{"removed patreon mode", config.ServiceConfig{"mode": "patreon"}, false, `mode "patreon" was removed; configure sources`},
		{"removed arkavo mode", config.ServiceConfig{"mode": "arkavo"}, false, `mode "arkavo" was removed; configure sources`},
		{"removed mode and sources", config.ServiceConfig{"mode": "patreon", "sources": sources}, false, `mode "patreon" was removed`},
		// A removed mode in any case is still refused.
		{"removed mode, capitalized", config.ServiceConfig{"mode": "Patreon"}, false, `mode "Patreon" was removed`},
		{"removed mode, upper case", config.ServiceConfig{"mode": "ARKAVO"}, false, `mode "ARKAVO" was removed`},
		// Composite-only blocks without sources would start Keycloak instead.
		{"evidence without sources", config.ServiceConfig{"evidence": map[string]any{"seal_key": ""}}, false, `"evidence" is set but sources is not`},
		{"constraints without sources", config.ServiceConfig{"constraints": map[string]any{}}, false, `"constraints" is set but sources is not`},
		{"evidence with a mode and no sources", config.ServiceConfig{"mode": "claims", "evidence": map[string]any{}}, false, `"evidence" is set but sources is not`},
		// cache_expiration is read by every resolver, so it stays legitimate.
		{"cache_expiration and sources", config.ServiceConfig{"cache_expiration": "30s", "sources": sources}, true, ""},
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

// The removed modes' top-level keys are refused, with or without sources,
// naming the key and where it moved: under sources the composite would
// ignore them, and no other resolver reads them.
func TestSelectResolver_RemovedKeys(t *testing.T) {
	sources := []any{map[string]any{"id": "patreon", "type": "patreon-token"}}
	tests := map[string]string{
		"trust_materialized_claims":  "evidence.claims_chain_peps",
		"trusted_issuer":             "evidence.issuers",
		"infer_unknown_as_free":      "sources[].infer_unknown_as_free",
		"entitlements_namespace":     "sources[].entitlements_namespace",
		"agent_status":               "constraints.agent_status",
		"device_class_ceilings":      "device_rules in the policy file",
		"client_id_claim":            "server.auth.policy.client_id_claim",
		"direct_entitlement_actions": "sources[].actions",
	}
	for key, movedTo := range tests {
		for name, cfg := range map[string]config.ServiceConfig{
			"with sources":    {key: "x", "sources": sources},
			"without sources": {key: "x"},
		} {
			t.Run(key+" "+name, func(t *testing.T) {
				useComposite, err := selectResolver(cfg)
				require.Error(t, err)
				assert.False(t, useComposite)
				assert.Contains(t, err.Error(), `key "`+key+`" was removed`)
				assert.Contains(t, err.Error(), movedTo)
			})
		}
	}
}
