package arkavo

import (
	"encoding/base64"
	"encoding/json"
	"testing"
)

// buildJWT encodes claims as a compact, unsigned (alg=none) JWT, mirroring
// encodeUnsignedJWT in service/internal/auth/cwt_verifier.go — the exact
// wire format the fork's verified-CWT-to-unsigned-JWT bridge hands the ERS.
func buildJWT(t *testing.T, claims map[string]interface{}) string {
	t.Helper()
	header := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"none","typ":"JWT"}`))
	body, err := json.Marshal(claims)
	if err != nil {
		t.Fatalf("marshal claims: %v", err)
	}
	return header + "." + base64.RawURLEncoding.EncodeToString(body) + "."
}

func TestClaimsFromToken_JOSEThenCWT(t *testing.T) {
	jose := buildJWT(t, map[string]interface{}{"iss": "i", "sub": "s"})
	m, err := claimsFromToken(t.Context(), jose)
	if err != nil || m["sub"] != "s" {
		t.Fatalf("jose: %v %v", m, err)
	}
	if _, err := claimsFromToken(t.Context(), "definitely-not-a-token"); err == nil {
		t.Error("garbage must fail")
	}
}

func TestParseArkavoClaims_AgentShape(t *testing.T) {
	m := map[string]any{
		"iss":                 "https://identity.arkavo.net",
		"sub":                 "did:key:z6Mkabc",
		"arkavo_account_id":   "00000000-0000-0000-0000-000000000001",
		"arkavo_roles":        []any{"agent"},
		"arkavo_entitlements": []any{"https://arkavo.ai/attr/tdf/value/decrypt"},
		"arkavo_npe": map[string]any{
			"type": "agent", "delegation_id": "did:key:z6Mkabc", "depth": int64(0), "chain": []any{},
		},
		"act": []any{map[string]any{"sub": "https://kg.arkavo.net"}},
	}
	c := parseArkavoClaims(m)
	if c.Sub != "did:key:z6Mkabc" || c.AccountID != "00000000-0000-0000-0000-000000000001" {
		t.Errorf("identity: %+v", c)
	}
	if len(c.Entitlements) != 1 || c.Roles[0] != "agent" {
		t.Errorf("lists: %+v", c)
	}
	if c.Npe == nil || c.Npe.Type != "agent" || c.Npe.Depth != 0 {
		t.Errorf("npe: %+v", c.Npe)
	}
	if len(c.Actors) != 1 || c.Actors[0] != "https://kg.arkavo.net" {
		t.Errorf("act: %v", c.Actors)
	}
}

func TestConfigApplyDefaults(t *testing.T) {
	var c Config
	c.applyDefaults()
	if len(c.DirectEntitlementActions) != 1 || c.DirectEntitlementActions[0] != "read" {
		t.Errorf("direct entitlement actions default: %v", c.DirectEntitlementActions)
	}
	if c.ClientIDClaim != "arkavo_account_id" {
		t.Errorf("client id claim default: %q", c.ClientIDClaim)
	}
	if c.DeviceClassCeilings == nil {
		t.Error("device class ceilings should default to an empty map, not nil")
	}

	populated := Config{
		DirectEntitlementActions: []string{"create", "update"},
		ClientIDClaim:            "custom_claim",
	}
	populated.applyDefaults()
	if len(populated.DirectEntitlementActions) != 2 || populated.DirectEntitlementActions[0] != "create" {
		t.Errorf("configured actions must not be clobbered: %v", populated.DirectEntitlementActions)
	}
	if populated.ClientIDClaim != "custom_claim" {
		t.Errorf("configured client id claim must not be clobbered: %q", populated.ClientIDClaim)
	}
}

func TestParseArkavoClaims_DeviceShape(t *testing.T) {
	m := map[string]any{
		"sub": "u", "arkavo_npe": map[string]any{
			"type": "device", "class": "attested", "attestation_expiry": int64(1800000000), "device_id": "K1",
		},
	}
	c := parseArkavoClaims(m)
	if c.Npe == nil || c.Npe.Class != "attested" || c.Npe.AttestationExpiry != 1800000000 || c.Npe.DeviceID != "K1" {
		t.Errorf("device npe: %+v", c.Npe)
	}
}
