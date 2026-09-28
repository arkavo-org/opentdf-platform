package arkavo

import (
	"encoding/base64"
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
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

func TestStateVersionClaim(t *testing.T) {
	for name, tt := range map[string]struct {
		in   any
		want uint64
		ok   bool
	}{
		"first pass int64":       {int64(7), 7, true},
		"uint64":                 {uint64(7), 7, true},
		"int":                    {7, 7, true},
		"second pass float64":    {float64(7), 7, true},
		"2^53 - 1":               {float64(1<<53 - 1), 1<<53 - 1, true},
		"2^53 is past the bound": {float64(1 << 53), 0, false},
		"int64 2^53":             {int64(1 << 53), 0, false},
		"zero reads as zero":     {int64(0), 0, true},
		"negative":               {int64(-1), 0, false},
		"fraction":               {7.5, 0, false},
		"string":                 {"7", 0, false},
		"the malformed sentinel": {stateVersionMalformed, 0, false},
		"json.Number":            {json.Number("7"), 0, false},
		"absent":                 {nil, 0, false},
	} {
		t.Run(name, func(t *testing.T) {
			got, ok := stateVersionClaim(tt.in)
			assert.Equal(t, tt.ok, ok)
			assert.Equal(t, tt.want, got)
		})
	}
}

// claimsFromToken judges arkavo_state_version from the JWT payload text,
// before jwx turns it into a float64: only an integer literal from 0 to
// 2^53-1 survives, as an int64; any other value present becomes the sentinel.
func TestClaimsFromToken_StateVersionIsReadFromThePayloadText(t *testing.T) {
	for raw, want := range map[string]any{
		`3`:                   int64(3),
		`0`:                   int64(0),
		`9007199254740991`:    int64(9007199254740991),
		`9007199254740992`:    stateVersionMalformed,
		`9007199254740993`:    stateVersionMalformed,
		`1.0000000001`:        stateVersionMalformed,
		`1.00000000000000001`: stateVersionMalformed,
		`3.0`:                 stateVersionMalformed,
		`-1`:                  stateVersionMalformed,
		`"3"`:                 stateVersionMalformed,
		`null`:                stateVersionMalformed,
		`{"v":3}`:             stateVersionMalformed,
	} {
		t.Run(raw, func(t *testing.T) {
			tok := buildJWT(t, map[string]interface{}{"iss": "i", "sub": "s", claimStateVersion: json.RawMessage(raw)})
			m, err := claimsFromToken(t.Context(), tok)
			assert.NoError(t, err)
			assert.Equal(t, want, m[claimStateVersion])
		})
	}
	m, err := claimsFromToken(t.Context(), buildJWT(t, map[string]interface{}{"iss": "i", "sub": "s"}))
	assert.NoError(t, err)
	_, present := m[claimStateVersion]
	assert.False(t, present, "an absent claim stays absent")
}
