package arkavo

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
)

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
		"CWT int64":              {int64(7), 7, true},
		"uint64":                 {uint64(7), 7, true},
		"int":                    {7, 7, true},
		"structpb float64":       {float64(7), 7, true},
		"2^53 - 1":               {float64(1<<53 - 1), 1<<53 - 1, true},
		"2^53 is past the bound": {float64(1 << 53), 0, false},
		"int64 2^53":             {int64(1 << 53), 0, false},
		"zero reads as zero":     {int64(0), 0, true},
		"negative":               {int64(-1), 0, false},
		"fraction":               {7.5, 0, false},
		"string":                 {"7", 0, false},
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
