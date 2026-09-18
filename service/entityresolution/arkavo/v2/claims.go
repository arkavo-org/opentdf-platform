package arkavo

import (
	"context"
	"fmt"

	"github.com/lestrrat-go/jwx/v2/jwt"

	"github.com/opentdf/platform/service/internal/auth"
)

// claimsFromToken accepts either a JOSE JWT (the RAR endpoint's unsigned
// bridge, or a real JWT) or a base64url CWT (the with_request_token path
// hands the ERS the raw bearer). Signature verification happened upstream.
func claimsFromToken(ctx context.Context, tokenRaw string) (map[string]any, error) {
	if parsed, err := jwt.ParseString(tokenRaw, jwt.WithVerify(false), jwt.WithValidate(false)); err == nil {
		m, err := parsed.AsMap(ctx)
		if err != nil {
			return nil, fmt.Errorf("read jwt claims: %w", err)
		}
		return m, nil
	}
	m, err := auth.DecodeCWTClaimsFromToken(tokenRaw)
	if err != nil {
		return nil, fmt.Errorf("token is neither JWT nor CWT: %w", err)
	}
	return m, nil
}

type npeClaim struct {
	Type              string
	Class             string
	DeviceID          string
	DelegationID      string
	AttestationExpiry int64
	Depth             int64
	Chain             []string
}

type arkavoClaims struct {
	Iss, Sub, AccountID string
	Roles, Entitlements []string
	Npe                 *npeClaim
	Actors              []string
	Raw                 map[string]any
}

func strList(v any) []string {
	items, ok := v.([]any)
	if !ok {
		return nil
	}
	out := make([]string, 0, len(items))
	for _, it := range items {
		if s, isStr := it.(string); isStr && s != "" {
			out = append(out, s)
		}
	}
	return out
}

func asInt64(v any) int64 {
	switch x := v.(type) {
	case int64:
		return x
	case int:
		return int64(x)
	case uint64:
		return int64(x)
	case float64:
		return int64(x)
	}
	return 0
}

func parseArkavoClaims(m map[string]any) arkavoClaims {
	c := arkavoClaims{Raw: m}
	c.Iss, _ = m["iss"].(string)
	c.Sub, _ = m["sub"].(string)
	c.AccountID, _ = m["arkavo_account_id"].(string)
	c.Roles = strList(m["arkavo_roles"])
	c.Entitlements = strList(m["arkavo_entitlements"])
	if raw, ok := m["arkavo_npe"].(map[string]any); ok {
		n := &npeClaim{}
		n.Type, _ = raw["type"].(string)
		n.Class, _ = raw["class"].(string)
		n.DeviceID, _ = raw["device_id"].(string)
		n.DelegationID, _ = raw["delegation_id"].(string)
		n.AttestationExpiry = asInt64(raw["attestation_expiry"])
		n.Depth = asInt64(raw["depth"])
		n.Chain = strList(raw["chain"])
		if n.Type != "" {
			c.Npe = n
		}
	}
	if acts, isSlice := m["act"].([]any); isSlice {
		for _, a := range acts {
			if am, isMap := a.(map[string]any); isMap {
				if s, isStr := am["sub"].(string); isStr && s != "" {
					c.Actors = append(c.Actors, s)
				}
			}
		}
	}
	return c
}
