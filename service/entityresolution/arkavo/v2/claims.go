package arkavo

import "math"

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
	// Swarm is "" when absent or not a string. HasStateVersion is true
	// whenever the claim is present, whatever its type or value. Whether
	// the subject is gated is read from Raw (agentstatus.HasAgentMarker).
	Swarm           string
	HasStateVersion bool
	// StateVersion is arkavo_state_version, 0 when absent or not an integer
	// from 0 to maxExactVersion: such a token is withheld.
	StateVersion uint64
	// KeyBound: cnf carries the key itself (cnf.jwk).
	KeyBound bool
	Raw      map[string]any
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

// maxExactVersion is the largest integer every representation on the way
// holds exactly (2^53 - 1): a claims chain reaches the resolver through
// structpb, which carries every number as a float64, and a float64 cannot
// tell 2^53 from 2^53+1.
const maxExactVersion = 1<<53 - 1

// stateVersionClaim reads arkavo_state_version as the CWT verifier decodes it
// (an integer) or as structpb carries it (float64): a non-negative integer no
// larger than maxExactVersion. Anything else is not a version.
func stateVersionClaim(v any) (uint64, bool) {
	switch x := v.(type) {
	case int64:
		if x >= 0 && x <= maxExactVersion {
			return uint64(x), true
		}
	case int:
		return stateVersionClaim(int64(x))
	case uint64:
		if x <= maxExactVersion {
			return x, true
		}
	case float64:
		if x >= 0 && x <= maxExactVersion && x == math.Trunc(x) {
			return uint64(x), true
		}
	}
	return 0, false
}

func parseArkavoClaims(m map[string]any) arkavoClaims {
	c := arkavoClaims{Raw: m}
	c.Iss, _ = m["iss"].(string)
	c.Sub, _ = m["sub"].(string)
	c.AccountID, _ = m["arkavo_account_id"].(string)
	c.Roles = strList(m["arkavo_roles"])
	c.Entitlements = strList(m["arkavo_entitlements"])
	c.StateVersion, _ = stateVersionClaim(m[claimStateVersion])
	_, c.HasStateVersion = m[claimStateVersion]
	c.Swarm, _ = m[claimSwarm].(string)
	c.KeyBound = hasKeyCnf(m[claimCnf])
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
