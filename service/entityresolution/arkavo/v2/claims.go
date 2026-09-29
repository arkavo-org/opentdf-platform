package arkavo

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"math"
	"strconv"
	"strings"

	"github.com/opentdf/platform/service/internal/auth"
)

// claimsFromToken accepts either a JOSE JWT (the RAR endpoint's unsigned
// bridge, or a real JWT) or a base64url CWT (the with_request_token path
// hands the ERS the raw bearer). Signature verification happened upstream.
// The JOSE-then-CWT parse is shared with the Patreon provider via
// auth.DecodeClaimsFromToken.
//
// arkavo_state_version is then judged exactly: on the JWT path it is read
// from the payload text, before anything turns it into a float64, and
// rewritten to an in-range int64 or to stateVersionMalformed; on the CWT
// path the decoder's own int64 is kept as is, in or out of range (a value
// outside 0..maxExactVersion later reads as "not a version" via
// stateVersionClaim), and only a claim present in some other shape becomes
// stateVersionMalformed. Either way the claim's presence still gates the
// subject; it never reads as a version unless it is actually one.
func claimsFromToken(ctx context.Context, tokenRaw string) (map[string]any, error) {
	m, err := auth.DecodeClaimsFromToken(ctx, tokenRaw)
	if err != nil {
		return nil, err
	}
	if raw, ok := jwtPayloadClaim(tokenRaw, claimStateVersion); ok {
		m[claimStateVersion] = exactStateVersion(raw)
	} else if v, present := m[claimStateVersion]; present {
		if _, isInt := v.(int64); !isInt {
			m[claimStateVersion] = stateVersionMalformed
		}
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
// holds exactly (2^53 - 1): the claim reaches ResolveEntities through
// structpb, which carries every number as a float64, and a float64 cannot
// tell 2^53 from 2^53+1.
const maxExactVersion = 1<<53 - 1

// maxVersionDigits is len("9007199254740991"), maxExactVersion's digits.
const maxVersionDigits = 16

// stateVersionMalformed stands in for an arkavo_state_version that is present
// but is not an integer from 0 to maxExactVersion. Its presence still gates
// the subject; a string never reads as a version.
const stateVersionMalformed = "malformed"

// stateVersionClaim reads arkavo_state_version as claimsFromToken leaves it
// (int64) or as structpb hands it to the second pass (float64): a
// non-negative integer no larger than maxExactVersion. Anything else, the
// sentinel included, is not a version.
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

// exactStateVersion judges arkavo_state_version as written in a JWT payload:
// an integer literal (digits only: no sign, fraction or exponent) of at most
// maxExactVersion, returned as the int64 the CWT decoder would give. Anything
// else is stateVersionMalformed. Reading the text is what keeps 2^53+1 or
// 1.00000000000000001 from passing as the float64 each rounds to.
func exactStateVersion(raw json.RawMessage) any {
	text := strings.TrimSpace(string(raw))
	if text == "" || len(text) > maxVersionDigits || strings.Trim(text, "0123456789") != "" {
		return stateVersionMalformed
	}
	v, err := strconv.ParseInt(text, 10, 64)
	if err != nil || v > maxExactVersion {
		return stateVersionMalformed
	}
	return v
}

// jwtPayloadClaim returns claim's raw JSON from a compact JWS payload, and
// whether the token is one that carries the claim. A CWT (one base64url
// segment) is not.
func jwtPayloadClaim(tokenRaw, claim string) (json.RawMessage, bool) {
	const compactJWSSegments = 3 // header.payload.signature
	parts := strings.Split(tokenRaw, ".")
	if len(parts) != compactJWSSegments {
		return nil, false
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, false
	}
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(payload, &fields); err != nil {
		return nil, false
	}
	raw, ok := fields[claim]
	return raw, ok
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
