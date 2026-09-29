package agentstatus

// Claims that mark a subject as an agent. authnz-rs contract v2 mints
// arkavo_state_version and arkavo_swarm on agent tokens; arkavo_npe
// describes a non-person entity; arkavo_roles may name the agent role.
const (
	ClaimStateVersion = "arkavo_state_version"
	ClaimSwarm        = "arkavo_swarm"
	ClaimNpe          = "arkavo_npe"
	ClaimRoles        = "arkavo_roles"
	NpeTypeAgent      = "agent"
	NpeTypeDevice     = "device"
	RoleAgent         = "agent"
)

// HasAgentMarker reports whether a claims map carries any agent marker: an
// arkavo_npe of any type but device (including a missing, empty or
// malformed type), arkavo_swarm, arkavo_state_version (whatever its
// value), or an agent role. A token that looks partly like an agent's is
// judged as one. Person and device subjects carry none of these. A marker
// only ever widens gating: it grants nothing by itself.
//
// Every entity resolver that can see agent tokens shares this one test, so
// a subject gated in one mode is gated in all of them.
func HasAgentMarker(claims map[string]any) bool {
	if npe, present := claims[ClaimNpe]; present {
		members, _ := npe.(map[string]any)
		if typ, _ := members["type"].(string); typ != NpeTypeDevice {
			return true
		}
	}
	if _, present := claims[ClaimSwarm]; present {
		return true
	}
	if _, present := claims[ClaimStateVersion]; present {
		return true
	}
	return hasAgentRole(claims[ClaimRoles])
}

// hasAgentRole reads arkavo_roles as a string or a list.
func hasAgentRole(roles any) bool {
	switch r := roles.(type) {
	case string:
		return r == RoleAgent
	case []any:
		for _, role := range r {
			if role == RoleAgent {
				return true
			}
		}
	case []string:
		for _, role := range r {
			if role == RoleAgent {
				return true
			}
		}
	}
	return false
}
