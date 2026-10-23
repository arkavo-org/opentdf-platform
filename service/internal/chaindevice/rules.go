package chaindevice

import (
	"crypto/sha256"
	"encoding/hex"
	"slices"
	"strings"
)

// Requirement says that the grants it names are kept only when some device in
// the chain meets it.
type Requirement struct {
	// Grants holds lowercased value or definition FQNs (see Matches).
	Grants []string
	// DeviceClasses lists the classes that meet the requirement.
	DeviceClasses []string
	// AppIDHashes lists the apps that meet the requirement (see AppIDHash).
	// Nil or empty means any app, including none.
	AppIDHashes []string
	// AppEnvs lists the app environments that meet the requirement. Nil or
	// empty means any environment, including an unknown one.
	AppEnvs []string
}

// metBy reports whether d meets the requirement. A device with no app, or an
// unknown app environment, meets a list only by that list being empty.
func (q Requirement) metBy(d Device) bool {
	return slices.Contains(q.DeviceClasses, d.Class) &&
		listed(q.AppIDHashes, d.AppIDHash) &&
		listed(q.AppEnvs, d.AppEnv)
}

// listed reports whether list is empty (no restriction) or holds the non-empty
// value v.
func listed(list []string, v string) bool {
	return len(list) == 0 || (v != "" && slices.Contains(list, v))
}

// Cap limits what a person keeps while a device of one class is in the chain.
type Cap struct {
	DeviceClass string
	// Keeps holds the lowercased value or definition FQNs (see Matches) the
	// person keeps. Everything else is dropped.
	Keeps []string
}

// Rules are the device rules of a policy file. The zero value, and nil, have
// no rules.
type Rules struct {
	Requirements []Requirement
	Caps         []Cap
}

// Keeps reports whether a person keeps the grant fqn when devices ride in the
// chain. A device narrows and never grants:
//
//   - any unbound device drops every grant;
//   - for every requirement that names fqn, some device must meet it;
//   - for every cap on the class of a device in the chain, the cap must keep
//     fqn, so caps intersect.
//
// A nil r has no rules, so only an unbound device drops anything.
func (r *Rules) Keeps(devices []Device, fqn string) bool {
	if slices.ContainsFunc(devices, func(d Device) bool { return !d.Bound }) {
		return false
	}
	if r == nil {
		return true
	}
	for _, req := range r.Requirements {
		if matchesAny(req.Grants, fqn) && !slices.ContainsFunc(devices, req.metBy) {
			return false
		}
	}
	for _, c := range r.Caps {
		inChain := slices.ContainsFunc(devices, func(d Device) bool { return d.Class == c.DeviceClass })
		if inChain && !matchesAny(c.Keeps, fqn) {
			return false
		}
	}
	return true
}

// Narrows reports whether Keeps could drop a grant for these devices, so a
// caller can skip it when it cannot.
func (r *Rules) Narrows(devices []Device) bool {
	return len(devices) > 0 || (r != nil && len(r.Requirements) > 0)
}

// Matches reports whether pattern covers fqn, ignoring case. A pattern covers
// itself, and a definition FQN also covers the values below it. A definition
// FQN is not a prefix: .../attr/campaign does not cover .../attr/campaign-tier.
func Matches(pattern, fqn string) bool {
	pattern, fqn = strings.ToLower(pattern), strings.ToLower(fqn)
	return pattern == fqn || strings.HasPrefix(fqn, pattern+"/value/")
}

func matchesAny(patterns []string, fqn string) bool {
	return slices.ContainsFunc(patterns, func(p string) bool { return Matches(p, fqn) })
}

// AppIDHash returns the lowercase hex SHA-256 of an app ID of the form
// <TeamID>.<BundleID>. It is the hash App Attest binds a key to.
func AppIDHash(appID string) string {
	sum := sha256.Sum256([]byte(appID))
	return hex.EncodeToString(sum[:])
}
