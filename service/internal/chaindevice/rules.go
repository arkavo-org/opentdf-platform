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
	// ExemptActions holds lowercased action names the requirement does not
	// guard: a grant keeps those actions with no device. Nil means it guards
	// every action. It is an exemption rather than a list of guarded actions
	// so that a misspelled name guards more, never less.
	ExemptActions []string
}

// guards reports whether the requirement guards the action on the grant fqn.
// The action "" is never exempt.
func (q Requirement) guards(fqn, action string) bool {
	return matchesAny(q.Grants, fqn) && (action == "" || !slices.Contains(q.ExemptActions, strings.ToLower(action)))
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
// A nil r has no rules, so only an unbound device drops anything. Keeps counts
// no exemption: it is KeepsAction for an action no requirement exempts.
func (r *Rules) Keeps(devices []Device, fqn string) bool {
	return r.KeepsAction(devices, fqn, "")
}

// KeepsAction reports whether a person keeps the action on the grant fqn when
// devices ride in the chain. It is Keeps, except that a requirement that
// exempts the action does not apply to it. Action names compare ignoring case.
func (r *Rules) KeepsAction(devices []Device, fqn, action string) bool {
	if slices.ContainsFunc(devices, func(d Device) bool { return !d.Bound }) {
		return false
	}
	if r == nil {
		return true
	}
	for _, req := range r.Requirements {
		if req.guards(fqn, action) && !slices.ContainsFunc(devices, req.metBy) {
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

// Why Keeps drops a grant, as Why reports it.
const (
	// WhyUnboundDevice: a device of the chain is not bound to its person.
	WhyUnboundDevice = "unbound_device"
	// WhyRequirement: a requirement names the grant and no device meets it.
	WhyRequirement = "requirement"
	// WhyCap: a cap on the class of a device of the chain does not keep it.
	WhyCap = "cap"
)

// Why says why Keeps drops the grant fqn for these devices: "" when Keeps
// keeps it, else the first check of Keeps' it fails, WhyUnboundDevice,
// WhyRequirement or WhyCap. Keeps decides; Why only explains, for logs, and
// consults Keeps first, so it never disagrees with it.
func (r *Rules) Why(devices []Device, fqn string) string {
	return r.WhyAction(devices, fqn, "")
}

// WhyAction is Why for KeepsAction.
func (r *Rules) WhyAction(devices []Device, fqn, action string) string {
	if r.KeepsAction(devices, fqn, action) {
		return ""
	}
	if slices.ContainsFunc(devices, func(d Device) bool { return !d.Bound }) {
		return WhyUnboundDevice
	}
	if r != nil {
		for _, req := range r.Requirements {
			if req.guards(fqn, action) && !slices.ContainsFunc(devices, req.metBy) {
				return WhyRequirement
			}
		}
	}
	// Every device is bound and every requirement met, so a cap dropped it.
	return WhyCap
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
