// Package chaindevice is the contract between an entity resolver and the PDP
// for a device that comes with a person in an entity chain. Such a device
// never holds the person's entitlements, so it cannot be decided as a
// subject. It narrows what the person keeps, by rules from the policy file
// (see Rules), and never grants.
//
// The resolver (the composite) writes the device's marker into its
// representation, under PropKey in an AdditionalProps struct, and decides
// whether the device is bound to the person. The PDP reads the marker only
// from the representation, never from the entity the caller sent, and applies
// Rules.Keeps to the person's grants. Only the composite writes a marker: a
// resolver that copies the caller's claims into a representation (the claims
// and multi-strategy resolvers) drops PropKey and TokenClaim from them, so a
// caller cannot forge one.
package chaindevice

import (
	"slices"

	entityresolutionV2 "github.com/opentdf/platform/protocol/go/entityresolution/v2"
	"google.golang.org/protobuf/types/known/structpb"
)

const (
	// PropKey is the AdditionalProps key a device marker travels under. It is
	// reserved: no properties_key may use it.
	PropKey = "arkavo_device"
	// TokenClaim is the claim of an environment claims entity that carries the
	// raw device token. It is reserved too.
	TokenClaim = "arkavo_device_token" //nolint:gosec // G101: the name of a claim, not a credential
	// KindDevice is the kind of a device marker.
	KindDevice = "device"

	// ClassAttested is a device whose app passed App Attest.
	ClassAttested = "attested"
	// ClassManaged is a managed device.
	ClassManaged = "managed"
	// ClassUnverified is the class of a device whose class was not verified.
	// A device from a PEP's claims, or from a token that did not verify, reads
	// as unverified with no app, and never binds. A verified token that names
	// an unknown class, or none, reads as unverified too, yet can bind and
	// keep its app.
	ClassUnverified = "unverified"

	// EnvProduction is the app environment of a production build.
	EnvProduction = "production"
	// EnvDevelopment is the app environment of a development build.
	EnvDevelopment = "development"
)

// Classes lists every device class.
var Classes = []string{ClassAttested, ClassManaged, ClassUnverified}

// Device is what a representation says about one device in a chain.
type Device struct {
	Class    string
	Verified bool
	// Bound is whether the device belongs to the person it rides with. An
	// unbound device denies every grant of the chain.
	Bound bool
	// AppIDHash is the lowercase hex SHA-256 of <TeamID>.<BundleID> (see
	// AppIDHash). Empty means the device has no app.
	AppIDHash string
	// AppEnv is the app environment. Empty means unknown.
	AppEnv string
}

// Props renders a device for an AdditionalProps struct. Every key is always
// present, so the shape is fixed.
func (d Device) Props() map[string]any {
	return map[string]any{
		"kind":        KindDevice,
		"class":       d.Class,
		"verified":    d.Verified,
		"bound":       d.Bound,
		"app_id_hash": d.AppIDHash,
		"app_env":     d.AppEnv,
	}
}

// FromRepresentation returns the device rep carries, if any. A marker that is
// present but malformed, or that is not verified, is read as an unverified,
// unbound device with no app, so a broken resolver narrows rather than widens.
func FromRepresentation(rep *entityresolutionV2.EntityRepresentation) (Device, bool) {
	for _, props := range rep.GetAdditionalProps() {
		field, ok := props.GetFields()[PropKey]
		if !ok {
			continue
		}
		return parseMarker(field), true
	}
	return Device{}, false
}

func parseMarker(field *structpb.Value) Device {
	unverified := Device{Class: ClassUnverified}
	marker := field.GetStructValue()
	if marker == nil {
		return unverified
	}
	m := marker.AsMap()
	if kind, _ := m["kind"].(string); kind != KindDevice {
		return unverified
	}
	class, _ := m["class"].(string)
	if !slices.Contains(Classes, class) {
		return unverified
	}
	verified, verifiedIsBool := m["verified"].(bool)
	bound, boundIsBool := m["bound"].(bool)
	if !verifiedIsBool || !boundIsBool || !verified {
		return unverified
	}
	appIDHash, hashOK := optionalString(m, "app_id_hash")
	appEnv, envOK := optionalString(m, "app_env")
	if !hashOK || !envOK {
		return unverified
	}
	return Device{
		Class:     class,
		Verified:  true,
		Bound:     bound,
		AppIDHash: appIDHash,
		AppEnv:    appEnv,
	}
}

// optionalString returns m[key] when it is a string, "" when it is absent,
// and false when it is present but not a string.
func optionalString(m map[string]any, key string) (string, bool) {
	v, present := m[key]
	if !present {
		return "", true
	}
	s, isString := v.(string)
	return s, isString
}
