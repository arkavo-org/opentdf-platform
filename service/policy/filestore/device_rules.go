package filestore

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strings"

	"github.com/opentdf/platform/protocol/go/policy"
	"github.com/opentdf/platform/service/entityresolution/source"
	"github.com/opentdf/platform/service/internal/chaindevice"
	"gopkg.in/yaml.v3"
)

// Length of the Team ID in an App Attest app ID, <TeamID>.<BundleID>.
const appTeamIDLen = 10

// DeviceRules returns the rules of the policy file's device_rules section, or
// nil when it declares none. A non-nil result holds at least one requirement
// or cap. The rules are shared by every caller and must not be modified.
func (s *Store) DeviceRules() *chaindevice.Rules {
	if s == nil {
		return nil
	}
	return s.deviceRules
}

// The device_rules subtree decodes strictly, unlike the rest of the schema.
// An optional key that is misspelled (app: for apps:, app_env: for app_envs:)
// would otherwise load as "any app" or "any environment", and a misspelled
// requirements: or caps: would drop the rules, so a rule would silently allow.
// Each type below rejects a key it does not know, naming the key.

// deviceRulesFields has the fields of DeviceRulesDef and none of its methods,
// so decoding into it does not recurse into UnmarshalYAML or UnmarshalJSON.
type (
	deviceRulesFields       DeviceRulesDef
	deviceRequirementFields DeviceRequirementDef
	deviceCapFields         DeviceCapDef
)

// UnmarshalYAML implements yaml.Unmarshaler, rejecting unknown keys.
func (d *DeviceRulesDef) UnmarshalYAML(n *yaml.Node) error {
	if err := rejectUnknownKeys(n, "device_rules", "requirements", "caps"); err != nil {
		return err
	}
	return n.Decode((*deviceRulesFields)(d))
}

// UnmarshalYAML implements yaml.Unmarshaler, rejecting unknown keys.
func (d *DeviceRequirementDef) UnmarshalYAML(n *yaml.Node) error {
	if err := rejectUnknownKeys(n, "a requirement", "grants", "device_classes", "apps", "app_envs"); err != nil {
		return err
	}
	return n.Decode((*deviceRequirementFields)(d))
}

// UnmarshalYAML implements yaml.Unmarshaler, rejecting unknown keys.
func (d *DeviceCapDef) UnmarshalYAML(n *yaml.Node) error {
	if err := rejectUnknownKeys(n, "a cap", "device_class", "keeps"); err != nil {
		return err
	}
	return n.Decode((*deviceCapFields)(d))
}

// rejectUnknownKeys fails when the mapping n has a key outside known. what
// names the mapping in the error.
func rejectUnknownKeys(n *yaml.Node, what string, known ...string) error {
	if n.Kind != yaml.MappingNode {
		return nil // the decode that follows reports the wrong shape
	}
	for i := 0; i+1 < len(n.Content); i += 2 {
		if key := n.Content[i]; !slices.Contains(known, key.Value) {
			return fmt.Errorf("filestore: device_rules: line %d: unknown key %q in %s (expected %s)",
				key.Line, key.Value, what, strings.Join(known, "|"))
		}
	}
	return nil
}

// UnmarshalJSON implements json.Unmarshaler, rejecting unknown keys at every
// level of the subtree.
func (d *DeviceRulesDef) UnmarshalJSON(data []byte) error {
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	if err := dec.Decode((*deviceRulesFields)(d)); err != nil {
		return fmt.Errorf("filestore: device_rules: %w", err)
	}
	return nil
}

// buildDeviceRules loads and validates the device_rules section. Every
// failure fails the load: a rule that is dropped or misread would let a
// device narrow less than the file says, which is a fail-open.
func (b *builder) buildDeviceRules() error {
	def := b.schema.DeviceRules
	if def == nil {
		return nil
	}
	rules := &chaindevice.Rules{}
	for i := range def.Requirements {
		req, err := b.deviceRequirement(&def.Requirements[i])
		if err != nil {
			return fmt.Errorf("filestore: device_rules: requirements[%d]: %w", i, err)
		}
		rules.Requirements = append(rules.Requirements, req)
	}
	capIndex := map[string]int{}
	for i := range def.Caps {
		c, err := b.deviceCap(&def.Caps[i])
		if err != nil {
			return fmt.Errorf("filestore: device_rules: caps[%d]: %w", i, err)
		}
		if first, dup := capIndex[c.DeviceClass]; dup {
			return fmt.Errorf("filestore: device_rules: caps[%d]: device_class %q already has a cap in caps[%d]", i, c.DeviceClass, first)
		}
		capIndex[c.DeviceClass] = i
		rules.Caps = append(rules.Caps, c)
	}
	if len(rules.Requirements) > 0 || len(rules.Caps) > 0 {
		b.deviceRules = rules
	}
	return nil
}

func (b *builder) deviceRequirement(def *DeviceRequirementDef) (chaindevice.Requirement, error) {
	grants, err := b.deviceFQNs("grants", def.Grants)
	if err != nil {
		return chaindevice.Requirement{}, err
	}
	if len(grants) == 0 {
		return chaindevice.Requirement{}, errors.New("grants must name at least one attribute value or definition, or the requirement narrows nothing")
	}
	if err := checkDeviceClasses("device_classes", def.DeviceClasses); err != nil {
		return chaindevice.Requirement{}, err
	}
	req := chaindevice.Requirement{
		Grants:        grants,
		DeviceClasses: append([]string(nil), def.DeviceClasses...),
	}
	// A list that is absent means "any"; one that is present and empty is
	// refused, since it would read as "any" too.
	if def.Apps != nil {
		if len(def.Apps) == 0 {
			return chaindevice.Requirement{}, errors.New("apps is present but empty; omit it to allow any app")
		}
		for i, app := range def.Apps {
			if !validAppID(app) {
				return chaindevice.Requirement{}, fmt.Errorf("apps[%d]: %q is not <TeamID>.<BundleID> (a %d-character Team ID of A-Z and 0-9, a dot, a bundle ID)", i, app, appTeamIDLen)
			}
			req.AppIDHashes = append(req.AppIDHashes, chaindevice.AppIDHash(app))
		}
	}
	if def.AppEnvs != nil {
		if len(def.AppEnvs) == 0 {
			return chaindevice.Requirement{}, errors.New("app_envs is present but empty; omit it to allow any environment")
		}
		for i, env := range def.AppEnvs {
			if env != chaindevice.EnvProduction && env != chaindevice.EnvDevelopment {
				return chaindevice.Requirement{}, fmt.Errorf("app_envs[%d]: unknown app environment %q (expected %s|%s)", i, env, chaindevice.EnvProduction, chaindevice.EnvDevelopment)
			}
		}
		req.AppEnvs = append([]string(nil), def.AppEnvs...)
	}
	return req, nil
}

func (b *builder) deviceCap(def *DeviceCapDef) (chaindevice.Cap, error) {
	if err := checkDeviceClasses("device_class", []string{def.DeviceClass}); err != nil {
		return chaindevice.Cap{}, err
	}
	keeps, err := b.deviceFQNs("keeps", def.Keeps)
	if err != nil {
		return chaindevice.Cap{}, err
	}
	return chaindevice.Cap{DeviceClass: def.DeviceClass, Keeps: keeps}, nil
}

// checkDeviceClasses requires a non-empty list of known device classes. field
// names the list in errors.
func checkDeviceClasses(field string, classes []string) error {
	if len(classes) == 0 {
		return fmt.Errorf("%s must name at least one class (%s); an empty list can never be met", field, strings.Join(chaindevice.Classes, "|"))
	}
	for i, class := range classes {
		if !isDeviceClass(class) {
			return fmt.Errorf("%s[%d]: unknown device class %q (expected %s)", field, i, class, strings.Join(chaindevice.Classes, "|"))
		}
	}
	return nil
}

func isDeviceClass(class string) bool {
	for _, c := range chaindevice.Classes {
		if c == class {
			return true
		}
	}
	return false
}

// deviceFQNs checks each FQN against the attributes the file declares and
// returns them lowercased. field names the list in errors.
func (b *builder) deviceFQNs(field string, fqns []string) ([]string, error) {
	out := make([]string, 0, len(fqns))
	for i, raw := range fqns {
		fqn, err := b.deviceFQN(raw)
		if err != nil {
			return nil, fmt.Errorf("%s[%d]: %w", field, i, err)
		}
		out = append(out, fqn)
	}
	return out, nil
}

// deviceFQN checks one value or definition FQN and returns it lowercased.
//
// It must name a declared attribute definition, which is not hierarchy, and a
// value FQN under a definition with declared values must name one of them. A
// definition with no declared values has synthetic values (campaigns, tiers),
// so any value under it is accepted. A name that matched nothing would never
// narrow, which fails open.
func (b *builder) deviceFQN(raw string) (string, error) {
	definition, valueFQN, parsed := parseDeviceFQN(raw)
	if !parsed {
		return "", fmt.Errorf("%q is not an attribute value or definition FQN (https://<namespace>/attr/<definition>[/value/<value>])", raw)
	}
	attr, declared := b.attributesByFQN[definition]
	if !declared {
		return "", fmt.Errorf("%q names the attribute definition %q, which the policy file does not declare", raw, definition)
	}
	if attr.GetRule() == policy.AttributeRuleTypeEnum_ATTRIBUTE_RULE_TYPE_ENUM_HIERARCHY {
		return "", fmt.Errorf("%q names the hierarchy attribute %q; a device rule cannot name a hierarchy attribute", raw, definition)
	}
	if valueFQN == "" {
		return definition, nil
	}
	if len(attr.GetValues()) > 0 {
		if _, known := b.valuesByFQN[valueFQN]; !known {
			return "", fmt.Errorf("%q is not one of the declared values of %q", raw, definition)
		}
	}
	return valueFQN, nil
}

// parseDeviceFQN splits a value FQN or a definition FQN into the lowercased
// definition FQN and, for a value FQN, the lowercased value FQN ("" for a
// definition FQN).
func parseDeviceFQN(raw string) (string, string, bool) {
	if v, isValue := source.ParseFQN(raw); isValue {
		definition := v.DefinitionFQN()
		return definition, definition + "/value/" + v.Value, true
	}
	if ns, def, isDefinition := source.ParseDefinition(raw); isDefinition {
		return "https://" + ns + "/attr/" + def, "", true
	}
	return "", "", false
}

// validAppID reports whether id has the form <TeamID>.<BundleID>: a Team ID of
// exactly 10 characters from A-Z and 0-9, a dot, and a non-empty bundle ID.
func validAppID(id string) bool {
	if len(id) <= appTeamIDLen+1 || id[appTeamIDLen] != '.' {
		return false
	}
	for _, c := range id[:appTeamIDLen] {
		if (c < 'A' || c > 'Z') && (c < '0' || c > '9') {
			return false
		}
	}
	return true
}
