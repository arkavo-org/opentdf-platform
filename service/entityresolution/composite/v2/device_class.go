package composite

import (
	"context"
	"fmt"
	"strings"

	"github.com/go-viper/mapstructure/v2"
	"github.com/opentdf/platform/service/entityresolution/source"
)

// classUnverified is the class of a device whose arkavo_npe omits one.
const classUnverified = "unverified"

// deviceClassSource grants a device the value FQNs configured for its class.
type deviceClassSource struct {
	classes map[string][]string
}

// newDeviceClassSource returns the source that grants a device subject
// classes[arkavo_npe.class], or classes["unverified"] when the claim has no
// class. Every other kind of subject gets nothing. It takes the class from
// the claims it is given; the capability decides whether those claims count.
func newDeviceClassSource(classes map[string][]string) source.Source {
	return &deviceClassSource{classes: classes}
}

func (s *deviceClassSource) Resolve(_ context.Context, subject source.Subject, _ source.Query) (source.Resolution, error) {
	if subject.Kind != source.KindDevice {
		return source.Resolution{Outcome: source.OutcomeNotApplicable}, nil
	}
	var grants []source.Grant
	seen := map[string]bool{}
	for _, raw := range s.classes[deviceClass(subject.Claims)] {
		fqn := strings.ToLower(raw)
		if _, ok := source.ParseFQN(fqn); !ok || seen[fqn] {
			continue
		}
		seen[fqn] = true
		grants = append(grants, source.Grant{FQN: fqn})
	}
	return source.Resolution{Grants: grants, Outcome: source.OutcomeComplete}, nil
}

// deviceClass is a device's arkavo_npe.class, or "unverified" when the claim
// has none.
func deviceClass(claims map[string]any) string {
	if npe, _ := claims["arkavo_npe"].(map[string]any); npe != nil {
		if c, _ := npe["class"].(string); c != "" {
			return c
		}
	}
	return classUnverified
}

// deviceClasses reads a device-class source's classes option: a map of class
// name to value FQNs.
func deviceClasses(opts map[string]any) (map[string][]string, error) {
	raw, ok := opts[optionClasses]
	if !ok {
		return nil, fmt.Errorf("a device-class source needs a %s map", optionClasses)
	}
	var classes map[string][]string
	if err := mapstructure.Decode(raw, &classes); err != nil {
		return nil, fmt.Errorf("%s must map a class name to a list of value FQNs: %w", optionClasses, err)
	}
	return classes, nil
}
