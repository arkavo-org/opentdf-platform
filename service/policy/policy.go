package policy

import (
	"github.com/arkavo-org/opentdf-platform/service/pkg/serviceregistry"
	"github.com/arkavo-org/opentdf-platform/service/policy/attributes"
	"github.com/arkavo-org/opentdf-platform/service/policy/kasregistry"
	"github.com/arkavo-org/opentdf-platform/service/policy/namespaces"
	"github.com/arkavo-org/opentdf-platform/service/policy/resourcemapping"
	"github.com/arkavo-org/opentdf-platform/service/policy/subjectmapping"
)

func NewRegistrations() []serviceregistry.Registration {
	registrations := []serviceregistry.Registration{}
	namespace := "policy"

	for _, r := range []serviceregistry.Registration{
		attributes.NewRegistration(),
		namespaces.NewRegistration(),
		resourcemapping.NewRegistration(),
		subjectmapping.NewRegistration(),
		kasregistry.NewRegistration(),
	} {
		r.Namespace = namespace
		registrations = append(registrations, r)
	}

	return registrations
}
