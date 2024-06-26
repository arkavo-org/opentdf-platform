package server

import (
	"github.com/arkavo-org/opentdf-platform/service/authorization"
	"github.com/arkavo-org/opentdf-platform/service/health"
	"github.com/arkavo-org/opentdf-platform/service/kas"
	"github.com/arkavo-org/opentdf-platform/service/pkg/serviceregistry"
	"github.com/arkavo-org/opentdf-platform/service/policy"
	wellknown "github.com/arkavo-org/opentdf-platform/service/wellknownconfiguration"
)

func registerServices() error {
	// Register the services
	services := []serviceregistry.Registration{
		health.NewRegistration(),
		authorization.NewRegistration(),
		kas.NewRegistration(),
		wellknown.NewRegistration(),
	}
	services = append(services, policy.NewRegistrations()...)

	// Register the services
	for _, s := range services {
		if err := serviceregistry.RegisterService(s); err != nil {
			return err //nolint:wrapcheck // We are all friends here
		}
	}
	return nil
}
