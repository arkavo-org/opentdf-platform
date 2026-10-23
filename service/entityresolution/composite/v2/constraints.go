package composite

import (
	"context"
	"slices"

	arkavo "github.com/opentdf/platform/service/entityresolution/arkavo/v2"
	"github.com/opentdf/platform/service/entityresolution/source"
	"github.com/opentdf/platform/service/internal/entityconstraint"
)

// Constraints only remove grants.

// withheldAgent reports whether the agent gate refuses subj: an agent marker
// with no agent profile, no key-bound cnf, no agent_status configured, or an
// agent its status service does not find eligible. A subject with no agent
// marker is never checked. Every refusal is logged.
func (s *Service) withheldAgent(ctx context.Context, subj source.Subject) bool {
	agent, err := arkavo.AgentDenial(ctx, s.agentStatus, subj.Claims, claimAccountID)
	if err == nil {
		return false
	}
	arkavo.LogAgentDenial(ctx, s.logger, agent, err)
	return true
}

// capGrants keeps, of a device subject's grants, only those its class is
// capped to. The class is arkavo_npe.class, "unverified" when absent; a class
// with no entry in caps has no cap. A cap intersects and never adds, and
// other subjects are not capped.
func capGrants(caps map[string]map[string]bool, subj source.Subject, grants []sealedGrant) []sealedGrant {
	if subj.Kind != source.KindDevice {
		return grants
	}
	allowed, capped := caps[deviceClass(subj.Claims)]
	if !capped {
		return grants
	}
	kept := make([]sealedGrant, 0, len(grants))
	for _, g := range grants {
		if allowed[g.FQN] {
			kept = append(kept, g)
		}
	}
	return kept
}

// deviceConstraint is the constraint a device of class puts on the subjects
// of its chain: capped to caps[class], or not capped when the class has no
// entry, as capGrants judges a device subject.
func (s *Service) deviceConstraint(class string) map[string]any {
	allowed, capped := s.caps[class]
	fqns := make([]string, 0, len(allowed))
	for fqn := range allowed {
		fqns = append(fqns, fqn)
	}
	slices.Sort(fqns)
	return entityconstraint.Props(entityconstraint.KindDevice, class, capped, fqns)
}
