package composite

import (
	"context"

	arkavo "github.com/opentdf/platform/service/entityresolution/arkavo/v2"
	"github.com/opentdf/platform/service/entityresolution/source"
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
