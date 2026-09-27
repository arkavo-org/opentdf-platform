package auth

import "github.com/opentdf/platform/service/internal/agentstatus"

// AgentStatus returns the workload-status checker for agent-token rewraps.
// The explicit nil return matters: a nil *agentstatus.Client wrapped in the
// interface would be non-nil, and the KAS tests for nil to fail closed.
func (a *Authentication) AgentStatus() agentstatus.Checker {
	if a == nil || a.agentStatus == nil {
		return nil
	}
	return a.agentStatus
}
