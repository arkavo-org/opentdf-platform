package composite

import (
	"context"
	"errors"
	"fmt"
	"log/slog"

	arkavo "github.com/opentdf/platform/service/entityresolution/arkavo/v2"
	"github.com/opentdf/platform/service/entityresolution/source"
	"github.com/opentdf/platform/service/internal/publishingstatus"
	"github.com/opentdf/platform/service/logger/audit"
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

const (
	// publishingDefinition is the attribute definition a suspended creator
	// loses every value of. Matched by parsed definition, so
	// arkavo-creator-pro and the per-creator attributes are untouched.
	publishingDefinition = "https://patreon.arkavo.com/attr/arkavo-creator"
	// publishingConstraint names the constraint in logs and audit events.
	publishingConstraint = "publishing_status"

	reasonPublishingCheckerPanicked = "publishing status checker panicked"
	publishingWithheldMsg           = "composite: publishing grants withheld"
)

// withholdSuspendedPublishing drops every grant of publishingDefinition when
// subj holds one and arks does not answer that its sub is not suspended. Any
// failure to ask counts as a suspension. Other grants are never touched. Each
// withholding is logged and audited.
func (s *Service) withholdSuspendedPublishing(ctx context.Context, subj source.Subject, grants []sealedGrant) []sealedGrant {
	if s.publishing == nil {
		return grants
	}
	var withheld []string
	for _, g := range grants {
		if fqn, ok := source.ParseFQN(g.FQN); ok && fqn.DefinitionFQN() == publishingDefinition {
			withheld = append(withheld, g.FQN)
		}
	}
	if len(withheld) == 0 {
		return grants
	}
	sub, _ := subj.Claims["sub"].(string)
	err := checkPublishing(ctx, s.publishing, sub)
	if err == nil {
		s.logger.DebugContext(ctx, "composite: publishing status not suspended", slog.String("sub", sub))
		return grants
	}
	var denial *publishingstatus.DenialError
	if !errors.As(err, &denial) {
		denial = &publishingstatus.DenialError{Reason: publishingstatus.ReasonUnreachable, Subject: sub, Cause: err}
	} else if denial == nil {
		// A typed nil *DenialError: its fields and methods would panic.
		denial = &publishingstatus.DenialError{Reason: publishingstatus.ReasonUnreachable, Subject: sub, Cause: errors.New("checker returned a nil denial")}
	}

	attrs := []slog.Attr{
		slog.String("sub", sub),
		slog.String("reason", denial.Reason),
		slog.Any("withheld", withheld),
		slog.String("since", denial.Since),
		slog.String("report_id", denial.ReportID),
	}
	if denial.Cause != nil {
		attrs = append(attrs, slog.String("cause", denial.Cause.Error()))
	}
	level := slog.LevelWarn
	// These withhold every creator until an operator fixes config (or, for a
	// panic, the code), so they are errors rather than per-creator warnings.
	switch denial.Reason {
	case publishingstatus.ReasonForbidden, publishingstatus.ReasonUnauthorized,
		publishingstatus.ReasonCredentialsRejected, reasonPublishingCheckerPanicked:
		level = slog.LevelError
	}
	s.logger.LogAttrs(ctx, level, publishingWithheldMsg, attrs...)
	// The client already denies an empty sub without calling arks; the audit
	// event just needs a non-empty subject.
	auditSub := sub
	if auditSub == "" {
		auditSub = "(none)"
	}
	s.logger.Audit.EntitlementWithheld(ctx, audit.EntitlementWithheldEventParams{
		Constraint:   publishingConstraint,
		Subject:      auditSub,
		Reason:       denial.Reason,
		Since:        denial.Since,
		ReportID:     denial.ReportID,
		WithheldFQNs: withheld,
	})

	kept := make([]sealedGrant, 0, len(grants)-len(withheld))
	for _, g := range grants {
		if fqn, ok := source.ParseFQN(g.FQN); !ok || fqn.DefinitionFQN() != publishingDefinition {
			kept = append(kept, g)
		}
	}
	return kept
}

// checkPublishing runs the checker, turning a panic into a denial so a faulty
// checker withholds instead of failing the decision.
func checkPublishing(ctx context.Context, checker publishingstatus.Checker, sub string) (err error) {
	defer func() {
		if r := recover(); r != nil {
			err = &publishingstatus.DenialError{Reason: reasonPublishingCheckerPanicked, Subject: sub, Cause: fmt.Errorf("%v", r)}
		}
	}()
	return checker.Check(ctx, sub)
}
