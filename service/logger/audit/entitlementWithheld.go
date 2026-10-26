package audit

import (
	"context"
	"time"
)

// EntitlementWithheldEventParams describes a constraint that removed grants
// from a subject. The constraint's cause text is deliberately absent: it can
// carry upstream error detail, and belongs in the service log only.
type EntitlementWithheldEventParams struct {
	// Constraint names the constraint, e.g. publishing_status.
	Constraint string
	// Subject is the withheld subject's sub.
	Subject      string
	Reason       string
	Since        string
	ReportID     string
	WithheldFQNs []string
}

// CreateEntitlementWithheldEvent builds the event for a withholding. It is a
// decision event: the subject asked for entitlements and a constraint refused
// them.
func CreateEntitlementWithheldEvent(ctx context.Context, p EntitlementWithheldEventParams) (*EventObject, error) {
	auditDataFromContext := GetAuditDataFromContext(ctx)

	fqns := p.WithheldFQNs
	if fqns == nil {
		fqns = []string{}
	}
	return &EventObject{
		Object: auditEventObject{
			ID:   p.Subject + "-" + p.Constraint,
			Type: ObjectTypeEntityObject,
			Name: "entitlementWithheld-" + p.Constraint,
		},
		Action: eventAction{
			Type:   ActionTypeRead,
			Result: ActionResultFailure,
		},
		Actor: auditEventActor{
			ID:         p.Subject,
			Attributes: []any{},
		},
		EventMetaData: auditEventMetadata{
			"constraint":    p.Constraint,
			"reason":        p.Reason,
			"since":         p.Since,
			"report_id":     p.ReportID,
			"withheld_fqns": fqns,
		},
		ClientInfo: eventClientInfo{
			Platform:  "entityresolution.composite",
			UserAgent: auditDataFromContext.UserAgent,
			RequestIP: auditDataFromContext.RequestIP,
		},
		RequestID: auditDataFromContext.RequestID,
		Timestamp: time.Now().Format(time.RFC3339),
	}, nil
}

// EntitlementWithheld records a withholding in the request's audit
// transaction. Entity resolution also runs outside a request (startup checks,
// tests), where there is no transaction to record into; it then does nothing.
func (a *Logger) EntitlementWithheld(ctx context.Context, p EntitlementWithheldEventParams) {
	if !HasTransaction(ctx) {
		return
	}
	event, err := CreateEntitlementWithheldEvent(ctx, p)
	if err != nil {
		a.logger.ErrorContext(ctx, "error creating entitlement withheld audit event")
		return
	}
	LogAuditEvent(ctx, VerbDecision, event)
}
