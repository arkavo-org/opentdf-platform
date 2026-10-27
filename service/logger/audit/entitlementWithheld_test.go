package audit

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

var withheldParams = EntitlementWithheldEventParams{
	Constraint:   "publishing_status",
	Subject:      "arkavo:abc",
	Reason:       "suspended by moderation",
	Since:        "2026-10-01T00:00:00Z",
	ReportID:     "r1",
	WithheldFQNs: []string{"https://patreon.arkavo.com/attr/arkavo-creator/value/publish"},
}

func TestEntitlementWithheldEvent_Shape(t *testing.T) {
	ctx := createTestContext(t)
	event, err := CreateEntitlementWithheldEvent(ctx, withheldParams)
	require.NoError(t, err)
	validateRecentEventTimestamp(t, event)

	assert.Equal(t, "arkavo:abc-publishing_status", event.Object.ID)
	assert.Equal(t, ObjectTypeEntityObject, event.Object.Type)
	assert.Equal(t, "entitlementWithheld-publishing_status", event.Object.Name)
	assert.Equal(t, ActionTypeRead, event.Action.Type)
	assert.Equal(t, ActionResultFailure, event.Action.Result)
	assert.Equal(t, "arkavo:abc", event.Actor.ID)
	assert.Equal(t, auditEventMetadata{
		"constraint":    "publishing_status",
		"reason":        "suspended by moderation",
		"since":         "2026-10-01T00:00:00Z",
		"report_id":     "r1",
		"withheld_fqns": withheldParams.WithheldFQNs,
	}, event.EventMetaData)
	assert.NotContains(t, event.EventMetaData, "cause")
	assert.Equal(t, "entityresolution.composite", event.ClientInfo.Platform)
	assert.Equal(t, TestUserAgent, event.ClientInfo.UserAgent)
	assert.Equal(t, TestRequestIP.String(), event.ClientInfo.RequestIP)
	assert.Equal(t, TestRequestID, event.RequestID)
}

func TestEntitlementWithheld_NoTransactionNoPanic(t *testing.T) {
	l, buf := createTestLogger()
	assert.False(t, HasTransaction(t.Context()))
	assert.NotPanics(t, func() { l.EntitlementWithheld(t.Context(), withheldParams) })
	assert.Empty(t, buf.String())
}

func TestEntitlementWithheld_EmittedOnClose(t *testing.T) {
	l, buf := createTestLogger()
	ctx := createTestContext(t)
	assert.True(t, HasTransaction(ctx))
	tx, ok := ctx.Value(contextKey{}).(*auditTransaction)
	require.True(t, ok)

	l.EntitlementWithheld(ctx, withheldParams)
	assert.Empty(t, buf.String(), "events are emitted on close")
	tx.logClose(ctx, l.logger, true, nil)

	entry, _ := extractLogEntry(t, buf)
	assert.Equal(t, LevelAuditStr, entry.Level)
	assert.Equal(t, string(VerbDecision), entry.Msg)
	var event struct {
		EventMetaData map[string]any `json:"eventMetaData"`
	}
	require.NoError(t, json.Unmarshal(entry.Audit, &event))
	assert.Equal(t, "r1", event.EventMetaData["report_id"])
	assert.Equal(t, []any{withheldParams.WithheldFQNs[0]}, event.EventMetaData["withheld_fqns"])
	assert.Equal(t, 1, countLines(buf.String()))
}

func countLines(s string) int {
	n := 0
	for _, c := range s {
		if c == '\n' {
			n++
		}
	}
	return n
}
