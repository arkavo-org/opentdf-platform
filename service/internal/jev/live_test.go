//go:build jevlive

// Package jev live tests exercise the real TypeSafe Jev model through
// OpenRouter. They are excluded from ordinary builds by the jevlive build tag,
// because `make test` runs `go test ./...` and these tests cost money and need
// network access.
//
// Run them deliberately:
//
//	set -a; . ./.env; set +a
//	cd service && go test -tags jevlive -v ./internal/jev/...
//
// They assert the contract we depend on rather than the model's judgement:
// that the wire format matches our structs, that each question type returns
// the answer type we expect, and that certainty is calibrated well enough for
// confidence gating to mean something. One test does check direction of
// judgement, because a seam whose model cannot tell a bulk 3am pull from a
// single routine read would be worthless.
package jev

import (
	"context"
	"os"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func liveClient(t *testing.T) Client {
	t.Helper()

	if os.Getenv(DefaultAPIKeyEnv) == "" {
		t.Skipf("%s not set; source .env to run live tests", DefaultAPIKeyEnv)
	}

	cfg := &Config{
		Enabled:             true,
		Timeout:             "30s",
		ConfidenceThreshold: DefaultConfidenceThreshold,
		StateAllowlist: []string{
			"action", "attribute_value_fqns", "resource_count",
			"time_of_day", "entity_role", "recent_request_count",
		},
	}
	client, err := New(cfg, nil)
	require.NoError(t, err)
	return client
}

// routineRequest is an unremarkable single-document read during work hours.
func routineRequest() map[string]any {
	return map[string]any{
		"action":               "read",
		"attribute_value_fqns": []any{"https://example.org/attr/classification/value/confidential"},
		"resource_count":       1,
		"time_of_day":          "14:05 local, Tuesday",
		"entity_role":          "analyst, 4 years tenure, reads this classification daily",
		"recent_request_count": 12,
	}
}

// bulkRequest is the shape the restrictor seam exists to catch: everything
// passes policy individually, but the request as a whole looks like staging
// for exfiltration.
func bulkRequest() map[string]any {
	return map[string]any{
		"action": "read",
		"attribute_value_fqns": []any{
			"https://example.org/attr/classification/value/secret",
			"https://example.org/attr/classification/value/confidential",
		},
		"resource_count":       4812,
		"time_of_day":          "03:14 local, Sunday",
		"entity_role":          "analyst, 4 years tenure, resigned effective Friday",
		"recent_request_count": 4812,
	}
}

func accessQuestions() map[string]Question {
	return map[string]Question{
		"is_exfiltration": NewNoulQuestion(
			"Does this access request look like bulk data exfiltration rather than ordinary work?",
			"The volume, timing, or breadth is inconsistent with how this role normally works.",
			"The request is consistent with ordinary day-to-day use.",
		),
		"risk_tier": NewChoiceQuestion(
			"How much scrutiny does this access request warrant?",
			map[string]any{
				"routine":  "Consistent with the entity's normal pattern of work.",
				"elevated": "Unusual in volume, timing, or breadth, but plausibly legitimate.",
				"critical": "Strongly resembles data staging or exfiltration.",
			},
		),
		"scrutiny": NewScoreQuestion(
			"How much additional verification should be required before granting this request?",
			[]any{
				"None; grant as normal.",
				"Log for later review.",
				"Require step-up authentication.",
				"Deny and alert a human.",
			},
		),
	}
}

// TestLiveWireFormatMatchesOurStructs is the test that most justifies running
// against the real service: it proves the types we decode into still match
// what the provider actually sends.
func TestLiveWireFormatMatchesOurStructs(t *testing.T) {
	client := liveClient(t)

	start := time.Now()
	resp, err := client.Decide(context.Background(), bulkRequest(), accessQuestions())
	elapsed := time.Since(start)
	require.NoError(t, err)

	t.Logf("latency=%s model=%s id=%s cost=$%.8f tokens=%d/%d",
		elapsed.Round(time.Millisecond), resp.Model, resp.ID,
		resp.Usage.Cost, resp.Usage.InputTokens, resp.Usage.OutputTokens)

	assert.NotEmpty(t, resp.ID)
	assert.Contains(t, resp.Model, "jev", "the pinned model should answer")
	assert.Positive(t, resp.Usage.InputTokens)

	require.Len(t, resp.Answers, 3, "every question must be answered")

	noul := resp.Answers["is_exfiltration"]
	assert.Equal(t, QuestionTypeNoul, noul.Type)
	assert.GreaterOrEqual(t, noul.Noul, 0.0)
	assert.LessOrEqual(t, noul.Noul, 1.0)

	choice := resp.Answers["risk_tier"]
	assert.Equal(t, QuestionTypeChoice, choice.Type)
	assert.Contains(t, []string{"routine", "elevated", "critical"}, choice.Choice,
		"the model must answer with one of the options it was given")
	assert.NotEmpty(t, choice.Probabilities, "choice answers carry a distribution")

	score := resp.Answers["scrutiny"]
	assert.Equal(t, QuestionTypeScore, score.Type)
	assert.GreaterOrEqual(t, score.Score, 0.0)
	assert.LessOrEqual(t, score.Score, 3.0, "score must stay within the scale it was given")

	for name, answer := range resp.Answers {
		c := answer.Certainty()
		assert.GreaterOrEqual(t, c, 0.0, "certainty for %s", name)
		assert.LessOrEqual(t, c, 1.0, "certainty for %s", name)
		t.Logf("  %-16s type=%-6s certainty=%.3f", name, answer.Type, c)
	}
}

// TestLiveModelDistinguishesBulkFromRoutine checks the one behavioural property
// the seams depend on. If the model rated a 4812-resource 3am pull the same as
// a single routine read, the restrictor seam would have no signal to act on.
func TestLiveModelDistinguishesBulkFromRoutine(t *testing.T) {
	client := liveClient(t)
	ctx := context.Background()
	questions := accessQuestions()

	routine, err := client.Decide(ctx, routineRequest(), questions)
	require.NoError(t, err)

	bulk, err := client.Decide(ctx, bulkRequest(), questions)
	require.NoError(t, err)

	routineNoul := routine.Answers["is_exfiltration"].Noul
	bulkNoul := bulk.Answers["is_exfiltration"].Noul

	t.Logf("P(exfiltration): routine=%.3f bulk=%.3f", routineNoul, bulkNoul)
	t.Logf("risk_tier:       routine=%-8s bulk=%s",
		routine.Answers["risk_tier"].Choice, bulk.Answers["risk_tier"].Choice)
	t.Logf("scrutiny:        routine=%.2f    bulk=%.2f",
		routine.Answers["scrutiny"].Score, bulk.Answers["scrutiny"].Score)

	assert.Greater(t, bulkNoul, routineNoul,
		"the bulk 3am request must read as more exfiltration-like than a routine read")
	assert.Greater(t, bulk.Answers["scrutiny"].Score, routine.Answers["scrutiny"].Score,
		"the bulk request must warrant more scrutiny")
	assert.Equal(t, "routine", routine.Answers["risk_tier"].Choice,
		"an ordinary read must not be rated as needing scrutiny")
}

// TestLiveConfidenceGatingIsMeaningful checks that certainty is calibrated
// enough for the threshold to be a real control: a clear-cut case should clear
// a high bar, and an impossible bar should admit nothing.
func TestLiveConfidenceGatingIsMeaningful(t *testing.T) {
	client := liveClient(t)

	resp, err := client.Decide(context.Background(), bulkRequest(), accessQuestions())
	require.NoError(t, err)

	value, ok := resp.Noul("is_exfiltration", 0.8)
	t.Logf("at threshold 0.80: value=%v admitted=%v (certainty=%.3f)",
		value, ok, resp.Answers["is_exfiltration"].Certainty())
	assert.True(t, ok, "a blatant case should clear a 0.8 bar")
	assert.True(t, value, "and should read as exfiltration")

	_, ok = resp.Noul("is_exfiltration", 1.01)
	assert.False(t, ok, "an unreachable threshold must admit nothing")

	_, ok = resp.Choice("is_exfiltration", 0)
	assert.False(t, ok, "asking a noul question as a choice must yield nothing")
}

// TestLiveRedactionPreventsEgress confirms end to end that an unlisted key
// never reaches the provider: the model cannot report a field it never saw.
func TestLiveRedactionPreventsEgress(t *testing.T) {
	client := liveClient(t)

	state := bulkRequest()
	state["employee_ssn"] = "123-45-6789"
	state["employee_email"] = "someone@example.org"

	allowlist := []string{"action", "resource_count", "time_of_day"}
	redacted := RedactState(state, allowlist)

	require.NotContains(t, redacted, "employee_ssn")
	require.NotContains(t, redacted, "employee_email")
	assert.ElementsMatch(t, []string{"attribute_value_fqns", "employee_email", "employee_ssn",
		"entity_role", "recent_request_count"}, RedactedKeys(state, allowlist))

	resp, err := client.Decide(context.Background(), redacted, map[string]Question{
		"saw_identifiers": NewNoulQuestion(
			"Does the state you were given contain any personal identifiers such as a social security number or an email address?",
			"It contains at least one personal identifier.",
			"It contains no personal identifiers.",
		),
	})
	require.NoError(t, err)

	sawIdentifiers, ok := resp.Noul("saw_identifiers", 0.7)
	t.Logf("model reports personal identifiers present: value=%v admitted=%v (certainty=%.3f)",
		sawIdentifiers, ok, resp.Answers["saw_identifiers"].Certainty())

	if ok {
		assert.False(t, sawIdentifiers,
			"redaction failed: the model saw personal data that should never have left the platform")
	}
}
