// Package jev provides a client for TypeSafe Jev "System One" decision models,
// reached over OpenRouter's Decisions API, along with the plumbing OpenTDF needs
// to consume probabilistic answers safely inside deterministic ABAC flows.
//
// Restrict-only consumers preserve the central safety property by independently
// enforcing that final permits are a subset of policy permits. The ERS consumer
// has a different threat model: its derived claims remain subject to ordinary
// subject mapping but may influence grants.
package jev

import (
	"errors"
	"fmt"
)

// QuestionType enumerates the answer shapes Jev supports. The type of the
// question fixes the type of the answer. The client still validates the remote
// representation at the HTTP trust boundary.
type QuestionType string

const (
	// QuestionTypeNoul is a boolean question. The answer is the probability
	// that the proposition is true.
	QuestionTypeNoul QuestionType = "noul"
	// QuestionTypeChoice selects one option from a named set.
	QuestionTypeChoice QuestionType = "choice"
	// QuestionTypeScore places the state on an ordered scale.
	QuestionTypeScore QuestionType = "score"
)

// Question is a single typed question posed to the model. Instructions and
// criteria accept a plain string or structured JSON, matching the Decisions API.
type Question struct {
	Type         QuestionType `json:"type"`
	Instructions any          `json:"instructions"`
	Criteria     any          `json:"criteria,omitempty"`
}

// NoulCriteria describes what distinguishes a true answer from a false one.
type NoulCriteria struct {
	True  any `json:"true"`
	False any `json:"false"`
}

// NewNoulQuestion builds a boolean question. Both criteria are required by the
// API whenever criteria are supplied, so callers give each explicitly.
func NewNoulQuestion(instructions, whenTrue, whenFalse any) Question {
	return Question{
		Type:         QuestionTypeNoul,
		Instructions: instructions,
		Criteria:     NoulCriteria{True: whenTrue, False: whenFalse},
	}
}

// NewChoiceQuestion builds a single-select question over named options.
func NewChoiceQuestion(instructions any, criteria map[string]any) Question {
	return Question{
		Type:         QuestionTypeChoice,
		Instructions: instructions,
		Criteria:     criteria,
	}
}

// NewScoreQuestion builds an ordered-scale question. Criteria are listed from
// lowest to highest and must be non-empty.
func NewScoreQuestion(instructions any, criteria []any) Question {
	return Question{
		Type:         QuestionTypeScore,
		Instructions: instructions,
		Criteria:     criteria,
	}
}

// Validate checks that a question defines the answer domain its type requires.
func (q Question) Validate() error {
	if q.Instructions == nil {
		return errors.New("missing instructions")
	}
	switch q.Type {
	case QuestionTypeNoul:
		return nil
	case QuestionTypeChoice:
		criteria, ok := q.Criteria.(map[string]any)
		if !ok || len(criteria) < 2 {
			return errors.New("choice criteria must define at least two options")
		}
	case QuestionTypeScore:
		criteria, ok := q.Criteria.([]any)
		if !ok || len(criteria) < 2 {
			return errors.New("score criteria must define at least two levels")
		}
	default:
		return fmt.Errorf("unsupported type %q", q.Type)
	}
	return nil
}
