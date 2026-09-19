// Package jev provides a client for TypeSafe Jev "System One" decision models,
// reached over OpenRouter's Decisions API, along with the plumbing OpenTDF needs
// to consume probabilistic answers safely inside deterministic ABAC flows.
//
// The central safety property: a Jev answer may never grant access that policy
// evaluation denies. Every consumer in this repository uses answers only to
// restrict a decision, to require an additional obligation, or to derive claims
// that are then subject to normal subject mapping.
package jev

// QuestionType enumerates the answer shapes Jev supports. The type of the
// question fixes the type of the answer, which is what makes the exchange
// type-safe without schema validation on our side.
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
