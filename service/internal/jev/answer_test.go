package jev

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// apiExampleResponse is the example response published in OpenRouter's OpenAPI
// spec for POST /api/alpha/decisions. Decoding it here pins our structs to the
// real wire format.
const apiExampleResponse = `{
  "answers": {
    "is_bug": { "noul": 0.96, "type": "noul" },
    "team": {
      "choice": "payments",
      "confidence": 0.75,
      "probabilities": { "account": 0, "frontend": 0.16, "payments": 0.84 },
      "type": "choice"
    },
    "urgency": {
      "confidence": 0.99,
      "legend": { "0": "Can wait", "1": "This week", "2": "Blocking" },
      "probabilities": { "0": 0, "1": 0.01, "2": 0.99 },
      "score": 1.99,
      "type": "score"
    }
  },
  "id": "gen-dec-1789738314-X5e5eKGQdvR9rblyX250",
  "model": "typesafe/jev-1.13-20260917",
  "provider": "TypeSafe",
  "usage": { "cost": 1.9992e-05, "input_tokens": 476, "output_tokens": 70 }
}`

func decodeExample(t *testing.T) *Response {
	t.Helper()
	var r Response
	require.NoError(t, json.Unmarshal([]byte(apiExampleResponse), &r))
	return &r
}

func TestResponseDecodesAPIExample(t *testing.T) {
	r := decodeExample(t)

	assert.Equal(t, "gen-dec-1789738314-X5e5eKGQdvR9rblyX250", r.ID)
	assert.Equal(t, "typesafe/jev-1.13-20260917", r.Model)
	assert.Equal(t, 476, r.Usage.InputTokens)
	assert.InDelta(t, 1.9992e-05, r.Usage.Cost, 1e-12)

	assert.InDelta(t, 0.96, r.Answers["is_bug"].Noul, 1e-9)
	assert.Equal(t, "payments", r.Answers["team"].Choice)
	assert.InDelta(t, 1.99, r.Answers["urgency"].Score, 1e-9)
	assert.InDelta(t, 0.84, r.Answers["team"].Probabilities["payments"], 1e-9)
}

func TestCertaintyTreatsNoulAsDistanceFromMidpoint(t *testing.T) {
	// A noul answer reports P(true); both extremes are certain answers.
	assert.InDelta(t, 0.96, Answer{Type: QuestionTypeNoul, Noul: 0.96}.Certainty(), 1e-9)
	assert.InDelta(t, 0.96, Answer{Type: QuestionTypeNoul, Noul: 0.04}.Certainty(), 1e-9)
	assert.InDelta(t, 0.5, Answer{Type: QuestionTypeNoul, Noul: 0.5}.Certainty(), 1e-9)

	// Choice and score report confidence directly.
	assert.InDelta(t, 0.75, Answer{Type: QuestionTypeChoice, Confidence: 0.75}.Certainty(), 1e-9)
}

func TestAccessorsGateOnThreshold(t *testing.T) {
	r := decodeExample(t)

	value, ok := r.Noul("is_bug", 0.8)
	assert.True(t, ok)
	assert.True(t, value)

	// 0.96 certainty does not clear a 0.99 bar, so the answer is absent.
	_, ok = r.Noul("is_bug", 0.99)
	assert.False(t, ok, "answer below threshold must be reported absent")

	choice, ok := r.Choice("team", 0.7)
	assert.True(t, ok)
	assert.Equal(t, "payments", choice)

	_, ok = r.Choice("team", 0.8)
	assert.False(t, ok)
}

func TestAccessorsRejectTypeMismatchAndMissing(t *testing.T) {
	r := decodeExample(t)

	_, ok := r.Choice("is_bug", 0) // noul answer, asked as choice
	assert.False(t, ok, "type mismatch must not yield a value")

	_, ok = r.Noul("nonexistent", 0)
	assert.False(t, ok)

	// A low-probability noul is a confident "false", not an absent answer.
	low := &Response{Answers: map[string]Answer{
		"anomalous": {Type: QuestionTypeNoul, Noul: 0.02},
	}}
	value, ok := low.Noul("anomalous", 0.8)
	assert.True(t, ok, "a confident false is still an answer")
	assert.False(t, value)
}

func TestNilResponseIsSafe(t *testing.T) {
	var r *Response
	_, ok := r.Noul("anything", 0)
	assert.False(t, ok)
}

func TestValidateAgainstRejectsValuesOutsideQuestionDomain(t *testing.T) {
	choiceQuestion := NewChoiceQuestion("Risk?", map[string]any{
		"routine":  "ordinary",
		"elevated": "unusual",
	})

	tests := map[string]Answer{
		"unknown choice": {
			Type: QuestionTypeChoice, Choice: "administrator", Confidence: 0.99,
		},
		"invalid choice confidence": {
			Type: QuestionTypeChoice, Choice: "routine", Confidence: 1.1,
		},
		"invalid choice probability": {
			Type: QuestionTypeChoice, Choice: "routine", Confidence: 0.9,
			Probabilities: map[string]float64{"routine": -0.1},
		},
	}
	for name, answer := range tests {
		t.Run(name, func(t *testing.T) {
			response := &Response{Answers: map[string]Answer{"risk": answer}}
			require.Error(t, response.ValidateAgainst(map[string]Question{"risk": choiceQuestion}))
		})
	}

	t.Run("noul outside probability range", func(t *testing.T) {
		response := &Response{Answers: map[string]Answer{
			"risk": {Type: QuestionTypeNoul, Noul: -0.2},
		}}
		require.Error(t, response.ValidateAgainst(map[string]Question{
			"risk": NewNoulQuestion("Risk?", "yes", "no"),
		}))
	})

	t.Run("score outside configured scale", func(t *testing.T) {
		response := &Response{Answers: map[string]Answer{
			"risk": {Type: QuestionTypeScore, Score: 3, Confidence: 0.9},
		}}
		require.Error(t, response.ValidateAgainst(map[string]Question{
			"risk": NewScoreQuestion("Risk?", []any{"low", "high"}),
		}))
	})

	t.Run("type mismatch", func(t *testing.T) {
		response := &Response{Answers: map[string]Answer{
			"risk": {Type: QuestionTypeNoul, Noul: 0.9},
		}}
		require.Error(t, response.ValidateAgainst(map[string]Question{"risk": choiceQuestion}))
	})
}
