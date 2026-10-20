package jev

import (
	"errors"
	"fmt"
	"math"
	"strconv"
)

// noulMidpoint is the decision boundary for a boolean answer: the reported
// value is the probability the proposition is true, so 0.5 carries no
// information either way.
const noulMidpoint = 0.5

// Answer is a single typed answer. Exactly one of Noul, Choice, or Score is
// meaningful, selected by Type.
type Answer struct {
	Type QuestionType `json:"type"`

	// Noul is the probability that a QuestionTypeNoul proposition is true.
	Noul float64 `json:"noul,omitempty"`
	// Choice is the selected option for a QuestionTypeChoice question.
	Choice string `json:"choice,omitempty"`
	// Score is the position on the scale for a QuestionTypeScore question.
	Score float64 `json:"score,omitempty"`

	// Confidence is reported directly for choice and score answers. For noul
	// answers the API reports no separate confidence; use Answer.Certainty.
	Confidence    float64            `json:"confidence,omitempty"`
	Probabilities map[string]float64 `json:"probabilities,omitempty"`
	Legend        map[string]any     `json:"legend,omitempty"`
}

// Usage reports what the call cost.
type Usage struct {
	Cost         float64 `json:"cost,omitempty"`
	InputTokens  int     `json:"input_tokens"`
	OutputTokens int     `json:"output_tokens"`
}

// Response is a decoded Decisions API response.
type Response struct {
	ID       string            `json:"id"`
	Model    string            `json:"model"`
	Provider string            `json:"provider"`
	Answers  map[string]Answer `json:"answers"`
	Usage    Usage             `json:"usage"`
}

// ValidateAgainst verifies that the remote response inhabits the exact answer
// domain described by the submitted questions. Typed model outputs remove the
// need to parse prose, but the HTTP response is still untrusted input.
func (r *Response) ValidateAgainst(questions map[string]Question) error {
	if r == nil {
		return errors.New("jev: nil decision response")
	}
	for name, question := range questions {
		answer, ok := r.Answers[name]
		if !ok {
			return fmt.Errorf("jev: response missing answer for question %q", name)
		}
		if answer.Type != question.Type {
			return fmt.Errorf("jev: answer %q has type %q, want %q", name, answer.Type, question.Type)
		}
		if err := validateAnswerAgainst(answer, question); err != nil {
			return fmt.Errorf("jev: invalid answer %q: %w", name, err)
		}
	}
	return nil
}

func validateAnswerAgainst(a Answer, question Question) error {
	switch question.Type {
	case QuestionTypeNoul:
		if !inUnitInterval(a.Noul) {
			return fmt.Errorf("noul probability %v outside [0,1]", a.Noul)
		}

	case QuestionTypeChoice:
		if !inUnitInterval(a.Confidence) {
			return fmt.Errorf("confidence %v outside [0,1]", a.Confidence)
		}
		options, ok := question.Criteria.(map[string]any)
		if !ok || len(options) == 0 {
			return errors.New("choice question has no option map")
		}
		if _, exists := options[a.Choice]; !exists {
			return fmt.Errorf("choice %q is outside the configured option set", a.Choice)
		}
		if err := validateProbabilities(a.Probabilities, options); err != nil {
			return err
		}

	case QuestionTypeScore:
		if !inUnitInterval(a.Confidence) {
			return fmt.Errorf("confidence %v outside [0,1]", a.Confidence)
		}
		levels, ok := question.Criteria.([]any)
		if !ok || len(levels) == 0 {
			return errors.New("score question has no levels")
		}
		if math.IsNaN(a.Score) || math.IsInf(a.Score, 0) || a.Score < 0 || a.Score > float64(len(levels)-1) {
			return fmt.Errorf("score %v outside configured range [0,%d]", a.Score, len(levels)-1)
		}
		for option, probability := range a.Probabilities {
			level, err := strconv.Atoi(option)
			if err != nil || level < 0 || level >= len(levels) {
				return fmt.Errorf("probability names unknown score level %q", option)
			}
			if !inUnitInterval(probability) {
				return fmt.Errorf("probability for score level %q is outside [0,1]", option)
			}
		}

	default:
		return fmt.Errorf("unsupported question type %q", question.Type)
	}
	return nil
}

func validateProbabilities(probabilities map[string]float64, options map[string]any) error {
	for option, probability := range probabilities {
		if _, ok := options[option]; !ok {
			return fmt.Errorf("probability names unknown choice %q", option)
		}
		if !inUnitInterval(probability) {
			return fmt.Errorf("probability for choice %q is outside [0,1]", option)
		}
	}
	return nil
}

func inUnitInterval(value float64) bool {
	return !math.IsNaN(value) && !math.IsInf(value, 0) && value >= 0 && value <= 1
}

// Certainty normalizes how sure the model is, in [0,1], across answer types.
//
// A noul answer reports only the probability of true, so certainty is the
// distance from the midpoint: 0.96 and 0.04 are both highly certain answers,
// while 0.5 is maximally uncertain. Choice and score answers carry an explicit
// confidence.
func (a Answer) Certainty() float64 {
	if a.Type == QuestionTypeNoul {
		if a.Noul < noulMidpoint {
			return 1 - a.Noul
		}
		return a.Noul
	}
	return a.Confidence
}

// Noul reports a boolean answer only when the model is certain enough.
//
// ok is false when the question is absent, answered with a different type, or
// answered below threshold. Callers must treat !ok as "no answer" rather than
// as false, so that an uncertain model never silently decides anything.
func (r *Response) Noul(name string, threshold float64) (bool, bool) {
	a, found := r.answer(name, QuestionTypeNoul, threshold)
	if !found {
		return false, false
	}
	return a.Noul >= noulMidpoint, true
}

// Choice reports a selected option only when the model is certain enough.
func (r *Response) Choice(name string, threshold float64) (string, bool) {
	a, found := r.answer(name, QuestionTypeChoice, threshold)
	if !found {
		return "", false
	}
	return a.Choice, true
}

// Score reports a scale position only when the model is certain enough.
func (r *Response) Score(name string, threshold float64) (float64, bool) {
	a, found := r.answer(name, QuestionTypeScore, threshold)
	if !found {
		return 0, false
	}
	return a.Score, true
}

func (r *Response) answer(name string, want QuestionType, threshold float64) (Answer, bool) {
	if r == nil {
		return Answer{}, false
	}
	a, found := r.Answers[name]
	if !found || a.Type != want || a.Certainty() < threshold {
		return Answer{}, false
	}
	return a, true
}
