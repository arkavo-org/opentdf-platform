package jev

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
