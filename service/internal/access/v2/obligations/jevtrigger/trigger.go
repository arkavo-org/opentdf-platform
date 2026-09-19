// Package jevtrigger implements a dynamic obligation trigger backed by a
// TypeSafe Jev decision model.
//
// The trigger can require additional obligations — a watermark, a step-up
// authentication, an enhanced audit record — on a request that policy alone
// would not have obligated. It can only add. An obligation the policy graph
// already required is never withdrawn here, and no answer can turn a denial
// into a permit, so the model can tighten a decision but never loosen one.
package jevtrigger

import (
	"context"
	"errors"
	"fmt"
	"log/slog"

	"github.com/opentdf/platform/service/internal/access/v2/obligations"
	"github.com/opentdf/platform/service/internal/jev"
	"github.com/opentdf/platform/service/logger"
)

// seamName labels this seam in observations.
const seamName = "obligations"

// State keys sent to the model. Operators allowlist these by name, so they are
// part of the configuration contract.
const (
	StateKeyAction             = "action"
	StateKeyAttributeValueFQNs = "attribute_value_fqns"
	StateKeyPEPClientID        = "pep_client_id"
	StateKeyPolicyTriggered    = "policy_triggered_obligations"
)

// Rule binds one answer to one obligation that the answer may require.
//
// Exactly one of the When fields applies, selected by the question's type. A
// rule whose condition is not met requires nothing.
type Rule struct {
	// Question names the entry in the catalog this rule reads.
	Question string `mapstructure:"question"`
	// Obligation is the obligation value FQN to require.
	Obligation string `mapstructure:"obligation"`

	// WhenFalse inverts a boolean rule, requiring the obligation when the
	// answer is false rather than true.
	WhenFalse bool `mapstructure:"when_false"`
	// WhenChoice lists the choices that require the obligation.
	WhenChoice []string `mapstructure:"when_choice"`
	// WhenScoreAtOrAbove requires the obligation at or above this score.
	WhenScoreAtOrAbove *float64 `mapstructure:"when_score_at_or_above"`
}

// Config configures the trigger.
type Config struct {
	Client    jev.Config              `mapstructure:",squash"`
	Questions map[string]jev.Question `mapstructure:"questions"`
	Rules     []Rule                  `mapstructure:"rules"`
}

// Trigger consults a Jev model for obligations policy did not trigger.
type Trigger struct {
	client jev.Client
	logger *logger.Logger
	config Config
}

// Ensure Trigger satisfies the obligations hook.
var _ obligations.DynamicTrigger = (*Trigger)(nil)

// ErrNoRules reports a trigger with a question catalog but nothing to do with
// the answers.
var ErrNoRules = errors.New("jevtrigger: at least one rule must be configured")

// New builds a Trigger. It returns a nil Trigger, and no error, when the seam
// is disabled, so callers can install the result unconditionally.
func New(cfg Config, log *logger.Logger) (*Trigger, error) {
	if !cfg.Client.Enabled || !cfg.Client.Seams.Obligations.Enabled {
		return nil, nil //nolint:nilnil // a disabled seam installs no trigger
	}
	if len(cfg.Rules) == 0 {
		return nil, ErrNoRules
	}
	for _, rule := range cfg.Rules {
		if rule.Obligation == "" {
			return nil, fmt.Errorf("jevtrigger: rule for question %q has no obligation", rule.Question)
		}
		if _, ok := cfg.Questions[rule.Question]; !ok {
			return nil, fmt.Errorf("jevtrigger: rule references unknown question %q", rule.Question)
		}
	}

	client, err := jev.New(&cfg.Client, nil)
	if err != nil {
		return nil, fmt.Errorf("jevtrigger: %w", err)
	}

	return &Trigger{client: client, logger: log, config: cfg}, nil
}

// AdditionalObligations implements obligations.DynamicTrigger.
//
// In shadow mode the model is consulted and the result recorded, but nothing
// is returned, so the decision is unchanged. An unreachable model returns no
// obligations under fail_mode: open, and an error under fail_mode: closed.
func (t *Trigger) AdditionalObligations(ctx context.Context, req obligations.TriggerRequest) ([]string, error) {
	if t == nil {
		return nil, nil
	}

	state := jev.RedactState(map[string]any{
		StateKeyAction:             req.ActionName,
		StateKeyAttributeValueFQNs: req.AttributeValueFQNs,
		StateKeyPEPClientID:        req.PEPClientID,
		StateKeyPolicyTriggered:    req.PolicyTriggered,
	}, t.config.Client.StateAllowlist)

	resp, err := t.client.Decide(ctx, state, t.config.Questions)
	if err != nil {
		return t.handleDecideError(ctx, err)
	}

	enforcing := t.config.Client.Seams.Obligations.Enforcing()
	required := make([]string, 0, len(t.config.Rules))

	for _, rule := range t.config.Rules {
		met, obs := t.evaluate(resp, rule)
		obs.Applied = met && enforcing
		if obs.Applied {
			obs.Effect = "required_obligation:" + rule.Obligation
		}
		jev.Observe(ctx, obs)

		if met && enforcing {
			required = append(required, rule.Obligation)
		}
	}

	if !enforcing {
		return nil, nil
	}
	return required, nil
}

// evaluate reports whether a rule's condition is met, and describes the answer
// it read for the audit trail.
func (t *Trigger) evaluate(resp *jev.Response, rule Rule) (bool, jev.Observation) {
	threshold := t.config.Client.ConfidenceThreshold
	obs := jev.Observation{
		Seam:       seamName,
		Mode:       t.config.Client.Seams.Obligations.Mode,
		Model:      resp.Model,
		ResponseID: resp.ID,
		Question:   rule.Question,
		Threshold:  threshold,
		Cost:       resp.Usage.Cost,
	}
	if answer, ok := resp.Answers[rule.Question]; ok {
		obs.AnswerType = answer.Type
		obs.Certainty = answer.Certainty()
	}

	switch obs.AnswerType {
	case jev.QuestionTypeNoul:
		value, ok := resp.Noul(rule.Question, threshold)
		if !ok {
			return false, obs
		}
		obs.Answer = value
		return value != rule.WhenFalse, obs

	case jev.QuestionTypeChoice:
		value, ok := resp.Choice(rule.Question, threshold)
		if !ok {
			return false, obs
		}
		obs.Answer = value
		for _, want := range rule.WhenChoice {
			if value == want {
				return true, obs
			}
		}
		return false, obs

	case jev.QuestionTypeScore:
		value, ok := resp.Score(rule.Question, threshold)
		if !ok {
			return false, obs
		}
		obs.Answer = value
		return rule.WhenScoreAtOrAbove != nil && value >= *rule.WhenScoreAtOrAbove, obs

	default:
		return false, obs
	}
}

func (t *Trigger) handleDecideError(ctx context.Context, err error) ([]string, error) {
	jev.Observe(ctx, jev.Observation{
		Seam:    seamName,
		Mode:    t.config.Client.Seams.Obligations.Mode,
		Applied: false,
		Error:   err.Error(),
	})

	// fail_mode applies only where the seam has authority. A shadow-mode seam
	// must never fail a decision it is not allowed to influence, so an
	// unreachable model in shadow mode is recorded and otherwise ignored.
	if t.config.Client.Seams.Obligations.Enforcing() && t.config.Client.FailMode == jev.FailClosed {
		return nil, fmt.Errorf("jevtrigger: model unavailable and fail_mode is closed: %w", err)
	}

	// Failing open loses only an obligation policy never required.
	t.logger.WarnContext(ctx, "jev obligation trigger unavailable; proceeding on policy alone",
		slog.String("error", err.Error()))
	return nil, nil
}
