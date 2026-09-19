// Package jevrestrictor implements a post-decision restrictor backed by a
// TypeSafe Jev decision model.
//
// It exists for the case policy cannot express: a request where every
// individual attribute check passes but the request as a whole looks wrong —
// a bulk pull at an odd hour, a pattern that does not match how this entity
// normally works. The model sees the shape of the whole request and may deny
// it.
//
// It may only deny. The access.DecisionRestrictor interface returns resources
// to deny and has no way to express "permit", so nothing here can grant access
// policy withheld, widen an entitlement, or resurrect a denied resource.
package jevrestrictor

import (
	"context"
	"errors"
	"fmt"
	"log/slog"

	access "github.com/opentdf/platform/service/internal/access/v2"
	"github.com/opentdf/platform/service/internal/jev"
	"github.com/opentdf/platform/service/logger"
)

// seamName labels this seam in observations.
const seamName = "restrictor"

// State keys sent to the model. Operators allowlist these by name, so they are
// part of the configuration contract.
const (
	StateKeyEntityID           = "entity_id"
	StateKeyAction             = "action"
	StateKeyResourceCount      = "resource_count"
	StateKeyAttributeValueFQNs = "attribute_value_fqns"
	StateKeyPermittedCount     = "permitted_count"
)

// Rule binds one answer to the decision to deny.
//
// A rule that fires denies every resource policy permitted in this decision.
// The seam is aimed at request-shaped anomalies rather than per-resource
// judgements, which also keeps it to a single model call per decision.
type Rule struct {
	Question string `mapstructure:"question"`
	// Reason is recorded in the audit trail and the platform logs.
	Reason string `mapstructure:"reason"`

	WhenFalse          bool     `mapstructure:"when_false"`
	WhenChoice         []string `mapstructure:"when_choice"`
	WhenScoreAtOrAbove *float64 `mapstructure:"when_score_at_or_above"`
}

// Config configures the restrictor.
type Config struct {
	Client    jev.Config              `mapstructure:",squash"`
	Questions map[string]jev.Question `mapstructure:"questions"`
	Rules     []Rule                  `mapstructure:"rules"`
}

// Restrictor denies decisions a model judges anomalous.
type Restrictor struct {
	client jev.Client
	logger *logger.Logger
	config Config
}

// Ensure Restrictor satisfies the decision hook.
var _ access.DecisionRestrictor = (*Restrictor)(nil)

// ErrNoRules reports a restrictor that could never deny anything.
var ErrNoRules = errors.New("jevrestrictor: at least one rule must be configured")

// New builds a Restrictor, or nil when the seam is disabled.
func New(cfg Config, log *logger.Logger) (*Restrictor, error) {
	if !cfg.Client.Enabled || !cfg.Client.Seams.Restrictor.Enabled {
		return nil, nil //nolint:nilnil // a disabled seam installs no restrictor
	}
	if len(cfg.Rules) == 0 {
		return nil, ErrNoRules
	}
	for _, rule := range cfg.Rules {
		if _, ok := cfg.Questions[rule.Question]; !ok {
			return nil, fmt.Errorf("jevrestrictor: rule references unknown question %q", rule.Question)
		}
	}

	client, err := jev.New(&cfg.Client, nil)
	if err != nil {
		return nil, fmt.Errorf("jevrestrictor: %w", err)
	}

	return &Restrictor{client: client, logger: log, config: cfg}, nil
}

// Deny implements access.DecisionRestrictor.
//
// In shadow mode the model is consulted and the result recorded, but no
// denials are returned, so the decision is unchanged.
func (r *Restrictor) Deny(ctx context.Context, req access.RestrictionRequest) (map[string]string, error) {
	// "No denials" is an empty map rather than a nil map: identical to callers,
	// and it keeps every success path returning a usable value.
	if r == nil {
		return noDenials(), nil
	}

	permitted := permittedResources(req)
	if len(permitted) == 0 {
		// Nothing left to deny; skip the call rather than spend on a decision
		// that cannot change.
		return noDenials(), nil
	}

	resp, err := r.client.Decide(ctx, r.state(req, permitted), r.config.Questions)
	if err != nil {
		return r.handleDecideError(ctx, err)
	}

	enforcing := r.config.Client.Seams.Restrictor.Enforcing()

	for _, rule := range r.config.Rules {
		met, obs := r.evaluate(resp, rule)
		obs.Applied = met && enforcing
		if obs.Applied {
			obs.Effect = "denied_decision:" + rule.Reason
		}
		jev.Observe(ctx, obs)

		if !met || !enforcing {
			continue
		}

		reason := rule.Reason
		if reason == "" {
			reason = "restricted by decision model"
		}
		denials := make(map[string]string, len(permitted))
		for _, id := range permitted {
			denials[id] = reason
		}
		return denials, nil
	}

	return noDenials(), nil
}

// state builds the request shape the model reasons about, redacted to the
// operator's allowlist.
func (r *Restrictor) state(req access.RestrictionRequest, permitted []string) map[string]any {
	fqnSet := make(map[string]struct{})
	fqns := make([]string, 0)
	for _, resource := range req.Resources {
		for _, fqn := range resource.AttributeValueFQNs {
			if _, seen := fqnSet[fqn]; seen {
				continue
			}
			fqnSet[fqn] = struct{}{}
			fqns = append(fqns, fqn)
		}
	}

	return jev.RedactState(map[string]any{
		StateKeyEntityID:           req.EntityID,
		StateKeyAction:             req.ActionName,
		StateKeyResourceCount:      len(req.Resources),
		StateKeyAttributeValueFQNs: fqns,
		StateKeyPermittedCount:     len(permitted),
	}, r.config.Client.StateAllowlist)
}

func (r *Restrictor) evaluate(resp *jev.Response, rule Rule) (bool, jev.Observation) {
	threshold := r.config.Client.ConfidenceThreshold
	obs := jev.Observation{
		Seam:       seamName,
		Mode:       r.config.Client.Seams.Restrictor.Mode,
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

func (r *Restrictor) handleDecideError(ctx context.Context, err error) (map[string]string, error) {
	jev.Observe(ctx, jev.Observation{
		Seam:    seamName,
		Mode:    r.config.Client.Seams.Restrictor.Mode,
		Applied: false,
		Error:   err.Error(),
	})

	// fail_mode applies only where the seam has authority; a shadow-mode seam
	// must never fail a decision it is not allowed to influence.
	if r.config.Client.Seams.Restrictor.Enforcing() && r.config.Client.FailMode == jev.FailClosed {
		return nil, fmt.Errorf("jevrestrictor: model unavailable and fail_mode is closed: %w", err)
	}

	r.logger.WarnContext(ctx, "jev decision restrictor unavailable; proceeding on policy alone",
		slog.String("error", err.Error()))
	return noDenials(), nil
}

// noDenials is the empty result: policy's decision stands unchanged.
func noDenials() map[string]string {
	return map[string]string{}
}

// permittedResources lists the resources still worth asking about.
func permittedResources(req access.RestrictionRequest) []string {
	ids := make([]string, 0, len(req.Resources))
	for _, resource := range req.Resources {
		if resource.Permitted {
			ids = append(ids, resource.EphemeralID)
		}
	}
	return ids
}
