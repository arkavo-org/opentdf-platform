package jev

import (
	"context"
	"fmt"

	"github.com/opentdf/platform/service/entityresolution/multi-strategy/types"
	jevclient "github.com/opentdf/platform/service/internal/jev"
)

// Provider resolves derived claims by asking a Jev model about entity context.
type Provider struct {
	client jevclient.Client
	mapper types.Mapper
	name   string
	config Config
}

// Ensure Provider satisfies the framework interface.
var _ types.Provider = (*Provider)(nil)

// NewProvider creates a Jev entity resolution provider. A provider whose
// client is disabled is still constructed; it resolves to no claims, which
// keeps configuration reversible without removing strategies.
func NewProvider(name string, config Config) (*Provider, error) {
	if err := config.Validate(); err != nil {
		return nil, err
	}

	client, err := jevclient.New(&config.Client, nil)
	if err != nil {
		return nil, fmt.Errorf("jev provider %q: %w", name, err)
	}

	return &Provider{
		client: client,
		mapper: NewMapper(),
		name:   name,
		config: config,
	}, nil
}

// Name returns the provider instance name.
func (p *Provider) Name() string { return p.name }

// Type returns the provider type.
func (p *Provider) Type() string { return ProviderType }

// ResolveEntity poses the configured questions about the parameters that the
// strategy's input_mapping extracted, and returns the confident answers as raw
// data for output mapping.
//
// Two independent operator-controlled gates govern what leaves the platform:
// input_mapping chooses which JWT claims become parameters at all, and the
// client's state_allowlist filters those parameters again by name.
//
// In shadow mode the model is still consulted and the call is still recorded,
// but no answers are returned, so no claim can reach a subject mapping.
func (p *Provider) ResolveEntity(ctx context.Context, strategy types.MappingStrategy, params map[string]any) (*types.RawResult, error) {
	result := &types.RawResult{
		Data: make(map[string]any),
		Metadata: map[string]any{
			"provider_type": ProviderType,
			"provider_name": p.name,
			"strategy":      strategy.Name,
			"mode":          string(p.config.Client.Seams.ERSClaims.Mode),
		},
	}

	seam := p.config.Client.Seams.ERSClaims
	if !p.config.Client.Enabled || !seam.Enabled {
		result.Metadata["consulted"] = false
		return result, nil
	}

	state := jevclient.RedactState(params, p.config.Client.StateAllowlist)
	if withheld := jevclient.RedactedKeys(params, p.config.Client.StateAllowlist); len(withheld) > 0 {
		result.Metadata["withheld_parameters"] = toAnySlice(withheld)
	}

	resp, err := p.client.Decide(ctx, state, p.config.Questions)
	if err != nil {
		return p.handleDecideError(result, err)
	}

	result.Metadata["consulted"] = true
	result.Metadata["response_id"] = resp.ID
	result.Metadata["model"] = resp.Model
	result.Metadata["cost"] = resp.Usage.Cost

	answers, certainties := p.confidentAnswers(resp)
	result.Metadata["certainties"] = certainties

	// Shadow mode observes without deriving claims.
	if !seam.Enforcing() {
		result.Metadata["applied"] = false
		return result, nil
	}

	result.Data = answers
	result.Metadata["applied"] = len(answers) > 0
	return result, nil
}

// HealthCheck reports healthy whenever the provider is not expected to call
// out. It deliberately does not probe the model: a health check that spends
// credits on every interval is worse than no health check.
func (p *Provider) HealthCheck(_ context.Context) error { return nil }

// GetMapper returns the provider's mapper implementation.
func (p *Provider) GetMapper() types.Mapper { return p.mapper }

// Close releases resources; the HTTP client needs none.
func (p *Provider) Close() error { return nil }

// confidentAnswers converts answers that clear the threshold into plain Go
// values, and reports the certainty of every answer for observability.
//
// Metadata eventually passes through structpb.NewStruct on its way into the
// entity representation, and structpb rejects concrete types like
// map[string]float64. Returning map[string]any keeps that conversion working;
// getting it wrong makes the whole entity be dropped, not merely unobserved.
func (p *Provider) confidentAnswers(resp *jevclient.Response) (map[string]any, map[string]any) {
	threshold := p.config.Client.ConfidenceThreshold
	answers := make(map[string]any, len(resp.Answers))
	certainties := make(map[string]any, len(resp.Answers))

	for name, answer := range resp.Answers {
		certainties[name] = answer.Certainty()

		switch answer.Type {
		case jevclient.QuestionTypeNoul:
			if v, ok := resp.Noul(name, threshold); ok {
				answers[name] = v
			}
		case jevclient.QuestionTypeChoice:
			if v, ok := resp.Choice(name, threshold); ok {
				answers[name] = v
			}
		case jevclient.QuestionTypeScore:
			if v, ok := resp.Score(name, threshold); ok {
				answers[name] = v
			}
		}
	}
	return answers, certainties
}

// handleDecideError applies fail mode, which only bites in enforce mode.
// Failing open yields no claims, which
// can only withhold entitlements a subject mapping would have granted; failing
// closed surfaces the error and aborts resolution.
func (p *Provider) handleDecideError(result *types.RawResult, err error) (*types.RawResult, error) {
	result.Metadata["consulted"] = false
	result.Metadata["applied"] = false
	result.Metadata["error"] = err.Error()

	// fail_mode applies only where the seam has authority; a shadow-mode seam
	// must never fail a resolution it is not allowed to influence.
	if p.config.Client.Seams.ERSClaims.Enforcing() && p.config.Client.FailMode == jevclient.FailClosed {
		return nil, types.NewProviderError("jev model unavailable and fail_mode is closed", map[string]any{
			"provider": p.name,
			"error":    err.Error(),
		})
	}
	return result, nil
}

// toAnySlice converts a string slice into the []any form structpb accepts.
func toAnySlice(values []string) []any {
	out := make([]any, len(values))
	for i, v := range values {
		out[i] = v
	}
	return out
}
