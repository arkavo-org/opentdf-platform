package jev

import (
	"errors"
	"fmt"
	"strings"

	"github.com/opentdf/platform/service/entityresolution/multi-strategy/transformation"
	"github.com/opentdf/platform/service/entityresolution/multi-strategy/types"
)

// Mapper maps JWT claims into model parameters and model answers into claims.
type Mapper struct{}

// Ensure Mapper implements the framework interface.
var _ types.Mapper = (*Mapper)(nil)

// NewMapper creates a Jev mapper.
func NewMapper() *Mapper { return &Mapper{} }

// ExtractParameters selects the JWT claims the strategy names as inputs. This
// is the first of two gates on what may reach the model.
func (m *Mapper) ExtractParameters(jwtClaims types.JWTClaims, inputMapping []types.InputMapping) (map[string]any, error) {
	params := make(map[string]any, len(inputMapping))

	for _, mapping := range inputMapping {
		value, exists := jwtClaims[mapping.JWTClaim]
		if !exists {
			if mapping.Required {
				return nil, fmt.Errorf("required JWT claim %q not found", mapping.JWTClaim)
			}
			if mapping.Default == "" {
				continue
			}
			value = mapping.Default
		}
		params[mapping.Parameter] = value
	}

	return params, nil
}

// TransformResults maps confident answers onto claim names. An answer that did
// not clear the confidence threshold is absent from rawData, so its claim is
// simply not produced.
func (m *Mapper) TransformResults(rawData map[string]any, outputMapping []types.OutputMapping) (map[string]any, error) {
	claims := make(map[string]any, len(outputMapping))

	for _, mapping := range outputMapping {
		value, exists := rawData[mapping.SourceAnswer]
		if !exists {
			continue
		}

		transformed, err := m.ApplyTransformation(value, mapping.Transformation)
		if err != nil {
			return nil, fmt.Errorf("transformation failed for answer %s: %w", mapping.SourceAnswer, err)
		}

		claims[mapping.ClaimName] = transformed
	}

	return claims, nil
}

// ValidateInputMapping checks Jev-specific input mapping requirements.
func (m *Mapper) ValidateInputMapping(inputMapping []types.InputMapping) error {
	for _, mapping := range inputMapping {
		if mapping.JWTClaim == "" {
			return errors.New("jwt_claim cannot be empty")
		}
		if mapping.Parameter == "" {
			return errors.New("parameter cannot be empty")
		}
	}
	return nil
}

// ValidateOutputMapping checks that every mapping names a question to read.
func (m *Mapper) ValidateOutputMapping(outputMapping []types.OutputMapping) error {
	for _, mapping := range outputMapping {
		if mapping.ClaimName == "" {
			return errors.New("claim_name cannot be empty")
		}
		if !strings.HasPrefix(mapping.ClaimName, "jev.") {
			return fmt.Errorf("claim_name %q must use the reserved jev. namespace", mapping.ClaimName)
		}
		if mapping.SourceAnswer == "" {
			return errors.New("source_answer cannot be empty for Jev mapper")
		}
		if mapping.Transformation != "" && !transformation.IsCommonTransformation(mapping.Transformation) {
			return fmt.Errorf("unsupported transformation for Jev mapper: %s", mapping.Transformation)
		}
	}
	return nil
}

// GetSupportedTransformations returns the transformations answers may use.
// Answers are plain scalars, so the common set is the whole set.
func (m *Mapper) GetSupportedTransformations() []string {
	return transformation.GetCommonTransformations()
}

// ApplyTransformation applies a common transformation to an answer value.
func (m *Mapper) ApplyTransformation(value any, transformationName string) (any, error) {
	return transformation.DefaultRegistry.ApplyTransformation(value, transformationName, ProviderType)
}
