package multistrategy

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"reflect"
	"testing"

	"github.com/opentdf/platform/service/entityresolution/multi-strategy/types"
	"github.com/opentdf/platform/service/logger"
)

func TestMultiStrategyService_JevProviderEndToEnd(t *testing.T) {
	t.Setenv("OPENROUTER_API_KEY", "test-key")

	var state map[string]any
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var body struct {
			State map[string]any `json:"state"`
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		state = body.State
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{
  "id":"jev-service-test",
  "model":"typesafe/jev-1.13-20260917",
  "answers":{
    "risk_tier":{
      "type":"choice",
      "choice":"elevated",
      "confidence":0.93,
      "probabilities":{"elevated":0.93,"routine":0.07}
    }
  },
  "usage":{"cost":0.000002,"input_tokens":20,"output_tokens":3}
}`))
	}))
	t.Cleanup(server.Close)

	config := types.MultiStrategyConfig{
		Providers: map[string]types.ProviderConfig{
			"risk": {
				Type: "jev",
				Connection: map[string]any{
					"enabled":              true,
					"base_url":             server.URL,
					"state_allowlist":      []string{"department", "employment_type"},
					"confidence_threshold": 0.8,
					"seams": map[string]any{
						"ers_claims": map[string]any{"enabled": true, "mode": "enforce"},
					},
					"questions": map[string]any{
						"risk_tier": map[string]any{
							"type":         "choice",
							"instructions": "How much scrutiny does this context warrant?",
							"criteria": map[string]any{
								"elevated": "unusual employment context",
								"routine":  "ordinary employment context",
							},
						},
					},
				},
			},
		},
		MappingStrategies: []types.MappingStrategy{
			{
				Name:       "derive_risk",
				Provider:   "risk",
				EntityType: types.EntityTypeSubject,
				Conditions: types.StrategyConditions{JWTClaims: []types.JWTClaimCondition{
					{Claim: "aud", Operator: "exists"},
				}},
				InputMapping: []types.InputMapping{
					{JWTClaim: "department", Parameter: "department", Required: true},
					{JWTClaim: "employment_type", Parameter: "employment_type", Default: "unknown"},
				},
				OutputMapping: []types.OutputMapping{
					{SourceAnswer: "risk_tier", ClaimName: "jev.risk_tier", Transformation: "array"},
				},
			},
		},
	}

	service, err := NewService(t.Context(), config, &logger.Logger{})
	if err != nil {
		t.Fatalf("NewService() error = %v", err)
	}
	t.Cleanup(func() { _ = service.Close() })

	result, err := service.ResolveEntity(t.Context(), "user-123", types.JWTClaims{
		"aud":        "arkavo",
		"department": "finance",
	})
	if err != nil {
		t.Fatalf("ResolveEntity() error = %v", err)
	}

	wantClaim := []any{"elevated"}
	if !reflect.DeepEqual(result.Claims["jev.risk_tier"], wantClaim) {
		t.Fatalf("derived claim = %#v, want %#v", result.Claims["jev.risk_tier"], wantClaim)
	}
	if got := state["employment_type"]; got != "unknown" {
		t.Fatalf("defaulted state employment_type = %#v, want unknown", got)
	}
}

func TestMultiStrategyService_JWT_Claims_Provider(t *testing.T) {
	// Test configuration with JWT claims provider
	config := types.MultiStrategyConfig{
		Providers: map[string]types.ProviderConfig{
			"jwt": {
				Type:       "claims",
				Connection: map[string]interface{}{},
			},
		},
		MappingStrategies: []types.MappingStrategy{
			{
				Name:       "jwt_strategy",
				Provider:   "jwt",
				EntityType: types.EntityTypeSubject,
				Conditions: types.StrategyConditions{
					JWTClaims: []types.JWTClaimCondition{
						{
							Claim:    "aud",
							Operator: "exists",
							Values:   []string{},
						},
					},
				},
				InputMapping: []types.InputMapping{},
				OutputMapping: []types.OutputMapping{
					{
						SourceClaim: "sub",
						ClaimName:   "subject",
					},
					{
						SourceClaim: "email",
						ClaimName:   "email_address",
					},
				},
			},
		},
	}

	// Create service
	service, err := NewService(t.Context(), config, &logger.Logger{})
	if err != nil {
		t.Fatalf("Failed to create service: %v", err)
	}
	defer service.Close()

	// Test with JWT claims in context
	ctx := context.WithValue(t.Context(), types.JWTClaimsContextKey, types.JWTClaims{
		"sub":   "user123",
		"email": "user@example.com",
		"aud":   "test-audience",
	})

	// Resolve entity
	result, err := service.ResolveEntity(ctx, "user123", types.JWTClaims{
		"sub":   "user123",
		"email": "user@example.com",
		"aud":   "test-audience",
	})
	if err != nil {
		t.Fatalf("Failed to resolve entity: %v", err)
	}

	// Verify result
	if result.OriginalID != "user123" {
		t.Errorf("Expected OriginalID 'user123', got '%s'", result.OriginalID)
	}

	// Check mapped claims
	if result.Claims["subject"] != "user123" {
		t.Errorf("Expected subject 'user123', got '%v'", result.Claims["subject"])
	}

	if result.Claims["email_address"] != "user@example.com" {
		t.Errorf("Expected email_address 'user@example.com', got '%v'", result.Claims["email_address"])
	}

	// Check metadata
	if result.Metadata["provider_type"] != "claims" {
		t.Errorf("Expected provider_type 'claims', got '%v'", result.Metadata["provider_type"])
	}
}

func TestMultiStrategyService_No_Matching_Strategy(t *testing.T) {
	// Test configuration with strict conditions
	config := types.MultiStrategyConfig{
		Providers: map[string]types.ProviderConfig{
			"jwt": {
				Type:       "claims",
				Connection: map[string]interface{}{},
			},
		},
		MappingStrategies: []types.MappingStrategy{
			{
				Name:     "strict_strategy",
				Provider: "jwt",
				Conditions: types.StrategyConditions{
					JWTClaims: []types.JWTClaimCondition{
						{
							Claim:    "aud",
							Operator: "equals",
							Values:   []string{"specific-audience"},
						},
					},
				},
				InputMapping:  []types.InputMapping{},
				OutputMapping: []types.OutputMapping{},
			},
		},
	}

	// Create service
	service, err := NewService(t.Context(), config, &logger.Logger{})
	if err != nil {
		t.Fatalf("Failed to create service: %v", err)
	}
	defer service.Close()

	// Test with JWT claims that don't match strategy conditions
	_, err = service.ResolveEntity(t.Context(), "user123", types.JWTClaims{
		"sub": "user123",
		"aud": "different-audience", // This won't match the strategy condition
	})

	// Should get a "no matching strategy" error
	if err == nil {
		t.Fatal("Expected error for no matching strategy, but got none")
	}

	var strategyErr *types.MultiStrategyError
	if !errors.As(err, &strategyErr) {
		t.Fatalf("Expected MultiStrategyError, got %T", err)
	}

	if strategyErr.Type != types.ErrorTypeStrategy {
		t.Errorf("Expected ErrorTypeStrategy, got %v", strategyErr.Type)
	}
}

func TestMultiStrategyService_Provider_Not_Found(t *testing.T) {
	// Test configuration with invalid provider reference
	config := types.MultiStrategyConfig{
		Providers: map[string]types.ProviderConfig{
			"jwt": {
				Type:       "claims",
				Connection: map[string]interface{}{},
			},
		},
		MappingStrategies: []types.MappingStrategy{
			{
				Name:     "invalid_strategy",
				Provider: "nonexistent_provider", // Provider doesn't exist
				Conditions: types.StrategyConditions{
					JWTClaims: []types.JWTClaimCondition{
						{
							Claim:    "aud",
							Operator: "exists",
							Values:   []string{},
						},
					},
				},
				InputMapping:  []types.InputMapping{},
				OutputMapping: []types.OutputMapping{},
			},
		},
	}

	// Create service
	service, err := NewService(t.Context(), config, &logger.Logger{})
	if err != nil {
		t.Fatalf("Failed to create service: %v", err)
	}
	defer service.Close()

	// Test with valid JWT claims
	_, err = service.ResolveEntity(t.Context(), "user123", types.JWTClaims{
		"aud": "test-audience",
	})

	// Should get a "provider not found" error
	if err == nil {
		t.Fatal("Expected error for provider not found, but got none")
	}

	var providerErr *types.MultiStrategyError
	if !errors.As(err, &providerErr) {
		t.Fatalf("Expected MultiStrategyError, got %T", err)
	}

	// The error could be either ErrorTypeProvider (if caught in executeStrategy)
	// or ErrorTypeStrategy (if caught in ResolveEntity loop)
	if providerErr.Type != types.ErrorTypeProvider && providerErr.Type != types.ErrorTypeStrategy {
		t.Errorf("Expected ErrorTypeProvider or ErrorTypeStrategy, got %v", providerErr.Type)
	}
}

func TestMultiStrategyService_FailureStrategyContinue(t *testing.T) {
	// Test configuration with global continue strategy where first fails, second succeeds
	config := types.MultiStrategyConfig{
		FailureStrategy: types.FailureStrategyContinue, // Global continue policy
		Providers: map[string]types.ProviderConfig{
			"bad_provider": {
				Type:       "claims",
				Connection: map[string]interface{}{},
			},
			"good_provider": {
				Type:       "claims",
				Connection: map[string]interface{}{},
			},
		},
		MappingStrategies: []types.MappingStrategy{
			{
				Name:       "failing_strategy",
				Provider:   "bad_provider",
				EntityType: types.EntityTypeSubject,
				Conditions: types.StrategyConditions{
					JWTClaims: []types.JWTClaimCondition{
						{
							Claim:    "aud",
							Operator: "exists",
							Values:   []string{},
						},
					},
				},
				OutputMapping: []types.OutputMapping{
					{
						SourceClaim: "sub",
						ClaimName:   "subject",
					},
				},
			},
			{
				Name:       "success_strategy",
				Provider:   "good_provider",
				EntityType: types.EntityTypeSubject,
				Conditions: types.StrategyConditions{
					JWTClaims: []types.JWTClaimCondition{
						{
							Claim:    "aud",
							Operator: "exists",
							Values:   []string{},
						},
					},
				},
				OutputMapping: []types.OutputMapping{
					{
						SourceClaim: "sub",
						ClaimName:   "subject",
					},
				},
			},
		},
	}

	// Create service
	service, err := NewService(t.Context(), config, &logger.Logger{})
	if err != nil {
		t.Fatalf("Failed to create service: %v", err)
	}

	// Remove the bad provider to simulate failure
	_ = service.providerRegistry.providers["bad_provider"].Close()
	delete(service.providerRegistry.providers, "bad_provider")

	// Test with matching JWT
	ctx := context.WithValue(t.Context(), types.JWTClaimsContextKey, types.JWTClaims{
		"sub": "user123",
		"aud": "test-audience",
	})

	result, err := service.ResolveEntity(ctx, "user123", types.JWTClaims{
		"sub": "user123",
		"aud": "test-audience",
	})
	if err != nil {
		t.Fatalf("Expected success with fallback strategy, got error: %v", err)
	}

	// Verify the second strategy was used
	if result.Metadata["strategy_name"] != "success_strategy" {
		t.Errorf("Expected strategy_name 'success_strategy', got '%v'", result.Metadata["strategy_name"])
	}

	// Verify entity type metadata
	if result.Metadata["entity_type"] != types.EntityTypeSubject {
		t.Errorf("Expected entity_type '%s', got '%v'", types.EntityTypeSubject, result.Metadata["entity_type"])
	}

	// Verify attempted strategies metadata
	attemptedStrategies, ok := result.Metadata["attempted_strategies"].([]string)
	if !ok || len(attemptedStrategies) != 2 {
		t.Errorf("Expected attempted_strategies to contain 2 strategies, got %v", result.Metadata["attempted_strategies"])
	}
}

func TestMultiStrategyService_FailureStrategyFailFast(t *testing.T) {
	// Test configuration with global fail-fast strategy
	config := types.MultiStrategyConfig{
		FailureStrategy: types.FailureStrategyFailFast, // Global fail-fast policy
		Providers: map[string]types.ProviderConfig{
			"bad_provider": {
				Type:       "claims",
				Connection: map[string]interface{}{},
			},
		},
		MappingStrategies: []types.MappingStrategy{
			{
				Name:       "failing_strategy",
				Provider:   "bad_provider",
				EntityType: types.EntityTypeSubject,
				Conditions: types.StrategyConditions{
					JWTClaims: []types.JWTClaimCondition{
						{
							Claim:    "aud",
							Operator: "exists",
							Values:   []string{},
						},
					},
				},
				OutputMapping: []types.OutputMapping{
					{
						SourceClaim: "sub",
						ClaimName:   "subject",
					},
				},
			},
		},
	}

	// Create service
	service, err := NewService(t.Context(), config, &logger.Logger{})
	if err != nil {
		t.Fatalf("Failed to create service: %v", err)
	}

	// Remove the provider to simulate failure
	_ = service.providerRegistry.providers["bad_provider"].Close()
	delete(service.providerRegistry.providers, "bad_provider")

	// Test with matching JWT
	_, err = service.ResolveEntity(t.Context(), "user123", types.JWTClaims{
		"sub": "user123",
		"aud": "test-audience",
	})

	// Should fail immediately
	if err == nil {
		t.Fatal("Expected error with fail-fast strategy, but got none")
	}

	var strategyErr *types.MultiStrategyError
	if !errors.As(err, &strategyErr) {
		t.Fatalf("Expected MultiStrategyError, got %T", err)
	}

	if strategyErr.Type != types.ErrorTypeStrategy {
		t.Errorf("Expected ErrorTypeStrategy, got %v", strategyErr.Type)
	}
}

func TestMultiStrategyService_EntityTypeEnvironment(t *testing.T) {
	// Test configuration with environment entity type
	config := types.MultiStrategyConfig{
		Providers: map[string]types.ProviderConfig{
			"env_provider": {
				Type:       "claims",
				Connection: map[string]interface{}{},
			},
		},
		MappingStrategies: []types.MappingStrategy{
			{
				Name:       "environment_strategy",
				Provider:   "env_provider",
				EntityType: types.EntityTypeEnvironment, // Environment entity
				Conditions: types.StrategyConditions{
					JWTClaims: []types.JWTClaimCondition{
						{
							Claim:    "client_ip",
							Operator: "exists",
							Values:   []string{},
						},
					},
				},
				OutputMapping: []types.OutputMapping{
					{
						SourceClaim: "client_ip",
						ClaimName:   "source_ip",
					},
					{
						SourceClaim: "device_id",
						ClaimName:   "device_identifier",
					},
				},
			},
		},
	}

	// Create service
	service, err := NewService(t.Context(), config, &logger.Logger{})
	if err != nil {
		t.Fatalf("Failed to create service: %v", err)
	}

	// Test with environment context
	ctx := context.WithValue(t.Context(), types.JWTClaimsContextKey, types.JWTClaims{
		"client_ip": "192.168.1.100",
		"device_id": "device-abc-123",
	})

	result, err := service.ResolveEntity(ctx, "env123", types.JWTClaims{
		"client_ip": "192.168.1.100",
		"device_id": "device-abc-123",
	})
	if err != nil {
		t.Fatalf("Failed to resolve environment entity: %v", err)
	}

	// Verify entity type metadata
	if result.Metadata["entity_type"] != types.EntityTypeEnvironment {
		t.Errorf("Expected entity_type '%s', got '%v'", types.EntityTypeEnvironment, result.Metadata["entity_type"])
	}

	// Check mapped claims
	if result.Claims["source_ip"] != "192.168.1.100" {
		t.Errorf("Expected source_ip '192.168.1.100', got '%v'", result.Claims["source_ip"])
	}

	if result.Claims["device_identifier"] != "device-abc-123" {
		t.Errorf("Expected device_identifier 'device-abc-123', got '%v'", result.Claims["device_identifier"])
	}
}

func TestMultiStrategyService_DefaultFailureStrategy(t *testing.T) {
	// Test that empty global failure_strategy defaults to fail-fast
	config := types.MultiStrategyConfig{
		// FailureStrategy not set - should default to fail-fast
		Providers: map[string]types.ProviderConfig{
			"bad_provider": {
				Type:       "claims",
				Connection: map[string]interface{}{},
			},
		},
		MappingStrategies: []types.MappingStrategy{
			{
				Name:       "strategy_no_failure_setting",
				Provider:   "bad_provider",
				EntityType: types.EntityTypeSubject,
				Conditions: types.StrategyConditions{
					JWTClaims: []types.JWTClaimCondition{
						{
							Claim:    "aud",
							Operator: "exists",
							Values:   []string{},
						},
					},
				},
				OutputMapping: []types.OutputMapping{
					{
						SourceClaim: "sub",
						ClaimName:   "subject",
					},
				},
			},
		},
	}

	// Create service
	service, err := NewService(t.Context(), config, &logger.Logger{})
	if err != nil {
		t.Fatalf("Failed to create service: %v", err)
	}

	// Remove the provider to simulate failure
	_ = service.providerRegistry.providers["bad_provider"].Close()
	delete(service.providerRegistry.providers, "bad_provider")

	// Test with matching JWT
	_, err = service.ResolveEntity(t.Context(), "user123", types.JWTClaims{
		"sub": "user123",
		"aud": "test-audience",
	})

	// Should fail immediately (default fail-fast behavior)
	if err == nil {
		t.Fatal("Expected error with default fail-fast strategy, but got none")
	}

	var strategyErr *types.MultiStrategyError
	if !errors.As(err, &strategyErr) {
		t.Fatalf("Expected MultiStrategyError, got %T", err)
	}

	if strategyErr.Type != types.ErrorTypeStrategy {
		t.Errorf("Expected ErrorTypeStrategy, got %v", strategyErr.Type)
	}
}
