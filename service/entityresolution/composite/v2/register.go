package composite

import (
	"context"
	"errors"
	"fmt"
	"log/slog"

	patreon "github.com/opentdf/platform/service/entityresolution/patreon/v2"
	"github.com/opentdf/platform/service/entityresolution/source"
	"github.com/opentdf/platform/service/internal/agentstatus"
	"github.com/opentdf/platform/service/internal/auth"
	"github.com/opentdf/platform/service/internal/publishingstatus"
	"github.com/opentdf/platform/service/logger"
	"github.com/opentdf/platform/service/pkg/config"
)

// sourceFactories builds a source from its config, by source type. Validate
// has already checked the options, so a factory only reads them.
var sourceFactories = map[string]func(SourceConfig) (source.Source, error){
	typePatreonToken: func(sc SourceConfig) (source.Source, error) {
		cfg, err := patreonOptions(sc.Options)
		if err != nil {
			return nil, err
		}
		return patreon.NewTokenSource(cfg), nil
	},
	typeTokenClaims: func(sc SourceConfig) (source.Source, error) {
		claim, _ := sc.Options[optionClaim].(string)
		if claim == "" {
			return nil, errors.New("a token-claims source needs a non-empty string claim")
		}
		return newTokenClaimsSource(claim, sc.Grants), nil
	},
}

// Register builds the composite resolver from the service config: it decodes
// and validates it, builds one CWT verifier per issuer, the configured
// sources, and the agent-status and publishing-status checkers when
// constraints.agent_status and constraints.publishing_status are set.
// Seal keys are decoded by New alone.
func Register(in config.ServiceConfig, log *logger.Logger) (*Service, error) {
	cfg, _, err := DecodeConfig(in)
	if err != nil {
		return nil, fmt.Errorf("decode composite entity resolution config: %w", err)
	}
	if err = cfg.Validate(); err != nil {
		return nil, fmt.Errorf("composite entity resolution config: %w", err)
	}
	log.Debug("composite entity resolution configuration", slog.Any("config", cfg))

	verifiers := make(map[string]claimsVerifier, len(cfg.Evidence.Issuers))
	for _, is := range cfg.Evidence.Issuers {
		v, vErr := auth.NewCWTVerifier(context.Background(), auth.CWTVerifierConfig{
			COSEKeysURL: is.COSEKeysURL,
			Issuer:      is.Issuer,
			Audience:    is.Audience,
			Algorithm:   "ES256",
		}, log)
		if vErr != nil {
			return nil, fmt.Errorf("evidence.issuers (%s): %w", is.Issuer, vErr)
		}
		verifiers[is.Issuer] = v
	}

	sources := make([]configuredSource, 0, len(cfg.Sources))
	for _, sc := range cfg.Sources {
		build, ok := sourceFactories[sc.Type]
		if !ok {
			return nil, fmt.Errorf("source %q: unknown type %q", sc.ID, sc.Type)
		}
		src, sErr := build(sc)
		if sErr != nil {
			return nil, fmt.Errorf("source %q: %w", sc.ID, sErr)
		}
		sources = append(sources, configuredSource{id: sc.ID, propsKey: sc.PropertiesKey, cap: newCapability(sc), src: src})
	}

	// A typed nil *agentstatus.Client in the interface would read as set, so
	// the checker is assigned only from a successful New.
	var checker agentstatus.Checker
	if cfg.Constraints.AgentStatus.Enabled() {
		client, aErr := agentstatus.New(cfg.Constraints.AgentStatus)
		if aErr != nil {
			return nil, fmt.Errorf("constraints.agent_status: %w", aErr)
		}
		checker = client
	}

	svc, err := New(cfg, verifiers, sources, checker, log)
	if err != nil {
		return nil, err
	}
	// Assigned only from a successful New, for the same typed-nil reason.
	if cfg.Constraints.PublishingStatus.Enabled() {
		client, pErr := publishingstatus.New(cfg.Constraints.PublishingStatus)
		if pErr != nil {
			return nil, fmt.Errorf("constraints.publishing_status: %w", pErr)
		}
		svc.publishing = client
	}
	return svc, nil
}
