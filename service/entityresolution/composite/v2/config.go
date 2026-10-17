// Package composite is the composite entity resolver: it unions the
// entitlements of independently configured sources under per-source
// capabilities, then applies constraints that only remove grants.
package composite

import (
	"encoding/base64"
	"errors"
	"fmt"
	"log/slog"
	"time"

	"github.com/go-viper/mapstructure/v2"
	"github.com/opentdf/platform/service/entityresolution/source"
	"github.com/opentdf/platform/service/internal/agentstatus"
	"github.com/opentdf/platform/service/pkg/config"
)

const (
	// defaultDeadline bounds each source's Resolve.
	defaultDeadline = 300 * time.Millisecond
	// minSealKeyBytes is the shortest HMAC key accepted, decoded.
	minSealKeyBytes = 32
	redacted        = "[REDACTED]"

	// Source types.
	typePatreonToken = "patreon-token"
	typeTokenClaims  = "token-claims"
	typeDeviceClass  = "device-class"

	// Keys in SourceConfig.Options.
	optionClaim   = "claim"
	optionClasses = "classes"
)

// Config is services.entityresolution when it selects the composite: the
// presence of sources does. Keys sit directly under the service block.
type Config struct {
	// Deadline bounds each source. Default 300ms.
	Deadline    time.Duration     `mapstructure:"deadline"`
	Evidence    EvidenceConfig    `mapstructure:"evidence"`
	Sources     []SourceConfig    `mapstructure:"sources"`
	Constraints ConstraintsConfig `mapstructure:"constraints"`
}

// EvidenceConfig configures who may issue the tokens the sources read and
// how the evidence handed from the token route to the second call is sealed.
type EvidenceConfig struct {
	Issuers []IssuerConfig `mapstructure:"issuers"`
	// SealKey seals and opens arkavo_evidence. Standard base64 with padding,
	// at least 32 bytes once decoded.
	SealKey string `mapstructure:"seal_key"`
	// PreviousSealKeys open evidence but never seal it, so SealKey can rotate.
	PreviousSealKeys []string `mapstructure:"previous_seal_keys"`
	// ClaimsChainPEPs are the client IDs of the PEPs whose unsealed claims
	// chains are accepted.
	ClaimsChainPEPs []string `mapstructure:"claims_chain_peps"`
}

// IssuerConfig is one token issuer and where its COSE keys are fetched.
type IssuerConfig struct {
	Issuer      string `mapstructure:"issuer"`
	COSEKeysURL string `mapstructure:"cose_keys_url"`
	Audience    string `mapstructure:"audience"`
}

// SourceConfig configures one source and its capability.
type SourceConfig struct {
	ID string `mapstructure:"id"`
	// Type is patreon-token, token-claims or device-class.
	Type   string `mapstructure:"type"`
	Issuer string `mapstructure:"issuer"`
	// Grants are the attribute definition FQNs this source owns.
	Grants []string `mapstructure:"grants"`
	// Actions are the actions its grants may carry. Default ["read"].
	Actions []string `mapstructure:"actions"`
	// Subjects are the kinds it serves. Default all three.
	Subjects      []source.Kind `mapstructure:"subjects"`
	PEPAssertable bool          `mapstructure:"pep_assertable"`
	PropertiesKey string        `mapstructure:"properties_key"`
	// Options holds the type-specific keys: claim, classes, and the patreon
	// source's entitlements_namespace and infer_unknown_as_free.
	Options map[string]any `mapstructure:",remain"`
}

// ConstraintsConfig holds what may only remove grants.
type ConstraintsConfig struct {
	// AgentStatus unset withholds every agent subject.
	AgentStatus agentstatus.Config `mapstructure:"agent_status"`
	// DeviceClassCaps maps an arkavo_npe.class to the value FQNs a device of
	// that class is capped to. A class missing from it has no cap.
	DeviceClassCaps map[string][]string `mapstructure:"device_class_caps"`
}

// LogValue keeps the seal keys out of every log line.
func (e EvidenceConfig) LogValue() slog.Value {
	issuers := make([]string, 0, len(e.Issuers))
	for _, i := range e.Issuers {
		issuers = append(issuers, i.Issuer)
	}
	return slog.GroupValue(
		slog.Any("issuers", issuers),
		slog.String("seal_key", redacted),
		slog.Int("previous_seal_keys", len(e.PreviousSealKeys)),
		slog.Any("claims_chain_peps", e.ClaimsChainPEPs),
	)
}

// LogValue summarizes the config without its secrets.
func (c Config) LogValue() slog.Value {
	sources := make([]string, 0, len(c.Sources))
	for _, s := range c.Sources {
		sources = append(sources, s.ID+":"+s.Type)
	}
	return slog.GroupValue(
		slog.Duration("deadline", c.Deadline),
		slog.Attr{Key: "evidence", Value: c.Evidence.LogValue()},
		slog.Any("sources", sources),
		slog.String("agent_status_url", c.Constraints.AgentStatus.URL),
		slog.Int("device_class_caps", len(c.Constraints.DeviceClassCaps)),
	)
}

// DecodeConfig reads the service config. The bool reports whether it has a
// "sources" key, which is what selects the composite. A zero deadline becomes
// 300ms; durations arrive as strings ("250ms").
func DecodeConfig(in config.ServiceConfig) (Config, bool, error) {
	if _, present := in["sources"]; !present {
		return Config{}, false, nil
	}
	var cfg Config
	dec, err := mapstructure.NewDecoder(&mapstructure.DecoderConfig{
		DecodeHook: mapstructure.StringToTimeDurationHookFunc(),
		Result:     &cfg,
	})
	if err != nil {
		return Config{}, true, err
	}
	if err = dec.Decode(in); err != nil {
		return Config{}, true, err
	}
	if cfg.Deadline == 0 {
		cfg.Deadline = defaultDeadline
	}
	return cfg, true, nil
}

// Validate reports the first problem that would make the config unsafe or
// meaningless. It never echoes a key.
func (c Config) Validate() error {
	issuers, err := c.Evidence.validate()
	if err != nil {
		return err
	}
	if err := validateSources(c.Sources, issuers); err != nil {
		return err
	}
	for class, fqns := range c.Constraints.DeviceClassCaps {
		for _, fqn := range fqns {
			if _, ok := source.ParseFQN(fqn); !ok {
				return fmt.Errorf("constraints.device_class_caps[%q]: %q is not a value FQN", class, fqn)
			}
		}
	}
	if c.Constraints.AgentStatus.Enabled() {
		if _, err := agentstatus.New(c.Constraints.AgentStatus); err != nil {
			return fmt.Errorf("constraints.agent_status: %w", err)
		}
	}
	return nil
}

// validate checks the evidence block and returns its issuers as a set.
func (e EvidenceConfig) validate() (map[string]bool, error) {
	if len(e.Issuers) == 0 {
		return nil, errors.New("evidence.issuers: at least one issuer is required")
	}
	issuers := make(map[string]bool, len(e.Issuers))
	for i, is := range e.Issuers {
		switch {
		case is.Issuer == "":
			return nil, fmt.Errorf("evidence.issuers[%d]: issuer is required", i)
		case is.COSEKeysURL == "":
			return nil, fmt.Errorf("evidence.issuers[%d] (%s): cose_keys_url is required", i, is.Issuer)
		case is.Audience == "":
			return nil, fmt.Errorf("evidence.issuers[%d] (%s): audience is required", i, is.Issuer)
		}
		issuers[is.Issuer] = true
	}
	if e.SealKey == "" {
		return nil, errors.New("evidence.seal_key is required")
	}
	if _, err := decodeKey(e.SealKey); err != nil {
		return nil, fmt.Errorf("evidence.seal_key: %w", err)
	}
	for i, k := range e.PreviousSealKeys {
		if _, err := decodeKey(k); err != nil {
			return nil, fmt.Errorf("evidence.previous_seal_keys[%d]: %w", i, err)
		}
	}
	for i, pep := range e.ClaimsChainPEPs {
		if pep == "" {
			return nil, fmt.Errorf("evidence.claims_chain_peps[%d]: empty client ID", i)
		}
	}
	return issuers, nil
}

// decodeKey decodes a seal key: standard base64 with padding, at least
// minSealKeyBytes long. The error never carries the key.
func decodeKey(s string) ([]byte, error) {
	key, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		return nil, errors.New("is not standard base64 with padding")
	}
	if len(key) < minSealKeyBytes {
		return nil, fmt.Errorf("must decode to at least %d bytes, got %d", minSealKeyBytes, len(key))
	}
	return key, nil
}

func validateSources(sources []SourceConfig, issuers map[string]bool) error {
	ids := map[string]bool{}
	owners := map[string]string{} // definition FQN -> source ID
	for i, sc := range sources {
		if sc.ID == "" {
			return fmt.Errorf("sources[%d]: id is required", i)
		}
		if ids[sc.ID] {
			return fmt.Errorf("sources[%d]: duplicate source id %q", i, sc.ID)
		}
		ids[sc.ID] = true
		if err := sc.validate(issuers); err != nil {
			return fmt.Errorf("source %q: %w", sc.ID, err)
		}
		for _, g := range sc.Grants {
			def, _ := definitionKey(g)
			if other, taken := owners[def]; taken && other != sc.ID {
				return fmt.Errorf("definition %s is listed by sources %q and %q: one source owns a definition", def, other, sc.ID)
			}
			owners[def] = sc.ID
		}
	}
	return nil
}

func (sc SourceConfig) validate(issuers map[string]bool) error {
	switch sc.Type {
	case typePatreonToken, typeTokenClaims, typeDeviceClass:
	default:
		return fmt.Errorf("unknown type %q", sc.Type)
	}
	if sc.Issuer == "" || !issuers[sc.Issuer] {
		return fmt.Errorf("issuer %q is not one of evidence.issuers", sc.Issuer)
	}
	for _, k := range sc.Subjects {
		switch k {
		case source.KindPerson, source.KindAgent, source.KindDevice:
		default:
			return fmt.Errorf("unknown subject kind %q", k)
		}
	}
	owned := map[string]bool{}
	for _, g := range sc.Grants {
		def, ok := definitionKey(g)
		if !ok {
			return fmt.Errorf("grant %q is not an attribute definition FQN (https://<namespace>/attr/<name>)", g)
		}
		owned[def] = true
	}
	switch sc.Type {
	case typeTokenClaims:
		if claim, _ := sc.Options[optionClaim].(string); claim == "" {
			return errors.New("a token-claims source needs a non-empty string claim")
		}
	case typeDeviceClass:
		classes, err := deviceClasses(sc.Options)
		if err != nil {
			return err
		}
		for class, fqns := range classes {
			for _, fqn := range fqns {
				parsed, ok := source.ParseFQN(fqn)
				if !ok {
					return fmt.Errorf("classes[%q]: %q is not a value FQN", class, fqn)
				}
				if !owned[parsed.DefinitionFQN()] {
					return fmt.Errorf("classes[%q]: %q is outside this source's grants", class, fqn)
				}
			}
		}
	}
	return nil
}

// definitionKey normalizes a definition FQN (lowercased) for comparison.
func definitionKey(s string) (string, bool) {
	ns, def, ok := source.ParseDefinition(s)
	if !ok {
		return "", false
	}
	return source.FQN{Namespace: ns, Definition: def}.DefinitionFQN(), true
}
