// Package composite is the composite entity resolver: it unions the
// entitlements of independently configured sources under per-source
// capabilities, then applies constraints that only remove grants.
package composite

import (
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"slices"
	"strings"
	"time"

	"github.com/go-viper/mapstructure/v2"
	patreon "github.com/opentdf/platform/service/entityresolution/patreon/v2"
	"github.com/opentdf/platform/service/entityresolution/source"
	"github.com/opentdf/platform/service/internal/agentstatus"
	"github.com/opentdf/platform/service/internal/chaindevice"
	"github.com/opentdf/platform/service/internal/identityentities"
	"github.com/opentdf/platform/service/internal/publishingstatus"
	"github.com/opentdf/platform/service/pkg/config"
)

const (
	// defaultDeadline bounds each source's Resolve.
	defaultDeadline = 300 * time.Millisecond
	// minDeadline is the shortest deadline accepted. Anything shorter is a
	// bare YAML number read as nanoseconds, under which every source times
	// out.
	minDeadline = time.Millisecond
	// minSealKeyBytes is the shortest HMAC key accepted, decoded.
	minSealKeyBytes = 32
	redacted        = "[REDACTED]"

	// Source types.
	typePatreonToken    = "patreon-token"
	typeTokenClaims     = "token-claims"
	typePatreonIdentity = "patreon-identity"
	// removedTypeDeviceClass was a source granting by device class. Devices
	// never grant, so Validate refuses it by name.
	removedTypeDeviceClass = "device-class"

	// optionClaim is the key in SourceConfig.Options naming the claim a
	// token-claims source reads.
	optionClaim = "claim"
	// optionServe is the key in a patreon-identity source's options choosing
	// what it grants from: serveToken (the default: the token, comparing with
	// identity on the side) or serveIdentity.
	optionServe   = "serve"
	serveToken    = "token"
	serveIdentity = "identity"

	// movedToDeviceRules is where device rules went, for the refusals of
	// what they replaced.
	movedToDeviceRules = "device rules moved to device_rules in the policy file"
)

// Config is services.entityresolution when it selects the composite: the
// presence of sources does. Keys sit directly under the service block.
type Config struct {
	// Deadline bounds each source. Default 300ms.
	Deadline    time.Duration     `mapstructure:"deadline"`
	Evidence    EvidenceConfig    `mapstructure:"evidence"`
	Sources     []SourceConfig    `mapstructure:"sources"`
	Constraints ConstraintsConfig `mapstructure:"constraints"`
	// IdentityEntities is how a patreon-identity source reaches identity's
	// GET /entities. It sits here rather than in the source so its client
	// secret can come from the environment, which cannot reach a list item.
	IdentityEntities identityentities.Config `mapstructure:"identity_entities"`
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
	// Type is patreon-token or token-claims.
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
	// Deadline replaces the global deadline for this source. Zero keeps it.
	Deadline time.Duration `mapstructure:"deadline"`
	// Options holds the type-specific keys: claim, and the patreon source's
	// entitlements_namespace and infer_unknown_as_free.
	Options map[string]any `mapstructure:",remain"`
}

// ConstraintsConfig holds what may only remove grants.
type ConstraintsConfig struct {
	// AgentStatus unset withholds every agent subject.
	AgentStatus agentstatus.Config `mapstructure:"agent_status"`
	// DeviceClassCaps was removed: device rules moved to device_rules in the
	// policy file. It is present only so Validate can refuse a config that
	// still sets it.
	DeviceClassCaps map[string][]string `mapstructure:"device_class_caps"`
	// PublishingStatus unset leaves the constraint off; a partial block is a
	// startup error.
	PublishingStatus publishingstatus.Config `mapstructure:"publishing_status"`
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
		slog.String("publishing_status_url", c.Constraints.PublishingStatus.URL),
		slog.String("identity_entities_url", c.IdentityEntities.URL),
	)
}

// String renders the evidence block as LogValue does, keys redacted.
func (e EvidenceConfig) String() string { return e.LogValue().String() }

// Format renders String for every verb, so no fmt verb (%#v and %d
// included) prints a seal key, also for an EvidenceConfig inside a larger
// struct. As for agentstatus.Secret, %p is beyond it: fmt handles that verb
// before any Formatter.
func (e EvidenceConfig) Format(f fmt.State, _ rune) { _, _ = io.WriteString(f, e.String()) }

// String renders the config as LogValue does, keys redacted.
func (c Config) String() string { return c.LogValue().String() }

// Format renders String for every verb; see EvidenceConfig.Format.
func (c Config) Format(f fmt.State, _ rune) { _, _ = io.WriteString(f, c.String()) }

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
	if c.Deadline < minDeadline {
		return fmt.Errorf("deadline must be at least %s, got %s: write a duration string such as 300ms (a bare number is nanoseconds)", minDeadline, c.Deadline)
	}
	issuers, err := c.Evidence.validate()
	if err != nil {
		return err
	}
	if err := validateSources(c.Sources, issuers); err != nil {
		return err
	}
	if c.IdentityEntities.Enabled() {
		if err := c.IdentityEntities.Validate(); err != nil {
			return err
		}
	}
	for _, sc := range c.Sources {
		if sc.Type == typePatreonIdentity && !c.IdentityEntities.Enabled() {
			return fmt.Errorf("source %q: a patreon-identity source needs identity_entities", sc.ID)
		}
	}
	// An empty map is let through: the config loader drops it, so it cannot
	// be told from an absent key, and it caps nothing.
	if len(c.Constraints.DeviceClassCaps) > 0 {
		return errors.New("constraints.device_class_caps was removed: " + movedToDeviceRules)
	}
	if c.Constraints.AgentStatus.Enabled() {
		if _, err := agentstatus.New(c.Constraints.AgentStatus); err != nil {
			return fmt.Errorf("constraints.agent_status: %w", err)
		}
	}
	if c.Constraints.PublishingStatus.Enabled() {
		if _, err := publishingstatus.New(c.Constraints.PublishingStatus); err != nil {
			return fmt.Errorf("constraints.publishing_status: %w", err)
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
		case issuers[is.Issuer]:
			// One verifier per issuer: a second entry would silently replace
			// the first's key set and audience.
			return nil, fmt.Errorf("evidence.issuers[%d]: duplicate issuer %s", i, is.Issuer)
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
	owners := map[string]string{}      // definition FQN -> source ID
	propsOwners := map[string]string{} // properties_key -> source ID
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
		// Properties are not bounded by a capability, so a second source under
		// a key would replace the first's and drive its subject mappings.
		// They land at the top level of a representation, where the PDP reads
		// the composite's device marker, so its key is reserved, as is the
		// device token's claim.
		if key := sc.PropertiesKey; key != "" {
			if key == chaindevice.PropKey || key == chaindevice.TokenClaim {
				return fmt.Errorf("source %q: properties_key %q is reserved for chain devices", sc.ID, key)
			}
			if other, taken := propsOwners[key]; taken {
				return fmt.Errorf("properties_key %q is set by sources %q and %q: one source owns a properties key", key, other, sc.ID)
			}
			propsOwners[key] = sc.ID
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
	case typePatreonToken, typeTokenClaims, typePatreonIdentity:
	case removedTypeDeviceClass:
		return fmt.Errorf("type %q was removed: devices never grant; %s", sc.Type, movedToDeviceRules)
	default:
		return fmt.Errorf("unknown type %q", sc.Type)
	}
	if sc.Issuer == "" || !issuers[sc.Issuer] {
		return fmt.Errorf("issuer %q is not one of evidence.issuers", sc.Issuer)
	}
	if sc.Deadline != 0 && sc.Deadline < minDeadline {
		return fmt.Errorf("deadline must be at least %s, got %s: write a duration string such as 3500ms (a bare number is nanoseconds)", minDeadline, sc.Deadline)
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
	case typePatreonToken, typePatreonIdentity:
		opts, _, err := patreonSourceOptions(sc.Type, sc.Options)
		if err != nil {
			return err
		}
		// The source grants values of exactly these definitions. Owning
		// anything else, or missing one, would drop its grants silently.
		want := opts.Definitions()
		if !ownsExactly(owned, want) {
			return fmt.Errorf("a %s source's grants must be exactly %s and %s, the definitions in its entitlements_namespace", sc.Type, want[0], want[1])
		}
	case typeTokenClaims:
		if err := rejectUnknownOptions(sc.Options, optionClaim); err != nil {
			return err
		}
		if claim, _ := sc.Options[optionClaim].(string); claim == "" {
			return errors.New("a token-claims source needs a non-empty string claim")
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

// ownsExactly reports whether owned, a set of normalized definition FQNs,
// holds the definitions in want and nothing else.
func ownsExactly(owned map[string]bool, want []string) bool {
	if len(owned) != len(want) {
		return false
	}
	for _, w := range want {
		def, ok := definitionKey(w)
		if !ok || !owned[def] {
			return false
		}
	}
	return true
}

// patreonOptions decodes a patreon-token source's options, refusing a key it
// does not read: a misspelled option must not silently change what the source
// grants.
func patreonOptions(opts map[string]any) (patreon.SourceConfig, error) {
	var cfg patreon.SourceConfig
	dec, err := mapstructure.NewDecoder(&mapstructure.DecoderConfig{ErrorUnused: true, Result: &cfg})
	if err != nil {
		return cfg, err
	}
	if err = dec.Decode(opts); err != nil {
		return cfg, fmt.Errorf("patreon-token options: %w", err)
	}
	return cfg, nil
}

// patreonSourceOptions decodes the options of a patreon-token or
// patreon-identity source. A patreon-identity source also reads serve,
// token (the default) or identity.
func patreonSourceOptions(typ string, opts map[string]any) (patreon.SourceConfig, string, error) {
	serve := serveToken
	if typ == typePatreonIdentity {
		rest := make(map[string]any, len(opts))
		for k, v := range opts {
			if k != optionServe {
				rest[k] = v
			}
		}
		if raw, set := opts[optionServe]; set {
			s, _ := raw.(string)
			if s != serveToken && s != serveIdentity {
				return patreon.SourceConfig{}, "", fmt.Errorf("serve must be %q or %q", serveToken, serveIdentity)
			}
			serve = s
		}
		opts = rest
	}
	cfg, err := patreonOptions(opts)
	return cfg, serve, err
}

// rejectUnknownOptions refuses every option key outside allowed.
func rejectUnknownOptions(opts map[string]any, allowed ...string) error {
	for key := range opts {
		if !slices.Contains(allowed, key) {
			return fmt.Errorf("unknown option %q (this source type reads only %s)", key, strings.Join(allowed, ", "))
		}
	}
	return nil
}
