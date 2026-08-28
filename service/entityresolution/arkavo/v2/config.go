package arkavo

import "log/slog"

// defaultClientIDClaim is the fallback for Config.ClientIDClaim.
//
// The arkavo_npe.class values (unverified/managed/attested) and npe.type
// values (agent/device) live in entity_resolution.go, next to the
// entitlement-shaping and entity-typing code that switches on them.
const defaultClientIDClaim = "arkavo_account_id"

// Config configures the arkavo claims-passthrough entity resolver.
type Config struct {
	// TrustMaterializedClaims enables emitting direct entitlements from the
	// token's arkavo_entitlements. Default false: without it this provider
	// only shapes entities and grants nothing. See patreon/v2 for the trust
	// rationale — the token signature is verified upstream by the authn
	// interceptor; TrustedIssuer pins which IdP's tokens are honored.
	TrustMaterializedClaims bool `mapstructure:"trust_materialized_claims" json:"trust_materialized_claims"`
	// TrustedIssuer must equal the token's iss for entitlements to be honored.
	TrustedIssuer string `mapstructure:"trusted_issuer" json:"trusted_issuer"`
	// DirectEntitlementActions are the action names attached to every
	// emitted entitlement. Standard lowercase names only. Default ["read"].
	DirectEntitlementActions []string `mapstructure:"direct_entitlement_actions" json:"direct_entitlement_actions"`
	// DeviceClassCeilings maps arkavo_npe.class -> attribute value FQNs a
	// device token is entitled to when presented as its own subject.
	DeviceClassCeilings map[string][]string `mapstructure:"device_class_ceilings" json:"device_class_ceilings"`
	// ClientIDClaim names the claim carrying the PE account id.
	ClientIDClaim string `mapstructure:"client_id_claim" json:"client_id_claim"`
}

// LogValue keeps config logging structured; nothing here is secret.
func (c Config) LogValue() slog.Value {
	return slog.GroupValue(
		slog.Bool("trust_materialized_claims", c.TrustMaterializedClaims),
		slog.String("trusted_issuer", c.TrustedIssuer),
		slog.Any("direct_entitlement_actions", c.DirectEntitlementActions),
		slog.Int("device_class_ceilings", len(c.DeviceClassCeilings)),
		slog.String("client_id_claim", c.ClientIDClaim),
	)
}

func (c *Config) applyDefaults() {
	if len(c.DirectEntitlementActions) == 0 {
		c.DirectEntitlementActions = []string{"read"}
	}
	if c.ClientIDClaim == "" {
		c.ClientIDClaim = defaultClientIDClaim
	}
	if c.DeviceClassCeilings == nil {
		c.DeviceClassCeilings = map[string][]string{}
	}
}
