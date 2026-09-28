package arkavo

import (
	"log/slog"

	"github.com/opentdf/platform/service/internal/agentstatus"
)

// defaultClientIDClaim is the fallback for Config.ClientIDClaim.
//
// DeviceClassCeilings keys are arkavo_npe.class values (e.g.
// unverified/managed/attested); the code that applies them switches only on
// the "unverified" default, in entity_resolution.go.
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
	// AgentStatus is where this resolver asks authnz-rs whether an agent
	// subject is eligible, each time it resolves one. Unset, every agent
	// subject resolves with no entitlements.
	AgentStatus agentstatus.Config `mapstructure:"agent_status" json:"agent_status"`
}

// LogValue keeps config logging structured; nothing here is secret.
func (c Config) LogValue() slog.Value {
	return slog.GroupValue(
		slog.Bool("trust_materialized_claims", c.TrustMaterializedClaims),
		slog.String("trusted_issuer", c.TrustedIssuer),
		slog.Any("direct_entitlement_actions", c.DirectEntitlementActions),
		slog.Int("device_class_ceilings", len(c.DeviceClassCeilings)),
		slog.String("client_id_claim", c.ClientIDClaim),
		slog.String("agent_status_url", c.AgentStatus.URL),
		slog.String("agent_status_client_id", c.AgentStatus.ClientID),
		slog.Duration("agent_status_timeout", c.AgentStatus.Timeout),
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
