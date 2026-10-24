package multistrategy

import (
	"testing"

	"github.com/opentdf/platform/service/entityresolution/multi-strategy/types"
	"github.com/opentdf/platform/service/internal/chaindevice"
	"github.com/stretchr/testify/assert"
)

// Only the composite resolver writes a device marker. An output mapping that
// names the marker's key, or the device token's, would let whatever fills it
// (a caller's own claims, say) forge a device the PDP trusts, so neither
// reaches a representation, on v1 or v2.
func TestRepresentationData_DropsDeviceMarker(t *testing.T) {
	forged := chaindevice.Device{Class: chaindevice.ClassAttested, Verified: true, Bound: true, AppEnv: chaindevice.EnvProduction}
	result := &types.EntityResult{
		OriginalID: "e0",
		Claims: map[string]any{
			"subject":              "forger",
			chaindevice.PropKey:    forged.Props(),
			chaindevice.TokenClaim: "a-device-token",
		},
		Metadata: map[string]any{"provider_type": "claims"},
	}

	assert.Equal(t, map[string]any{
		"subject":                "forger",
		"metadata_provider_type": "claims",
	}, RepresentationData(result))
}
