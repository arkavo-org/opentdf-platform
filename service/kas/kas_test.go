package kas

import (
	"testing"

	"github.com/opentdf/platform/service/kas/access"
	"github.com/opentdf/platform/service/logger"
	"github.com/opentdf/platform/service/pkg/serviceregistry"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/types/known/structpb"
)

// TestRegisterKASWellKnown_StructpbCompatible exercises the actual failure
// mode of the original feat(kas) implementation: emitting algorithms as a
// []string makes structpb.NewStruct (used by the well-known HTTP handler
// to serialize the aggregate map) return an error, so the endpoint 500s.
// The payload must be a value tree that structpb can convert.
func TestRegisterKASWellKnown_StructpbCompatible(t *testing.T) {
	var captured map[string]any
	srp := serviceregistry.RegistrationParams{
		Logger: logger.CreateTestLogger(),
		WellKnownConfig: func(ns string, cfg any) error {
			require.Equal(t, "kas", ns)
			m, ok := cfg.(map[string]any)
			require.True(t, ok, "kas namespace value must be map[string]any")
			captured = m
			return nil
		},
	}
	kasCfg := access.KASConfig{
		RegisteredKASURI: "https://platform.example.test/",
		Keyring: []access.CurrentKeyFor{
			{KID: "r1", Algorithm: "rsa:2048"},
			{KID: "e1", Algorithm: "ec:secp256r1"},
			{KID: "r1", Algorithm: "rsa:2048", Legacy: true},
			{KID: "", Algorithm: ""},
		},
	}

	require.NoError(t, registerKASWellKnown(srp, kasCfg))
	require.NotNil(t, captured)

	_, err := structpb.NewStruct(captured)
	require.NoError(t, err, "captured payload must be structpb-compatible")

	require.Equal(t, "https://platform.example.test", captured["uri"])
	require.Equal(t, "https://platform.example.test/kas/v2/rewrap", captured["rewrap_url"])
	require.Equal(t, "https://platform.example.test/kas.AccessService/Rewrap", captured["connect_rewrap_url"])

	algs, ok := captured["algorithms"].([]any)
	require.True(t, ok, "algorithms must be []any (structpb requirement)")
	require.ElementsMatch(t, []any{"rsa:2048", "ec:secp256r1"}, algs)
}

func TestRegisterKASWellKnown_NoRegistrarIsNoOp(t *testing.T) {
	srp := serviceregistry.RegistrationParams{
		Logger:          logger.CreateTestLogger(),
		WellKnownConfig: nil,
	}
	require.NoError(t, registerKASWellKnown(srp, access.KASConfig{RegisteredKASURI: "https://x"}))
}
