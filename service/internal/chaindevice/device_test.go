package chaindevice

import (
	"testing"

	entityresolutionV2 "github.com/opentdf/platform/protocol/go/entityresolution/v2"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/types/known/structpb"
)

func repWith(t *testing.T, props map[string]any) *entityresolutionV2.EntityRepresentation {
	t.Helper()
	st, err := structpb.NewStruct(props)
	require.NoError(t, err)
	return &entityresolutionV2.EntityRepresentation{AdditionalProps: []*structpb.Struct{st}}
}

func attestedDevice() Device {
	return Device{
		Class:     ClassAttested,
		Verified:  true,
		Bound:     true,
		AppIDHash: "ab",
		AppEnv:    EnvProduction,
	}
}

func TestDevice_RoundTrip(t *testing.T) {
	want := attestedDevice()
	rep := repWith(t, map[string]any{
		"patreon": map[string]any{"role": "creator"},
		PropKey:   want.Props(),
	})
	got, ok := FromRepresentation(rep)
	require.True(t, ok)
	assert.Equal(t, want, got)
}

func TestDevice_PropsShapeIsFixed(t *testing.T) {
	assert.Equal(t, map[string]any{
		"kind":        KindDevice,
		"class":       ClassUnverified,
		"verified":    false,
		"bound":       false,
		"app_id_hash": "",
		"app_env":     "",
	}, Device{Class: ClassUnverified}.Props())
}

func TestDevice_FoundInLaterProps(t *testing.T) {
	want := attestedDevice()
	first := repWith(t, map[string]any{"patreon": map[string]any{"role": "creator"}})
	second := repWith(t, map[string]any{PropKey: want.Props()})
	rep := &entityresolutionV2.EntityRepresentation{
		AdditionalProps: append(first.GetAdditionalProps(), second.GetAdditionalProps()...),
	}
	got, ok := FromRepresentation(rep)
	require.True(t, ok)
	assert.Equal(t, want, got)
}

// A marker that is present but broken reads as an unverified, unbound device
// rather than as no device, so a broken resolver denies instead of skipping
// the device.
func TestDevice_Malformed(t *testing.T) {
	marker := func(mutate func(map[string]any)) map[string]any {
		props := attestedDevice().Props()
		mutate(props)
		return map[string]any{PropKey: props}
	}
	for name, props := range map[string]map[string]any{
		"not a struct":       {PropKey: "device"},
		"kind missing":       marker(func(p map[string]any) { delete(p, "kind") }),
		"kind not device":    marker(func(p map[string]any) { p["kind"] = "person" }),
		"bound not a bool":   marker(func(p map[string]any) { p["bound"] = "yes" }),
		"bound missing":      marker(func(p map[string]any) { delete(p, "bound") }),
		"verified not bool":  marker(func(p map[string]any) { p["verified"] = "yes" }),
		"verified missing":   marker(func(p map[string]any) { delete(p, "verified") }),
		"verified is false":  marker(func(p map[string]any) { p["verified"] = false }),
		"class not a string": marker(func(p map[string]any) { p["class"] = true }),
		"class missing":      marker(func(p map[string]any) { delete(p, "class") }),
		"class unknown":      marker(func(p map[string]any) { p["class"] = "jailbroken" }),
		"app hash not text":  marker(func(p map[string]any) { p["app_id_hash"] = true }),
		"app env not text":   marker(func(p map[string]any) { p["app_env"] = 1 }),
	} {
		t.Run(name, func(t *testing.T) {
			got, ok := FromRepresentation(repWith(t, props))
			require.True(t, ok)
			assert.Equal(t, Device{Class: ClassUnverified}, got)
		})
	}
}

// A device with no app is a real shape (a managed device), so the app fields
// may be absent.
func TestDevice_AppFieldsMayBeAbsent(t *testing.T) {
	props := Device{Class: ClassManaged, Verified: true, Bound: true}.Props()
	delete(props, "app_id_hash")
	delete(props, "app_env")
	got, ok := FromRepresentation(repWith(t, map[string]any{PropKey: props}))
	require.True(t, ok)
	assert.Equal(t, Device{Class: ClassManaged, Verified: true, Bound: true}, got)
}

func TestDevice_UnverifiedNeverBound(t *testing.T) {
	props := Device{Class: ClassAttested, Verified: false, Bound: true}.Props()
	got, ok := FromRepresentation(repWith(t, map[string]any{PropKey: props}))
	require.True(t, ok)
	assert.Equal(t, Device{Class: ClassUnverified}, got)
}

func TestDevice_Absent(t *testing.T) {
	_, ok := FromRepresentation(repWith(t, map[string]any{"patreon": map[string]any{"role": "creator"}}))
	assert.False(t, ok)
	_, ok = FromRepresentation(&entityresolutionV2.EntityRepresentation{})
	assert.False(t, ok)
	_, ok = FromRepresentation(nil)
	assert.False(t, ok)
}
