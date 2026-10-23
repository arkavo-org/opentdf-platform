package entityconstraint

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

func TestFromRepresentation_RoundTrip(t *testing.T) {
	rep := repWith(t, map[string]any{
		"patreon": map[string]any{"role": "creator"},
		PropKey:   Props(KindDevice, "managed", true, []string{"https://Example.com/attr/a/value/X"}),
	})
	c, ok := FromRepresentation(rep)
	require.True(t, ok)
	assert.Equal(t, Constraint{
		Kind: KindDevice, Class: "managed", Capped: true,
		Allow: map[string]bool{"https://example.com/attr/a/value/x": true},
	}, c)
}

func TestFromRepresentation_UncappedNarrowsNothing(t *testing.T) {
	c, ok := FromRepresentation(repWith(t, map[string]any{PropKey: Props(KindDevice, "uncapped", false, []string{"ignored"})}))
	require.True(t, ok)
	assert.False(t, c.Capped)
	assert.True(t, Keeps([]Constraint{c}, "https://example.com/attr/a/value/any"))
}

func TestFromRepresentation_CappedToNothing(t *testing.T) {
	c, ok := FromRepresentation(repWith(t, map[string]any{PropKey: Props(KindDevice, "unverified", true, nil)}))
	require.True(t, ok)
	assert.True(t, c.Capped)
	assert.False(t, Keeps([]Constraint{c}, "https://example.com/attr/a/value/any"))
}

// A broken marker narrows rather than widens.
func TestFromRepresentation_MalformedFailsClosed(t *testing.T) {
	for name, marker := range map[string]map[string]any{
		"capped not a bool": {"kind": KindDevice, "capped": "no", "allow": []any{"https://example.com/attr/a/value/x"}},
		"capped missing":    {"kind": KindDevice},
		"allow missing":     {"kind": KindDevice, "capped": true},
	} {
		c, ok := FromRepresentation(repWith(t, map[string]any{PropKey: marker}))
		require.True(t, ok, name)
		assert.True(t, c.Capped, name)
		assert.False(t, Keeps([]Constraint{c}, "https://example.com/attr/a/value/y"), name)
	}
}

func TestFromRepresentation_None(t *testing.T) {
	_, ok := FromRepresentation(&entityresolutionV2.EntityRepresentation{})
	assert.False(t, ok)
	_, ok = FromRepresentation(repWith(t, map[string]any{"patreon": map[string]any{}}))
	assert.False(t, ok)
	_, ok = FromRepresentation(repWith(t, map[string]any{PropKey: map[string]any{"capped": true}}))
	assert.False(t, ok, "a marker with no kind is not a constraint")
}

func TestKeeps_IntersectsAndIgnoresCase(t *testing.T) {
	a := Constraint{Capped: true, Allow: map[string]bool{"https://e.com/attr/a/value/x": true, "https://e.com/attr/a/value/y": true}}
	b := Constraint{Capped: true, Allow: map[string]bool{"https://e.com/attr/a/value/x": true}}
	assert.True(t, Keeps([]Constraint{a, b}, "https://E.com/attr/a/value/X"))
	assert.False(t, Keeps([]Constraint{a, b}, "https://e.com/attr/a/value/y"))
	assert.True(t, Keeps(nil, "https://e.com/attr/a/value/z"))
}
