package composite

import (
	"testing"

	"github.com/opentdf/platform/service/entityresolution/source"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const (
	classInternal     = "https://arkavo.ai/attr/classification/value/internal"
	classConfidential = "https://arkavo.ai/attr/classification/value/confidential"
)

func TestDeviceClassSource(t *testing.T) {
	src := newDeviceClassSource(map[string][]string{
		"unverified": {classInternal},
		"managed":    {classInternal, "https://arkavo.ai/attr/classification/value/Confidential"},
	})
	device := func(npe map[string]any) source.Subject {
		claims := map[string]any{}
		if npe != nil {
			claims["arkavo_npe"] = npe
		}
		return source.Subject{Kind: source.KindDevice, Claims: claims}
	}
	fqns := func(res source.Resolution) []string {
		var out []string
		for _, g := range res.Grants {
			out = append(out, g.FQN)
		}
		return out
	}

	t.Run("managed", func(t *testing.T) {
		res, err := src.Resolve(t.Context(), device(map[string]any{"type": "device", "class": "managed"}), source.Query{})
		require.NoError(t, err)
		assert.Equal(t, source.OutcomeComplete, res.Outcome)
		assert.Equal(t, []string{classInternal, classConfidential}, fqns(res), "FQNs come back lowercased")
	})
	t.Run("a missing class is unverified", func(t *testing.T) {
		res, err := src.Resolve(t.Context(), device(map[string]any{"type": "device"}), source.Query{})
		require.NoError(t, err)
		assert.Equal(t, []string{classInternal}, fqns(res))
	})
	t.Run("no claims at all is unverified", func(t *testing.T) {
		res, err := src.Resolve(t.Context(), device(nil), source.Query{})
		require.NoError(t, err)
		assert.Equal(t, []string{classInternal}, fqns(res))
	})
	t.Run("an unlisted class grants nothing", func(t *testing.T) {
		res, err := src.Resolve(t.Context(), device(map[string]any{"type": "device", "class": "attested"}), source.Query{})
		require.NoError(t, err)
		assert.Empty(t, res.Grants)
	})
	for _, kind := range []source.Kind{source.KindPerson, source.KindAgent} {
		t.Run(string(kind)+" subject gets nothing", func(t *testing.T) {
			res, err := src.Resolve(t.Context(), source.Subject{Kind: kind, Claims: map[string]any{"arkavo_npe": map[string]any{"class": "managed"}}}, source.Query{})
			require.NoError(t, err)
			assert.Empty(t, res.Grants)
			assert.Equal(t, source.OutcomeNotApplicable, res.Outcome)
		})
	}
}
