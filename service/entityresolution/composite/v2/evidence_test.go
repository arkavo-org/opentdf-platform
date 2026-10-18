package composite

import (
	"strings"
	"testing"
	"time"

	"github.com/opentdf/platform/service/entityresolution/source"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/types/known/structpb"
)

var (
	evidenceKey     = []byte("0123456789abcdef0123456789abcdef")
	evidenceOldKey  = []byte("fedcba9876543210fedcba9876543210")
	evidenceOtherKy = []byte("ffffffffffffffffffffffffffffffff")
	evidenceNow     = time.Unix(1_800_000_000, 0)
)

func testEvidence() evidence {
	return evidence{
		V:   1,
		Sub: "acct-1",
		Exp: evidenceNow.Add(time.Hour).Unix(),
		Grants: []sealedGrant{
			{FQN: "https://patreon.arkavo.com/attr/campaign/value/123", Actions: []string{"read"}, Source: "patreon"},
			{FQN: "https://patreon.arkavo.com/attr/campaign-tier/value/123_gold", Actions: []string{"read", "publish"}, Source: "patreon", Exp: evidenceNow.Add(time.Minute).Unix()},
		},
		Props: map[string]map[string]any{
			"patreon": {"tier": "gold", "active": true},
		},
		Outcomes: map[string]source.Outcome{
			"_token":  source.OutcomeComplete,
			"patreon": source.OutcomeComplete,
			"other":   source.OutcomeUnavailable,
		},
	}
}

func TestEvidence_RoundTrip(t *testing.T) {
	want := testEvidence()
	sealed, err := sealEvidence(evidenceKey, want)
	require.NoError(t, err)

	got, err := openEvidence([][]byte{evidenceKey}, sealed, evidenceNow)
	require.NoError(t, err)
	assert.Equal(t, want, got)
}

func TestEvidence_Encoding(t *testing.T) {
	sealed, err := sealEvidence(evidenceKey, testEvidence())
	require.NoError(t, err)
	assert.Equal(t, 1, strings.Count(sealed, "."))
	assert.NotContains(t, sealed, "=")
}

func TestEvidence_SealNeedsKey(t *testing.T) {
	_, err := sealEvidence(nil, testEvidence())
	require.Error(t, err)
}

func TestEvidence_OpenNeedsKeys(t *testing.T) {
	sealed, err := sealEvidence(evidenceKey, testEvidence())
	require.NoError(t, err)
	_, err = openEvidence(nil, sealed, evidenceNow)
	require.Error(t, err)
}

func TestEvidence_TamperedPayloadRejected(t *testing.T) {
	e := testEvidence()
	sealed, err := sealEvidence(evidenceKey, e)
	require.NoError(t, err)

	forged := testEvidence()
	forged.Grants = append(forged.Grants, sealedGrant{FQN: "https://patreon.arkavo.com/attr/campaign/value/999", Actions: []string{"read"}, Source: "patreon"})
	forgedSealed, err := sealEvidence(evidenceOtherKy, forged)
	require.NoError(t, err)

	// A payload from another seal paired with this seal's MAC.
	payload, _, _ := strings.Cut(forgedSealed, ".")
	_, mac, _ := strings.Cut(sealed, ".")
	_, err = openEvidence([][]byte{evidenceKey}, payload+"."+mac, evidenceNow)
	require.Error(t, err)

	// One flipped payload character.
	p, m, _ := strings.Cut(sealed, ".")
	flipped := []byte(p)
	if flipped[10] == 'A' {
		flipped[10] = 'B'
	} else {
		flipped[10] = 'A'
	}
	_, err = openEvidence([][]byte{evidenceKey}, string(flipped)+"."+m, evidenceNow)
	require.Error(t, err)
}

func TestEvidence_WrongKeyRejected(t *testing.T) {
	sealed, err := sealEvidence(evidenceKey, testEvidence())
	require.NoError(t, err)
	_, err = openEvidence([][]byte{evidenceOtherKy}, sealed, evidenceNow)
	require.Error(t, err)
}

func TestEvidence_PreviousKeyStillOpens(t *testing.T) {
	sealed, err := sealEvidence(evidenceOldKey, testEvidence())
	require.NoError(t, err)
	got, err := openEvidence([][]byte{evidenceKey, evidenceOldKey}, sealed, evidenceNow)
	require.NoError(t, err)
	assert.Equal(t, "acct-1", got.Sub)
}

func TestEvidence_ExpiredRejected(t *testing.T) {
	e := testEvidence()
	e.Exp = evidenceNow.Unix() // Exp <= now is expired
	sealed, err := sealEvidence(evidenceKey, e)
	require.NoError(t, err)
	_, err = openEvidence([][]byte{evidenceKey}, sealed, evidenceNow)
	require.Error(t, err)

	_, err = openEvidence([][]byte{evidenceKey}, sealed, evidenceNow.Add(-time.Second))
	require.NoError(t, err)
}

func TestEvidence_ExpiredGrantDropped(t *testing.T) {
	sealed, err := sealEvidence(evidenceKey, testEvidence())
	require.NoError(t, err)

	// The second grant expires at now+1m; at now+1m it is dropped, the first stays.
	got, err := openEvidence([][]byte{evidenceKey}, sealed, evidenceNow.Add(time.Minute))
	require.NoError(t, err)
	require.Len(t, got.Grants, 1)
	assert.Equal(t, "https://patreon.arkavo.com/attr/campaign/value/123", got.Grants[0].FQN)
}

func TestEvidence_UnsupportedVersionRejected(t *testing.T) {
	e := testEvidence()
	e.V = 2
	sealed, err := sealEvidence(evidenceKey, e)
	require.NoError(t, err)
	_, err = openEvidence([][]byte{evidenceKey}, sealed, evidenceNow)
	require.Error(t, err)
}

func TestEvidence_MalformedRejected(t *testing.T) {
	for name, in := range map[string]string{
		"empty":          "",
		"no separator":   "abcdef",
		"bad base64":     "!!!.!!!",
		"two separators": "a.b.c",
		"empty parts":    ".",
	} {
		t.Run(name, func(t *testing.T) {
			_, err := openEvidence([][]byte{evidenceKey}, in, evidenceNow)
			require.Error(t, err)
		})
	}
}

func TestEvidence_BadJSONUnderValidMACRejected(t *testing.T) {
	// A correctly MACed payload that is not JSON: sealed by hand through the
	// same primitive, so only the JSON step can reject it.
	sealed := sealRaw(evidenceKey, []byte("not json"))
	_, err := openEvidence([][]byte{evidenceKey}, sealed, evidenceNow)
	require.Error(t, err)
}

func TestEvidence_SurvivesStructpb(t *testing.T) {
	sealed, err := sealEvidence(evidenceKey, testEvidence())
	require.NoError(t, err)

	s, err := structpb.NewStruct(map[string]any{evidenceClaim: sealed})
	require.NoError(t, err)
	back, ok := s.AsMap()[evidenceClaim].(string)
	require.True(t, ok)

	got, err := openEvidence([][]byte{evidenceKey}, back, evidenceNow)
	require.NoError(t, err)
	assert.Equal(t, testEvidence(), got)
}
