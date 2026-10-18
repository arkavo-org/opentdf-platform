package composite

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/opentdf/platform/service/entityresolution/source"
)

// evidenceClaim is the claim a sealed evidence travels in between the two ERS
// calls. Its value is an opaque string, so it survives structpb untouched.
const evidenceClaim = "arkavo_evidence"

const (
	evidenceVersion = 1
	// evidenceMACDomain separates evidence MACs from any other use of a seal key.
	evidenceMACDomain = "arkavo-evidence-v1"
)

// evidence is what the token route resolved for one verified token. The token
// route seals it and the entity route opens it, so only a key the ERS holds can
// have produced the grants it carries.
type evidence struct {
	V   int    `json:"v"`
	Sub string `json:"sub"`
	// Exp is unix seconds and never later than the token's own exp.
	Exp    int64         `json:"exp"`
	Grants []sealedGrant `json:"grants"`
	// Props maps properties_key to properties.
	Props map[string]map[string]any `json:"props"`
	// Outcomes maps a source id to its outcome; "_token" is the token itself.
	Outcomes map[string]source.Outcome `json:"outcomes"`
}

type sealedGrant struct {
	FQN     string   `json:"fqn"`
	Actions []string `json:"actions"`
	Source  string   `json:"source"`
	Exp     int64    `json:"exp,omitempty"`
}

var (
	errEvidenceMalformed = errors.New("evidence is malformed")
	errEvidenceUntrusted = errors.New("evidence was not sealed by a known key")
)

// sealEvidence returns base64url(payload JSON) "." base64url(MAC).
func sealEvidence(key []byte, e evidence) (string, error) {
	if len(key) == 0 {
		return "", errors.New("evidence seal key is empty")
	}
	payload, err := json.Marshal(e)
	if err != nil {
		return "", fmt.Errorf("marshal evidence: %w", err)
	}
	return sealRaw(key, payload), nil
}

func sealRaw(key, payload []byte) string {
	enc := base64.RawURLEncoding
	return enc.EncodeToString(payload) + "." + enc.EncodeToString(evidenceMAC(key, payload))
}

func evidenceMAC(key, payload []byte) []byte {
	m := hmac.New(sha256.New, key)
	m.Write([]byte(evidenceMACDomain))
	m.Write([]byte{0})
	m.Write(payload)
	return m.Sum(nil)
}

// openEvidence verifies sealed against every key, then parses it. The MAC is
// checked before the payload is parsed. It rejects an unknown version and an
// expired evidence, and drops grants whose own expiry has passed.
func openEvidence(keys [][]byte, sealed string, now time.Time) (evidence, error) {
	if len(keys) == 0 {
		return evidence{}, errors.New("no evidence seal keys configured")
	}
	encPayload, encMAC, ok := strings.Cut(sealed, ".")
	if !ok || encPayload == "" || encMAC == "" || strings.Contains(encMAC, ".") {
		return evidence{}, errEvidenceMalformed
	}
	enc := base64.RawURLEncoding
	payload, err := enc.DecodeString(encPayload)
	if err != nil {
		return evidence{}, errEvidenceMalformed
	}
	mac, err := enc.DecodeString(encMAC)
	if err != nil {
		return evidence{}, errEvidenceMalformed
	}

	// Try every key even after a match, so timing does not reveal which one.
	trusted := false
	for _, key := range keys {
		if len(key) > 0 && hmac.Equal(mac, evidenceMAC(key, payload)) {
			trusted = true
		}
	}
	if !trusted {
		return evidence{}, errEvidenceUntrusted
	}

	var e evidence
	if err := json.Unmarshal(payload, &e); err != nil {
		return evidence{}, fmt.Errorf("%w: %w", errEvidenceMalformed, err)
	}
	if e.V != evidenceVersion {
		return evidence{}, fmt.Errorf("unsupported evidence version %d", e.V)
	}
	nowUnix := now.Unix()
	if e.Exp <= nowUnix {
		return evidence{}, errors.New("evidence has expired")
	}
	kept := e.Grants[:0]
	for _, g := range e.Grants {
		if g.Exp != 0 && g.Exp <= nowUnix {
			continue
		}
		kept = append(kept, g)
	}
	e.Grants = kept
	return e, nil
}
