package composite

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	patreon "github.com/opentdf/platform/service/entityresolution/patreon/v2"
	"github.com/opentdf/platform/service/internal/identityentities"
	"github.com/stretchr/testify/require"
)

// fakeEntities is identity's token endpoint and GET /entities. Each account
// backs the campaigns in backs; down makes every lookup a 503
// patreon_unavailable.
type fakeEntities struct {
	backs map[string]string // account id -> campaign
	down  atomic.Bool
}

func (f *fakeEntities) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path == "/oauth/token" {
		_ = json.NewEncoder(w).Encode(map[string]any{"access_token": "svc", "expires_in": 3600})
		return
	}
	if r.Header.Get("X-Auth-Token") != "svc" {
		w.WriteHeader(http.StatusUnauthorized)
		return
	}
	if f.down.Load() {
		w.WriteHeader(http.StatusServiceUnavailable)
		_, _ = w.Write([]byte(`{"error":"patreon_unavailable"}`))
		return
	}
	account := strings.TrimPrefix(r.URL.Path, "/entities/arkavo:")
	campaign, known := f.backs[account]
	if !known {
		w.WriteHeader(http.StatusNotFound)
		_, _ = w.Write([]byte("Entity not found"))
		return
	}
	_ = json.NewEncoder(w).Encode(map[string]any{"id": "arkavo:" + account, "claims": patronOf(account, campaign, "supporter")})
}

// TestPatreonIdentity_ThroughTheV2PDP decides campaign content from
// identity's answer, on the KAS route and the catalog route, and keeps
// deciding from the last answer while identity is down.
func TestPatreonIdentity_ThroughTheV2PDP(t *testing.T) {
	identity := &fakeEntities{backs: map[string]string{identityAccount: "13167240"}}
	srv := httptest.NewServer(identity)
	t.Cleanup(srv.Close)
	client, err := identityentities.New(identityentities.Config{
		URL: srv.URL, ClientID: "opentdf-platform", ClientSecret: "s3cret", CacheTTL: time.Millisecond,
	})
	require.NoError(t, err)

	sc := SourceConfig{
		ID: "patreon", Type: typePatreonIdentity, Issuer: testIssuer,
		Grants: []string{campaignDef, tierDef}, PEPAssertable: true, PropertiesKey: "patreon",
		Deadline: 2 * time.Second,
	}
	src := newPatreonIdentitySource(patreon.NewTokenSource(patreon.SourceConfig{InferUnknownAsFree: true}), client, serveIdentity, testLogger(t))
	cs := sourceOf(sc, src)
	cs.deadline = sc.Deadline
	svc := newTestService(t, pepConfig(), verifiersFor(&fakeVerifier{}), []configuredSource{cs}, nil)
	pdp := pdpFor(t, svc, patreonPolicy)
	content := []string{creatorCampaign, creatorSupporter}

	// The token carries no Patreon data at all: only identity knows.
	claims := map[string]any{"iss": testIssuer, "sub": "arkavo:" + identityAccount, "arkavo_account_id": identityAccount}
	viaToken := func(t *testing.T) bool {
		t.Helper()
		signed := map[string]any{"exp": time.Now().Add(time.Hour)}
		for k, v := range claims {
			signed[k] = v
		}
		return permitted(t, pdp, "arks-media", tokenIdentifier(signCWT(t, signed)), content...)
	}
	viaCatalog := func(t *testing.T) bool {
		t.Helper()
		return permitted(t, pdp, testPEP, chainIdentifier(claimsEntity(t, "catalog-subject", claims)), content...)
	}

	t.Run("KAS route: identity's campaign is permitted", func(t *testing.T) {
		require.True(t, viaToken(t))
	})
	t.Run("catalog route: identity's campaign is permitted", func(t *testing.T) {
		require.True(t, viaCatalog(t))
	})
	t.Run("identity down: the last answer still decides", func(t *testing.T) {
		identity.down.Store(true)
		t.Cleanup(func() { identity.down.Store(false) })
		time.Sleep(5 * time.Millisecond) // past cache_ttl, so identity is asked
		require.True(t, viaToken(t))
		require.True(t, viaCatalog(t))
	})
	t.Run("an account identity does not know is denied", func(t *testing.T) {
		stranger := "00000000-0000-0000-0000-0000000000aa"
		signed := map[string]any{"iss": testIssuer, "sub": "arkavo:" + stranger, "arkavo_account_id": stranger, "exp": time.Now().Add(time.Hour)}
		require.False(t, permitted(t, pdp, "arks-media", tokenIdentifier(signCWT(t, signed)), content...))
	})
}
