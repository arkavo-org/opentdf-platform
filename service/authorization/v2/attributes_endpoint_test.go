package authorization

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/opentdf/platform/service/policy/filestore"
)

func attributesTestServer(t *testing.T) *httptest.Server {
	t.Helper()
	store, err := filestore.NewStoreFromFile("../../../examples/config/policy.patreon.yaml")
	require.NoError(t, err, "example policy snapshot must load")

	endpoint, err := NewAttributesEndpoint(store)
	require.NoError(t, err)

	mux := http.NewServeMux()
	endpoint.Mount(mux)
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return srv
}

func getJSON(t *testing.T, url string) (int, map[string]any) {
	t.Helper()
	resp, err := http.Get(url)
	require.NoError(t, err)
	defer resp.Body.Close()
	out := map[string]any{}
	if resp.StatusCode == http.StatusOK {
		require.NoError(t, json.NewDecoder(resp.Body).Decode(&out))
		require.Contains(t, resp.Header.Get("Cache-Control"), "max-age")
	}
	return resp.StatusCode, out
}

func TestAttributesEndpoint_ListServesSnapshotDefinitions(t *testing.T) {
	srv := attributesTestServer(t)

	status, body := getJSON(t, srv.URL+"/attributes")
	require.Equal(t, http.StatusOK, status)
	attrs, ok := body["attributes"].([]any)
	require.True(t, ok, "attributes array expected: %v", body)
	require.NotEmpty(t, attrs)

	// Every definition carries a dereferenceable FQN.
	fqns := map[string]bool{}
	for _, a := range attrs {
		attr, isMap := a.(map[string]any)
		require.True(t, isMap)
		fqn, _ := attr["fqn"].(string)
		require.NotEmpty(t, fqn, "attribute missing fqn: %v", attr)
		fqns[fqn] = true
	}
	require.True(t, fqns["https://patreon.arkavo.com/attr/classification"], "classification fqn missing: %v", fqns)
	require.True(t, fqns["https://patreon.arkavo.com/attr/campaign"])
}

func TestAttributesEndpoint_FQNPathsDereference(t *testing.T) {
	srv := attributesTestServer(t)

	// The path component of an attribute FQN resolves to its definition.
	status, attr := getJSON(t, srv.URL+"/attr/classification")
	require.Equal(t, http.StatusOK, status)
	require.Equal(t, "https://patreon.arkavo.com/attr/classification", attr["fqn"])
	require.Contains(t, attr["rule"], "HIERARCHY")

	// And a value FQN path resolves to the value.
	status, value := getJSON(t, srv.URL+"/attr/classification/value/member")
	require.Equal(t, http.StatusOK, status)
	require.Equal(t, "https://patreon.arkavo.com/attr/classification/value/member", value["fqn"])

	status, _ = getJSON(t, srv.URL+"/attr/classification/value/nonexistent")
	require.Equal(t, http.StatusNotFound, status)

	status, _ = getJSON(t, srv.URL+"/attr/no-such-attribute")
	require.Equal(t, http.StatusNotFound, status)
}
