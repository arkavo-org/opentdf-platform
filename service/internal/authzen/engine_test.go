package authzen_test

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/opentdf/platform/service/internal/authzen"
	"github.com/opentdf/platform/service/logger"
	"github.com/opentdf/platform/service/pkg/authz"
)

func testEngine(t *testing.T, cfg authzen.Config) *authzen.Engine {
	t.Helper()
	if cfg.Logger == nil {
		cfg.Logger = logger.CreateTestLogger()
	}
	engine, err := authzen.NewEngine(cfg)
	require.NoError(t, err)
	return engine
}

func endpointRequest(subject authz.Subject, action, resource string) authz.DecisionRequest {
	return authz.DecisionRequest{
		Subject:  subject,
		Action:   authz.Action{Name: action},
		Resource: authz.Resource{Type: authz.ResourceTypeEndpoint, ID: resource},
	}
}

func TestPatternMatch(t *testing.T) {
	tests := []struct {
		value, pattern string
		want           bool
	}{
		{"policy.attributes.List", "*", true},
		{"policy.attributes.List", "policy.*", true},
		{"policy.attributes.List", "policy.attributes.List", true},
		{"policy.attributes.List", "kasregistry.*", false},
		{"policy.attributes.List", "", false},
		{"/access/v1/evaluation", "/access/v1/*", true},
		{"/access/v2/evaluation", "/access/v1/*", false},
		{"policy.attributes.CreateAttribute", "policy.*.Create*", true},
		{"policy.attributes.ListAttributes", "policy.*.Create*", false},
		{"read", "read", true},
		{"write", "read", false},
	}
	for _, tc := range tests {
		require.Equalf(t, tc.want, authzen.PatternMatch(tc.value, tc.pattern),
			"PatternMatch(%q, %q)", tc.value, tc.pattern)
	}
}

func TestActionDerivation(t *testing.T) {
	require.Equal(t, authzen.ActionRead, authzen.ActionForRPC("ListAttributes"))
	require.Equal(t, authzen.ActionRead, authzen.ActionForRPC("GetAttribute"))
	require.Equal(t, authzen.ActionWrite, authzen.ActionForRPC("CreateAttribute"))
	require.Equal(t, authzen.ActionWrite, authzen.ActionForRPC("AssignKeyAccessServer"))
	require.Equal(t, authzen.ActionDelete, authzen.ActionForRPC("DeactivateAttribute"))
	require.Equal(t, authzen.ActionUnsafe, authzen.ActionForRPC("UnsafeDeleteAttribute"))
	require.Equal(t, authzen.ActionOther, authzen.ActionForRPC("Rewrap"))

	require.Equal(t, authzen.ActionRead, authzen.ActionForHTTP(http.MethodGet))
	require.Equal(t, authzen.ActionWrite, authzen.ActionForHTTP(http.MethodPost))
	require.Equal(t, authzen.ActionDelete, authzen.ActionForHTTP(http.MethodDelete))
	require.Equal(t, authzen.ActionUnsafe, authzen.ActionForHTTP("TRACE"))
}

func TestConnectRequestNormalizesProcedure(t *testing.T) {
	req := authzen.ConnectRequest("/policy.attributes.AttributeService/CreateAttribute")
	require.Equal(t, "policy.attributes.AttributeService/CreateAttribute", req.Resource.ID)
	require.Equal(t, authzen.ActionWrite, req.Action.Name)
	require.Equal(t, authz.ResourceTypeEndpoint, req.Resource.Type)
	require.Equal(t, authz.TransportConnect, req.Context.Transport)

	// A procedure that does not split into service and method stays
	// addressable rather than becoming unauthorizable.
	odd := authzen.ConnectRequest("/weird")
	require.Equal(t, "weird", odd.Resource.ID)
}

func TestLegacyPolicyTranslation(t *testing.T) {
	set, err := authzen.ParseGrantSet(strings.Join([]string{
		"# a comment",
		"p, role:admin, *, *, allow",
		"p, role:standard, policy.*, read, allow",
		"p, role:standard, policy.*, write, deny",
		"g, opentdf-admin, role:admin",
		"nonsense line",
	}, "\n"))
	require.NoError(t, err)
	require.Len(t, set.Grants, 3)
	require.Len(t, set.Bindings, 1)
	require.Equal(t, []string{"nonsense line"}, set.SkippedLines)
	require.Equal(t, "admin", set.Bindings[0].Role)
	require.Equal(t, string(authz.EffectDeny), set.Grants[2].Effect)
}

func TestParseGrantSetYAML(t *testing.T) {
	set, err := authzen.ParseGrantSet(`
grants:
  - subjects: ["role:admin"]
    resources: ["*"]
    actions: ["*"]
bindings:
  - subject: platform-admins
    role: admin
`)
	require.NoError(t, err)
	require.Len(t, set.Grants, 1)
	require.Len(t, set.Bindings, 1)
}

func TestBuildGrantSetDefaultBindingsStepAside(t *testing.T) {
	base, err := authzen.BuildGrantSet(authzen.GrantSources{})
	require.NoError(t, err)
	require.NotEmpty(t, base.Bindings)

	withRoleMap, err := authzen.BuildGrantSet(authzen.GrantSources{
		RoleMap: map[string]string{"admin": "corp-admins"},
	})
	require.NoError(t, err)
	require.Len(t, withRoleMap.Bindings, 1)
	require.Equal(t, "corp-admins", withRoleMap.Bindings[0].Subject)
}

func TestEngineDeniesByDefault(t *testing.T) {
	engine := testEngine(t, authzen.Config{})
	decision, err := engine.Decide(context.Background(),
		endpointRequest(authz.Subject{ID: "nobody"}, "read", "policy.attributes.List"))
	require.NoError(t, err)
	require.False(t, decision.Allowed())
	require.Equal(t, authzen.SourceDefault, decision.Source)
}

func TestEngineGrantsPermit(t *testing.T) {
	engine := testEngine(t, authzen.Config{})
	subject := authz.Subject{ID: "someone", Roles: []string{"opentdf-standard"}}

	decision, err := engine.Decide(context.Background(),
		endpointRequest(subject, "read", "policy.attributes.List"))
	require.NoError(t, err)
	require.True(t, decision.Allowed())
	require.Equal(t, authzen.SourceGrants, decision.Source)
}

// fakeEvaluator stands in for the authorization service.
type fakeEvaluator struct {
	decision authz.Decision
	err      error
	seen     authz.DecisionRequest
}

func (f *fakeEvaluator) Evaluate(_ context.Context, req authz.DecisionRequest) (authz.Decision, error) {
	f.seen = req
	return f.decision, f.err
}

func TestEngineEndpointPolicyDisabledByDefault(t *testing.T) {
	evaluator := &fakeEvaluator{decision: authz.Decision{Effect: authz.EffectDeny}}
	registry := authz.NewEvaluatorRegistry()
	registry.Register(evaluator)

	engine := testEngine(t, authzen.Config{Evaluators: registry})
	subject := authz.Subject{ID: "someone", Roles: []string{"opentdf-standard"}}

	decision, err := engine.Decide(context.Background(),
		endpointRequest(subject, "read", "policy.attributes.List"))
	require.NoError(t, err)
	require.True(t, decision.Allowed(), "grants should answer while endpoint policy is off")
	require.Empty(t, evaluator.seen.Resource.ID, "policy must not be consulted for endpoints when disabled")
}

func TestEngineEndpointPolicyGovernsWhenEnabled(t *testing.T) {
	evaluator := &fakeEvaluator{decision: authz.Decision{Effect: authz.EffectDeny, Reason: "policy says no"}}
	registry := authz.NewEvaluatorRegistry()
	registry.Register(evaluator)

	engine := testEngine(t, authzen.Config{
		Evaluators: registry,
		EndpointPolicy: authzen.EndpointPolicyConfig{
			Enabled:   true,
			Namespace: "platform.example.com",
		},
	})
	// An admin the grant table would permit is still denied by policy.
	subject := authz.Subject{ID: "someone", Roles: []string{"opentdf-admin"}}

	decision, err := engine.Decide(context.Background(),
		endpointRequest(subject, "write", "policy.attributes.AttributeService/CreateAttribute"))
	require.NoError(t, err)
	require.False(t, decision.Allowed())
	require.Equal(t, authzen.SourcePolicy, decision.Source)
	require.Equal(t,
		"https://platform.example.com/reg_res/endpoint/value/policy_attributes_attributeservice_createattribute",
		evaluator.seen.Resource.FQN,
	)
}

func TestEngineFallsBackToGrantsWhenPolicyAbstains(t *testing.T) {
	evaluator := &fakeEvaluator{decision: authz.Decision{Effect: authz.EffectAbstain}}
	registry := authz.NewEvaluatorRegistry()
	registry.Register(evaluator)

	engine := testEngine(t, authzen.Config{
		Evaluators: registry,
		EndpointPolicy: authzen.EndpointPolicyConfig{
			Enabled:   true,
			Namespace: "platform.example.com",
		},
	})
	subject := authz.Subject{ID: "someone", Roles: []string{"opentdf-admin"}}

	decision, err := engine.Decide(context.Background(),
		endpointRequest(subject, "write", "policy.attributes.AttributeService/CreateAttribute"))
	require.NoError(t, err)
	require.True(t, decision.Allowed())
	require.Equal(t, authzen.SourceGrants, decision.Source)
}

func TestEngineFailsClosedOnPolicyError(t *testing.T) {
	evaluator := &fakeEvaluator{err: errors.New("policy unavailable")}
	registry := authz.NewEvaluatorRegistry()
	registry.Register(evaluator)

	engine := testEngine(t, authzen.Config{
		Evaluators: registry,
		EndpointPolicy: authzen.EndpointPolicyConfig{
			Enabled:   true,
			Namespace: "platform.example.com",
		},
	})
	subject := authz.Subject{ID: "someone", Roles: []string{"opentdf-admin"}}

	decision, err := engine.Decide(context.Background(),
		endpointRequest(subject, "write", "policy.attributes.AttributeService/CreateAttribute"))
	require.Error(t, err)
	require.False(t, decision.Allowed())
}

// Data resources always reach policy, whether or not endpoints do.
func TestEngineRoutesDataResourcesToPolicy(t *testing.T) {
	evaluator := &fakeEvaluator{decision: authz.Decision{
		Effect:      authz.EffectPermit,
		Obligations: []string{"https://example.com/obl/watermark/value/on"},
	}}
	registry := authz.NewEvaluatorRegistry()
	registry.Register(evaluator)

	engine := testEngine(t, authzen.Config{Evaluators: registry})

	decision, err := engine.Decide(context.Background(), authz.DecisionRequest{
		Subject: authz.Subject{ID: "someone"},
		Action:  authz.Action{Name: "read"},
		Resource: authz.Resource{
			Type:               authz.ResourceTypeAttributeValues,
			AttributeValueFQNs: []string{"https://example.com/attr/classification/value/secret"},
		},
	})
	require.NoError(t, err)
	require.True(t, decision.Allowed())
	require.Equal(t, authzen.SourcePolicy, decision.Source)
	require.Len(t, decision.Obligations, 1)
}

func TestSanitizePolicyName(t *testing.T) {
	require.Equal(t, "policy_attributes_attributeservice_createattribute",
		authzen.SanitizePolicyName("policy.attributes.AttributeService/CreateAttribute"))
	require.Equal(t, "access_v1_evaluation", authzen.SanitizePolicyName("/access/v1/evaluation"))
	require.Empty(t, authzen.SanitizePolicyName("///"))
}

func TestEngineRequiresNamespaceForEndpointPolicy(t *testing.T) {
	_, err := authzen.NewEngine(authzen.Config{
		Logger:         logger.CreateTestLogger(),
		EndpointPolicy: authzen.EndpointPolicyConfig{Enabled: true},
	})
	require.Error(t, err)
}

// The AuthZEN endpoint is a thin adapter over the same engine: it must not
// let a caller assert what a subject is entitled to.
func TestAuthZENEvaluationEndpoint(t *testing.T) {
	engine := testEngine(t, authzen.Config{})
	caller := authz.Subject{ID: "admin-user", Roles: []string{"opentdf-admin"}}
	api := authzen.NewAPI(engine, func(context.Context) (authz.Subject, error) { return caller, nil }, logger.CreateTestLogger())

	mux := http.NewServeMux()
	api.Mount(mux)

	// The caller asking about itself is answered with its own roles.
	body := `{"subject":{"type":"user","id":"admin-user"},"action":{"name":"write"},"resource":{"type":"endpoint","id":"policy.attributes.AttributeService/CreateAttribute"}}`
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, authzen.EvaluationPath, strings.NewReader(body)))
	require.Equal(t, http.StatusOK, rec.Code)

	var decision struct {
		Decision bool           `json:"decision"`
		Context  map[string]any `json:"context"`
	}
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &decision))
	require.True(t, decision.Decision)
	require.Equal(t, authzen.SourceGrants, decision.Context["source"])

	// A question about somebody else does not inherit the caller's roles.
	other := `{"subject":{"type":"user","id":"someone-else"},"action":{"name":"write"},"resource":{"type":"endpoint","id":"policy.attributes.AttributeService/CreateAttribute"}}`
	rec = httptest.NewRecorder()
	mux.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, authzen.EvaluationPath, strings.NewReader(other)))
	require.Equal(t, http.StatusOK, rec.Code)
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &decision))
	require.False(t, decision.Decision)
}

func TestAuthZENBatchEvaluation(t *testing.T) {
	engine := testEngine(t, authzen.Config{})
	caller := authz.Subject{ID: "standard-user", Roles: []string{"opentdf-standard"}}
	api := authzen.NewAPI(engine, func(context.Context) (authz.Subject, error) { return caller, nil }, logger.CreateTestLogger())

	mux := http.NewServeMux()
	api.Mount(mux)

	body := `{
	  "subject": {"type":"user","id":"standard-user"},
	  "resource": {"type":"endpoint","id":"policy.attributes.AttributeService/ListAttributes"},
	  "evaluations": [
	    {"action":{"name":"read"}},
	    {"action":{"name":"write"}}
	  ]
	}`
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, authzen.EvaluationsPath, strings.NewReader(body)))
	require.Equal(t, http.StatusOK, rec.Code)

	var out struct {
		Evaluations []struct {
			Decision bool `json:"decision"`
		} `json:"evaluations"`
	}
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &out))
	require.Len(t, out.Evaluations, 2)
	require.True(t, out.Evaluations[0].Decision)
	require.False(t, out.Evaluations[1].Decision)
}

func TestAuthZENRejectsBadRequests(t *testing.T) {
	engine := testEngine(t, authzen.Config{})
	api := authzen.NewAPI(engine, func(context.Context) (authz.Subject, error) { return authz.Subject{}, nil }, logger.CreateTestLogger())
	mux := http.NewServeMux()
	api.Mount(mux)

	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, authzen.EvaluationPath, nil))
	require.Equal(t, http.StatusMethodNotAllowed, rec.Code)

	rec = httptest.NewRecorder()
	mux.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, authzen.EvaluationPath, strings.NewReader("{")))
	require.Equal(t, http.StatusBadRequest, rec.Code)

	rec = httptest.NewRecorder()
	mux.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, authzen.EvaluationPath, strings.NewReader(`{"resource":{"id":"x"}}`)))
	require.Equal(t, http.StatusBadRequest, rec.Code)
}

func TestEvaluatorRegistryAbstainsWhenEmpty(t *testing.T) {
	registry := authz.NewEvaluatorRegistry()
	decision, err := registry.Evaluate(context.Background(), authz.DecisionRequest{})
	require.NoError(t, err)
	require.Equal(t, authz.EffectAbstain, decision.Effect)
}

// sessionEvaluator records how many times it had to build its per-request
// state, so a batch that shares one session is visible as one build.
type sessionEvaluator struct {
	builds    int
	decisions int
}

type sessionEvaluatorKey struct{}

func (e *sessionEvaluator) Evaluate(ctx context.Context, _ authz.DecisionRequest) (authz.Decision, error) {
	e.decisions++
	session := authz.SessionFromContext(ctx)
	if session == nil {
		return authz.Decision{}, errors.New("no decision session on the context")
	}
	if _, err := session.Do(sessionEvaluatorKey{}, func() (any, error) {
		e.builds++
		return struct{}{}, nil
	}); err != nil {
		return authz.Decision{}, err
	}
	return authz.Decision{Effect: authz.EffectPermit}, nil
}

func dataEvaluationsBody(count int) string {
	items := make([]string, 0, count)
	for range count {
		items = append(items, `{"action":{"name":"read"}}`)
	}
	return `{
	  "resource": {"type":"attribute_values","id":"tdf-1","properties":{"attribute_value_fqns":["https://example.com/attr/classification/value/secret"]}},
	  "evaluations": [` + strings.Join(items, ",") + `]
	}`
}

// A batch asks many questions; the evaluator should only assemble its
// policy state once for the whole request.
func TestAuthZENBatchSharesOneSession(t *testing.T) {
	evaluator := &sessionEvaluator{}
	registry := authz.NewEvaluatorRegistry()
	registry.Register(evaluator)

	engine := testEngine(t, authzen.Config{Evaluators: registry})
	api := authzen.NewAPI(engine, func(context.Context) (authz.Subject, error) {
		return authz.Subject{ID: "someone"}, nil
	}, logger.CreateTestLogger())
	mux := http.NewServeMux()
	api.Mount(mux)

	const items = 25
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, authzen.EvaluationsPath, strings.NewReader(dataEvaluationsBody(items))))
	require.Equal(t, http.StatusOK, rec.Code)

	require.Equal(t, items, evaluator.decisions)
	require.Equal(t, 1, evaluator.builds, "a batch must assemble policy state once, not once per item")

	// A second request is a second session, and so a second build: a
	// session is request-scoped, never a cache.
	rec = httptest.NewRecorder()
	mux.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, authzen.EvaluationsPath, strings.NewReader(dataEvaluationsBody(1))))
	require.Equal(t, http.StatusOK, rec.Code)
	require.Equal(t, 2, evaluator.builds)
}

// One unanswerable item denies that item; the rest of the batch is still
// answered, as the AuthZEN batch contract expects.
type flakyEvaluator struct{ calls int }

// failOnCall is the 1-based item the evaluator refuses to answer.
const failOnCall = 2

func (e *flakyEvaluator) Evaluate(context.Context, authz.DecisionRequest) (authz.Decision, error) {
	e.calls++
	if e.calls == failOnCall {
		return authz.Decision{}, errors.New("policy unavailable")
	}
	return authz.Decision{Effect: authz.EffectPermit}, nil
}

func TestAuthZENBatchSurvivesOneFailingItem(t *testing.T) {
	registry := authz.NewEvaluatorRegistry()
	registry.Register(&flakyEvaluator{})

	engine := testEngine(t, authzen.Config{Evaluators: registry})
	api := authzen.NewAPI(engine, func(context.Context) (authz.Subject, error) {
		return authz.Subject{ID: "someone"}, nil
	}, logger.CreateTestLogger())
	mux := http.NewServeMux()
	api.Mount(mux)

	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, authzen.EvaluationsPath, strings.NewReader(dataEvaluationsBody(3))))
	require.Equal(t, http.StatusOK, rec.Code)

	var out struct {
		Evaluations []struct {
			Decision bool           `json:"decision"`
			Context  map[string]any `json:"context"`
		} `json:"evaluations"`
	}
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &out))
	require.Len(t, out.Evaluations, 3)
	require.True(t, out.Evaluations[0].Decision)
	require.False(t, out.Evaluations[1].Decision)
	require.Equal(t, true, out.Evaluations[1].Context["error"])
	require.True(t, out.Evaluations[2].Decision)
}

// A malformed item is the caller's to fix, so the batch says so rather than
// handing back a denial they might act on.
func TestAuthZENBatchRejectsMalformedItem(t *testing.T) {
	engine := testEngine(t, authzen.Config{})
	api := authzen.NewAPI(engine, func(context.Context) (authz.Subject, error) {
		return authz.Subject{ID: "someone"}, nil
	}, logger.CreateTestLogger())
	mux := http.NewServeMux()
	api.Mount(mux)

	body := `{"resource":{"type":"endpoint","id":"policy.attributes.List"},"evaluations":[{"action":{"name":"read"}},{}]}`
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, authzen.EvaluationsPath, strings.NewReader(body)))
	require.Equal(t, http.StatusBadRequest, rec.Code)
	require.Contains(t, rec.Body.String(), "evaluations[1]")
}

// A caller whose subject cannot be resolved is an outage, not a denial.
func TestAuthZENReportsCallerResolutionFailure(t *testing.T) {
	engine := testEngine(t, authzen.Config{})
	api := authzen.NewAPI(engine, func(context.Context) (authz.Subject, error) {
		return authz.Subject{}, errors.New("role provider unreachable")
	}, logger.CreateTestLogger())
	mux := http.NewServeMux()
	api.Mount(mux)

	body := `{"action":{"name":"read"},"resource":{"type":"endpoint","id":"policy.attributes.List"}}`
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, authzen.EvaluationPath, strings.NewReader(body)))
	require.Equal(t, http.StatusInternalServerError, rec.Code)
}

func TestSessionBuildsOnce(t *testing.T) {
	session := authz.NewSession()
	builds := 0
	build := func() (any, error) {
		builds++
		return "value", nil
	}

	for range 3 {
		v, err := session.Do(sessionEvaluatorKey{}, build)
		require.NoError(t, err)
		require.Equal(t, "value", v)
	}
	require.Equal(t, 1, builds)
}

func TestSessionRemembersFailure(t *testing.T) {
	session := authz.NewSession()
	builds := 0
	build := func() (any, error) {
		builds++
		return nil, errors.New("cannot build")
	}

	for range 3 {
		_, err := session.Do(sessionEvaluatorKey{}, build)
		require.Error(t, err)
	}
	require.Equal(t, 1, builds, "a failed build is not retried for every question in the request")
}

// Without a session, Do still answers: an enforcement point that asks one
// question need not establish one.
func TestNilSessionStillBuilds(t *testing.T) {
	var session *authz.Session
	v, err := session.Do(sessionEvaluatorKey{}, func() (any, error) { return 42, nil })
	require.NoError(t, err)
	require.Equal(t, 42, v)
	require.Nil(t, authz.SessionFromContext(context.Background()))
}
