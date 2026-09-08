package authzen

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"

	"github.com/opentdf/platform/service/logger"
	"github.com/opentdf/platform/service/pkg/authz"
)

// Routes of the AuthZEN Authorization API 1.0 evaluation endpoints.
const (
	EvaluationPath  = "/access/v1/evaluation"
	EvaluationsPath = "/access/v1/evaluations"

	maxEvaluationBodyBytes = 1 << 20 // 1 MiB
	maxBatchEvaluations    = 100
)

// ErrInvalidRequest marks an AuthZEN request the endpoint cannot evaluate.
var ErrInvalidRequest = errors.New("invalid evaluation request")

// API exposes the engine over the AuthZEN Authorization API. It is the
// public contract for the same in-process PDP the platform's own policy
// enforcement points call: no request is authorized by looping back through
// this endpoint.
type API struct {
	pdp    authz.PDP
	logger *logger.Logger
	// callerSubject resolves the authenticated caller from the request
	// context. Supplied by the authentication layer. It fails when the
	// caller's subject cannot be resolved — a degraded role provider, say —
	// which is an outage, not a denial.
	callerSubject func(ctx context.Context) (authz.Subject, error)
}

// NewAPI builds the AuthZEN endpoint handler.
func NewAPI(pdp authz.PDP, callerSubject func(ctx context.Context) (authz.Subject, error), log *logger.Logger) *API {
	return &API{pdp: pdp, callerSubject: callerSubject, logger: log}
}

// Mount registers the AuthZEN routes on a mux.
func (a *API) Mount(mux *http.ServeMux) {
	mux.HandleFunc(EvaluationPath, a.handleEvaluation)
	mux.HandleFunc(EvaluationsPath, a.handleEvaluations)
}

// apiSubject is the AuthZEN subject object.
type apiSubject struct {
	Type       string         `json:"type"`
	ID         string         `json:"id"`
	Properties map[string]any `json:"properties,omitempty"`
}

// apiResource is the AuthZEN resource object.
type apiResource struct {
	Type       string         `json:"type"`
	ID         string         `json:"id"`
	Properties map[string]any `json:"properties,omitempty"`
}

// apiAction is the AuthZEN action object.
type apiAction struct {
	Name       string         `json:"name"`
	Properties map[string]any `json:"properties,omitempty"`
}

type evaluationRequest struct {
	Subject  *apiSubject    `json:"subject"`
	Action   *apiAction     `json:"action"`
	Resource *apiResource   `json:"resource"`
	Context  map[string]any `json:"context,omitempty"`
}

type evaluationsRequest struct {
	Subject     *apiSubject         `json:"subject"`
	Action      *apiAction          `json:"action"`
	Resource    *apiResource        `json:"resource"`
	Context     map[string]any      `json:"context,omitempty"`
	Evaluations []evaluationRequest `json:"evaluations"`
}

type evaluationResponse struct {
	Decision bool           `json:"decision"`
	Context  map[string]any `json:"context,omitempty"`
}

type evaluationsResponse struct {
	Evaluations []evaluationResponse `json:"evaluations"`
}

func (a *API) handleEvaluation(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	var body evaluationRequest
	if err := decodeJSON(w, r, &body); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}

	ctx := authz.ContextWithSession(r.Context(), authz.NewSession())
	caller, err := a.caller(ctx)
	if err != nil {
		a.writeEvaluationError(w, r, err)
		return
	}

	decision, err := a.evaluate(ctx, caller, body, evaluationRequest{})
	if err != nil {
		a.writeEvaluationError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, decisionResponse(decision))
}

func (a *API) handleEvaluations(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	var body evaluationsRequest
	if err := decodeJSON(w, r, &body); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	if len(body.Evaluations) == 0 {
		writeError(w, http.StatusBadRequest, "evaluations must not be empty")
		return
	}
	if len(body.Evaluations) > maxBatchEvaluations {
		writeError(w, http.StatusBadRequest, "too many evaluations in one request")
		return
	}

	defaults := evaluationRequest{
		Subject:  body.Subject,
		Action:   body.Action,
		Resource: body.Resource,
		Context:  body.Context,
	}
	// One session for the whole batch: the evaluator assembles the policy
	// graph once and answers every item from it.
	ctx := authz.ContextWithSession(r.Context(), authz.NewSession())

	// Who is asking is a property of the request, not of any one item, so
	// it is resolved once. A caller the platform cannot resolve is a
	// request-wide outage; reporting it as N denials would hide it in the
	// very denial rate the distinction exists to keep it out of.
	caller, err := a.caller(ctx)
	if err != nil {
		a.writeEvaluationError(w, r, err)
		return
	}

	out := evaluationsResponse{Evaluations: make([]evaluationResponse, 0, len(body.Evaluations))}
	for i, item := range body.Evaluations {
		decision, err := a.evaluate(ctx, caller, item, defaults)
		switch {
		case errors.Is(err, ErrInvalidRequest):
			// The request is malformed rather than unanswerable, and the
			// caller can fix it. Say so for the batch rather than
			// returning a deny they might act on.
			writeError(w, http.StatusBadRequest, fmt.Sprintf("evaluations[%d]: %s", i, err.Error()))
			return
		case err != nil:
			// One item the PDP could not answer denies that item and is
			// reported in its own result. The rest of the batch still gets
			// answered, as the AuthZEN batch contract expects.
			a.logger.WarnContext(ctx, "authzen evaluation failed",
				slog.Int("index", i),
				slog.Any("error", err),
			)
			out.Evaluations = append(out.Evaluations, evaluationResponse{
				Decision: false,
				Context: map[string]any{
					"decision": string(authz.EffectDeny),
					"source":   SourceDefault,
					"reason":   "evaluation failed",
					"error":    true,
				},
			})
		default:
			out.Evaluations = append(out.Evaluations, decisionResponse(decision))
		}
	}
	writeJSON(w, http.StatusOK, out)
}

// evaluate turns an AuthZEN request into a SARC decision request and asks
// the engine. The caller is resolved by the handler, once per request, so
// that an unresolvable caller can only ever be reported as the request-wide
// failure it is.
//
// The subject's roles and root capabilities are only ever taken from the
// caller's verified token, never from the request body: a PEP may ask about
// any subject, but it may not assert what that subject is entitled to.
func (a *API) evaluate(ctx context.Context, caller authz.Subject, req, defaults evaluationRequest) (authz.Decision, error) {
	subject := firstSubject(req.Subject, defaults.Subject)
	action := firstAction(req.Action, defaults.Action)
	resource := firstResource(req.Resource, defaults.Resource)
	reqContext := req.Context
	if reqContext == nil {
		reqContext = defaults.Context
	}

	if action == nil || action.Name == "" {
		return authz.Decision{}, fmt.Errorf("%w: action.name is required", ErrInvalidRequest)
	}
	if resource == nil || (resource.ID == "" && resource.Type == "") {
		return authz.Decision{}, fmt.Errorf("%w: resource is required", ErrInvalidRequest)
	}

	decisionSubject := caller
	if subject != nil && subject.ID != "" && subject.ID != caller.ID {
		// A question about somebody else is answered from policy alone.
		decisionSubject = authz.Subject{
			Type:       subject.Type,
			ID:         subject.ID,
			Properties: subject.Properties,
		}
	} else if subject != nil {
		decisionSubject.Type = firstNonEmpty(subject.Type, decisionSubject.Type)
		decisionSubject.Properties = subject.Properties
	}

	return a.pdp.Decide(ctx, authz.DecisionRequest{
		Subject: decisionSubject,
		Action:  authz.Action{Name: action.Name, Properties: action.Properties},
		Resource: authz.Resource{
			Type:               resourceType(resource),
			ID:                 resource.ID,
			FQN:                resourceFQN(resource),
			AttributeValueFQNs: attributeValueFQNs(resource),
			Properties:         resource.Properties,
		},
		Context: authz.RequestContext{
			Issuer:     callerIssuer(caller),
			Transport:  authz.TransportAPI,
			Properties: reqContext,
		},
	})
}

// writeEvaluationError distinguishes a request the caller can fix from a
// failure of the decision path itself.
func (a *API) writeEvaluationError(w http.ResponseWriter, r *http.Request, err error) {
	if errors.Is(err, ErrInvalidRequest) {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	a.logger.WarnContext(r.Context(), "authzen evaluation failed", slog.Any("error", err))
	writeError(w, http.StatusInternalServerError, "evaluation failed")
}

func (a *API) caller(ctx context.Context) (authz.Subject, error) {
	if a.callerSubject == nil {
		return authz.Subject{Type: authz.SubjectTypeUnknown}, nil
	}
	return a.callerSubject(ctx)
}

// callerIssuer reports the issuer of the caller's verified token. Root
// capabilities are only honored for issuers the platform trusts, so this
// must come from the token itself and never from the request body.
func callerIssuer(s authz.Subject) string {
	if s.Token == nil {
		return ""
	}
	return s.Token.Issuer()
}

// resourceType maps an AuthZEN resource type onto a platform resource type,
// defaulting to an endpoint so a bare {"type":"...","id":"/policy/..."}
// resource is authorized like the API operation it names.
func resourceType(r *apiResource) string {
	switch r.Type {
	case authz.ResourceTypeRegisteredResource, authz.ResourceTypeAttributeValues, authz.ResourceTypeEndpoint:
		return r.Type
	case "":
		return authz.ResourceTypeEndpoint
	default:
		return authz.ResourceTypeEndpoint
	}
}

func resourceFQN(r *apiResource) string {
	if r.Type == authz.ResourceTypeRegisteredResource {
		return r.ID
	}
	if fqn, ok := r.Properties["fqn"].(string); ok {
		return fqn
	}
	return ""
}

func attributeValueFQNs(r *apiResource) []string {
	raw, ok := r.Properties["attribute_value_fqns"]
	if !ok {
		raw = r.Properties["fqns"]
	}
	list, isList := raw.([]any)
	if !isList {
		return nil
	}
	out := make([]string, 0, len(list))
	for _, item := range list {
		if s, isString := item.(string); isString && s != "" {
			out = append(out, s)
		}
	}
	return out
}

func decisionResponse(d authz.Decision) evaluationResponse {
	ctx := map[string]any{
		"reason":   d.Reason,
		"source":   d.Source,
		"decision": string(d.Effect),
	}
	if len(d.Obligations) > 0 {
		ctx["obligations"] = d.Obligations
	}
	return evaluationResponse{Decision: d.Allowed(), Context: ctx}
}

func decodeJSON(w http.ResponseWriter, r *http.Request, out any) error {
	r.Body = http.MaxBytesReader(w, r.Body, maxEvaluationBodyBytes)
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	if err := dec.Decode(out); err != nil {
		return errors.New("malformed request body")
	}
	return nil
}

func writeJSON(w http.ResponseWriter, status int, body any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(body)
}

func writeError(w http.ResponseWriter, status int, msg string) {
	writeJSON(w, status, map[string]string{"error": msg})
}

func firstSubject(vals ...*apiSubject) *apiSubject {
	for _, v := range vals {
		if v != nil {
			return v
		}
	}
	return nil
}

func firstAction(vals ...*apiAction) *apiAction {
	for _, v := range vals {
		if v != nil {
			return v
		}
	}
	return nil
}

func firstResource(vals ...*apiResource) *apiResource {
	for _, v := range vals {
		if v != nil {
			return v
		}
	}
	return nil
}

func firstNonEmpty(vals ...string) string {
	for _, v := range vals {
		if v != "" {
			return v
		}
	}
	return ""
}
