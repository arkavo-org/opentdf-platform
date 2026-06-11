package authorization

import (
	"fmt"
	"log/slog"
	"net/http"
	"strings"

	"google.golang.org/protobuf/encoding/protojson"

	"github.com/opentdf/platform/protocol/go/policy"
	"github.com/opentdf/platform/service/logger"
	"github.com/opentdf/platform/service/policy/filestore"
)

// AttributesEndpoint publicly serves the attribute definitions the PDP
// evaluates against — the single source of truth for attribute discovery.
// Attribute FQNs (https://<namespace>/attr/<name>[/value/<v>]) dereference
// when the namespace host points at this platform (directly or via the
// arks reverse proxy):
//
//   - GET /attributes                 → every attribute definition
//   - GET /attr/{name}                → one attribute definition
//   - GET /attr/{name}/value/{value}  → one attribute value
//
// Only wired for the file-backed policy provider (`policy_file`), where the
// served definitions are byte-for-byte the snapshot decisions use. Output is
// canonical proto-JSON of policy.Attribute / policy.Value.
type AttributesEndpoint struct {
	store  *filestore.Store
	logger *logger.Logger
}

// Definitions are static for the process lifetime (the snapshot loads at
// startup), but keep the cache window modest so a redeploy propagates.
const attributesCacheControl = "public, max-age=300"

func NewAttributesEndpoint(store *filestore.Store, log *logger.Logger) *AttributesEndpoint {
	return &AttributesEndpoint{store: store, logger: log}
}

func (e *AttributesEndpoint) Mount(mux *http.ServeMux) {
	mux.HandleFunc("GET /attributes", e.handleList)
	mux.HandleFunc("GET /attr/{name}", e.handleAttribute)
	mux.HandleFunc("GET /attr/{name}/value/{value}", e.handleValue)
}

func (e *AttributesEndpoint) handleList(w http.ResponseWriter, r *http.Request) {
	attrs, err := e.store.ListAllAttributes(r.Context())
	if err != nil {
		e.logger.ErrorContext(r.Context(), "attributes listing failed", slog.Any("error", err))
		http.Error(w, "attributes unavailable", http.StatusInternalServerError)
		return
	}

	parts := make([]string, 0, len(attrs))
	for _, a := range attrs {
		j, err := protojson.Marshal(a)
		if err != nil {
			e.logger.ErrorContext(r.Context(), "attribute marshal failed", slog.Any("error", err))
			http.Error(w, "attributes unavailable", http.StatusInternalServerError)
			return
		}
		parts = append(parts, string(j))
	}
	writeJSON(w, fmt.Sprintf(`{"attributes":[%s]}`, strings.Join(parts, ",")))
}

// attributeByName matches on the FQN path component `/attr/<name>` so the
// lookup works regardless of which host the request arrived on
// (platform.arkavo.net or the namespace host itself). When the same
// attribute name exists in several namespaces, the request Host picks the
// namespace; an unresolvable ambiguity is a 404 with a warning.
func (e *AttributesEndpoint) attributeByName(r *http.Request, name string) *policy.Attribute {
	attrs, err := e.store.ListAllAttributes(r.Context())
	if err != nil {
		return nil
	}
	suffix := "/attr/" + name
	var matches []*policy.Attribute
	for _, a := range attrs {
		if strings.HasSuffix(a.GetFqn(), suffix) {
			matches = append(matches, a)
		}
	}
	switch len(matches) {
	case 0:
		return nil
	case 1:
		return matches[0]
	}
	host := strings.Split(r.Host, ":")[0]
	for _, a := range matches {
		if strings.HasPrefix(a.GetFqn(), "https://"+host+"/") {
			return a
		}
	}
	e.logger.Warn("ambiguous attribute name across namespaces; disambiguate via Host",
		slog.String("name", name),
		slog.String("host", host),
	)
	return nil
}

func (e *AttributesEndpoint) handleAttribute(w http.ResponseWriter, r *http.Request) {
	attr := e.attributeByName(r, r.PathValue("name"))
	if attr == nil {
		http.NotFound(w, r)
		return
	}
	j, err := protojson.Marshal(attr)
	if err != nil {
		http.Error(w, "attributes unavailable", http.StatusInternalServerError)
		return
	}
	writeJSON(w, string(j))
}

func (e *AttributesEndpoint) handleValue(w http.ResponseWriter, r *http.Request) {
	attr := e.attributeByName(r, r.PathValue("name"))
	if attr == nil {
		http.NotFound(w, r)
		return
	}
	wanted := r.PathValue("value")
	for _, v := range attr.GetValues() {
		if v.GetValue() == wanted {
			j, err := protojson.Marshal(v)
			if err != nil {
				http.Error(w, "attributes unavailable", http.StatusInternalServerError)
				return
			}
			writeJSON(w, string(j))
			return
		}
	}
	http.NotFound(w, r)
}

func writeJSON(w http.ResponseWriter, body string) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", attributesCacheControl)
	_, _ = w.Write([]byte(body))
}
