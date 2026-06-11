package authorization

import (
	"context"
	"fmt"
	"net/http"
	"strings"

	"google.golang.org/protobuf/encoding/protojson"

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
// served definitions are byte-for-byte the snapshot decisions use. Because
// the snapshot is immutable for the process lifetime, every response body is
// marshaled ONCE at construction: the public, unauthenticated handlers do no
// cloning, no marshaling, and no store access per request, and a 404 always
// means "genuinely not defined" — there is no backend error to mask.
type AttributesEndpoint struct {
	// Marshaled {"attributes":[...]} listing.
	listJSON []byte
	// FQN path component ("/attr/<name>") → precomputed entry.
	bySuffix map[string][]attributeEntry
}

type attributeEntry struct {
	// Namespace FQN prefix ("https://<host>") for Host disambiguation.
	namespacePrefix string
	attrJSON        []byte
	// value → marshaled policy.Value.
	valueJSON map[string][]byte
}

// Definitions are static for the process lifetime (the snapshot loads at
// startup), but keep the cache window modest so a redeploy propagates.
const attributesCacheControl = "public, max-age=300"

// NewAttributesEndpoint precomputes all responses from the snapshot.
func NewAttributesEndpoint(store *filestore.Store) (*AttributesEndpoint, error) {
	attrs, err := store.ListAllAttributes(context.Background())
	if err != nil {
		return nil, fmt.Errorf("list attributes: %w", err)
	}

	e := &AttributesEndpoint{
		bySuffix: map[string][]attributeEntry{},
	}

	parts := make([]string, 0, len(attrs))
	for _, a := range attrs {
		j, err := protojson.Marshal(a)
		if err != nil {
			return nil, fmt.Errorf("marshal attribute %q: %w", a.GetFqn(), err)
		}
		parts = append(parts, string(j))

		fqn := a.GetFqn()
		idx := strings.Index(fqn, "/attr/")
		if idx < 0 {
			continue
		}
		entry := attributeEntry{
			namespacePrefix: fqn[:idx],
			attrJSON:        j,
			valueJSON:       map[string][]byte{},
		}
		for _, v := range a.GetValues() {
			vj, err := protojson.Marshal(v)
			if err != nil {
				return nil, fmt.Errorf("marshal value %q: %w", v.GetFqn(), err)
			}
			entry.valueJSON[v.GetValue()] = vj
		}
		suffix := fqn[idx:]
		e.bySuffix[suffix] = append(e.bySuffix[suffix], entry)
	}
	e.listJSON = []byte(fmt.Sprintf(`{"attributes":[%s]}`, strings.Join(parts, ",")))
	return e, nil
}

func (e *AttributesEndpoint) Mount(mux *http.ServeMux) {
	mux.HandleFunc("GET /attributes", e.handleList)
	mux.HandleFunc("GET /attr/{name}", e.handleAttribute)
	mux.HandleFunc("GET /attr/{name}/value/{value}", e.handleValue)
}

func (e *AttributesEndpoint) handleList(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, e.listJSON)
}

// attributeByName matches on the FQN path component `/attr/<name>` so the
// lookup works regardless of which host the request arrived on
// (platform.arkavo.net or the namespace host itself). When the same
// attribute name exists in several namespaces, the request Host picks the
// namespace; an unresolvable ambiguity is a 404.
func (e *AttributesEndpoint) attributeByName(r *http.Request, name string) *attributeEntry {
	matches := e.bySuffix["/attr/"+name]
	switch len(matches) {
	case 0:
		return nil
	case 1:
		return &matches[0]
	}
	host := strings.Split(r.Host, ":")[0]
	for i := range matches {
		if matches[i].namespacePrefix == "https://"+host {
			return &matches[i]
		}
	}
	return nil
}

func (e *AttributesEndpoint) handleAttribute(w http.ResponseWriter, r *http.Request) {
	entry := e.attributeByName(r, r.PathValue("name"))
	if entry == nil {
		http.NotFound(w, r)
		return
	}
	writeJSON(w, entry.attrJSON)
}

func (e *AttributesEndpoint) handleValue(w http.ResponseWriter, r *http.Request) {
	entry := e.attributeByName(r, r.PathValue("name"))
	if entry == nil {
		http.NotFound(w, r)
		return
	}
	vj, ok := entry.valueJSON[r.PathValue("value")]
	if !ok {
		http.NotFound(w, r)
		return
	}
	writeJSON(w, vj)
}

func writeJSON(w http.ResponseWriter, body []byte) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", attributesCacheControl)
	_, _ = w.Write(body)
}
