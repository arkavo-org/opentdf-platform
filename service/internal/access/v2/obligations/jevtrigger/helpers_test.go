package jevtrigger

import (
	"encoding/json"
	"net/http"
)

// decodeJSON reads a request body inside a test handler, where require must
// not be called because it runs off the test goroutine.
func decodeJSON(r *http.Request, into any) error {
	return json.NewDecoder(r.Body).Decode(into)
}
