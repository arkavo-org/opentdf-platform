package jev

import (
	"encoding/json"
	"net/http"
)

// decodeJSON reads a request body in a test handler without using require,
// which must not be called off the test goroutine.
func decodeJSON(r *http.Request, into any) error {
	return json.NewDecoder(r.Body).Decode(into)
}
