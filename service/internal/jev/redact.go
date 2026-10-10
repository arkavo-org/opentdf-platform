package jev

import "sort"

// RedactState drops every key of state that the operator has not explicitly
// allowed to leave the platform.
//
// Matching is on top-level keys only. A permitted key carries its whole value,
// including nested maps, so operators should allow narrow, already-shaped keys
// rather than whole claim sets. Keys are matched exactly and case-sensitively.
//
// The result is always non-nil, so a fully redacted state sends an empty object
// rather than null.
func RedactState(state map[string]any, allowlist []string) map[string]any {
	allowed := make(map[string]struct{}, len(allowlist))
	for _, k := range allowlist {
		allowed[k] = struct{}{}
	}

	out := make(map[string]any, len(allowed))
	for k, v := range state {
		if _, ok := allowed[k]; ok {
			out[k] = v
		}
	}
	return out
}

// RedactedKeys reports which keys of state were withheld, sorted, so that a
// caller can record what was dropped without recording the values themselves.
func RedactedKeys(state map[string]any, allowlist []string) []string {
	allowed := make(map[string]struct{}, len(allowlist))
	for _, k := range allowlist {
		allowed[k] = struct{}{}
	}

	dropped := make([]string, 0, len(state))
	for k := range state {
		if _, ok := allowed[k]; !ok {
			dropped = append(dropped, k)
		}
	}
	sort.Strings(dropped)
	return dropped
}
