// Package jev provides an entity resolution provider backed by a TypeSafe Jev
// decision model.
//
// The provider turns a small, operator-chosen slice of entity context into
// derived claims. Those claims carry no authority of their own: they become
// entitlements only where an operator has also written a subject mapping that
// consumes them, so policy remains the sole grantor of access.
package jev

import (
	"errors"
	"fmt"

	jevclient "github.com/opentdf/platform/service/internal/jev"
)

// ProviderType is the value operators put in `providers.<name>.type`.
const ProviderType = "jev"

// Config configures one Jev provider instance. Each instance owns one catalog
// of questions; operators who need a different catalog configure a second
// provider rather than overloading this one.
type Config struct {
	// Client configures the model client, including the state allowlist and
	// the confidence threshold below which answers are discarded.
	Client jevclient.Config `mapstructure:",squash"`

	// Questions is the catalog posed on every resolution, keyed by the name
	// that output_mapping refers to via source_answer.
	Questions map[string]jevclient.Question `mapstructure:"questions"`

	// Description labels this instance in logs.
	Description string `mapstructure:"description"`
}

// ErrNoQuestions reports a provider configured with an empty catalog, which
// would call the model with nothing to answer.
var ErrNoQuestions = errors.New("jev provider: at least one question must be configured")

// Validate checks the provider configuration.
func (c *Config) Validate() error {
	if err := c.Client.Validate(); err != nil {
		return err
	}
	if !c.Client.Enabled {
		return nil
	}
	if len(c.Questions) == 0 {
		return ErrNoQuestions
	}
	for name, q := range c.Questions {
		if err := q.Validate(); err != nil {
			return fmt.Errorf("jev provider: invalid question %q: %w", name, err)
		}
	}
	return nil
}
