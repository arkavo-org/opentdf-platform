package patreon

import (
	"context"
	"testing"

	"connectrpc.com/connect"
	"github.com/opentdf/platform/protocol/go/entity"
	ersV2 "github.com/opentdf/platform/protocol/go/entityresolution/v2"
	"github.com/opentdf/platform/service/logger"
	"go.opentelemetry.io/otel/trace/noop"
)

func newSvc(t *testing.T, cfg Config) *EntityResolutionService {
	t.Helper()
	svc := NewERS(cfg, testLogger(t))
	svc.Tracer = noop.NewTracerProvider().Tracer("test")
	return svc
}

func testLogger(t *testing.T) *logger.Logger {
	t.Helper()
	l, err := logger.NewLogger(logger.Config{Level: "debug", Output: "stdout", Type: "text"})
	if err != nil {
		t.Fatalf("logger: %v", err)
	}
	return l
}

// A subject with no usable Patreon claim resolves to a free follower when
// InferUnknownAsFree is set — the only non-passthrough resolution behavior.
func TestResolveEntities_UnknownInfersFree(t *testing.T) {
	svc := newSvc(t, Config{InferUnknownAsFree: true})
	req := connect.NewRequest(&ersV2.ResolveEntitiesRequest{
		Entities: []*entity.Entity{{
			EphemeralId: "e0",
			EntityType:  &entity.Entity_EmailAddress{EmailAddress: "nobody@nowhere"},
		}},
	})
	resp, err := svc.ResolveEntities(context.Background(), req)
	if err != nil {
		t.Fatalf("ResolveEntities: %v", err)
	}
	patreon, ok := resp.Msg.GetEntityRepresentations()[0].GetAdditionalProps()[0].
		AsMap()["patreon"].(map[string]interface{})
	if !ok {
		t.Fatalf("patreon key missing or wrong type")
	}
	if patreon["tier_slug"] != "free" {
		t.Errorf("tier_slug = %v, want free", patreon["tier_slug"])
	}
}

func TestResolveEntities_UnknownErrors(t *testing.T) {
	svc := newSvc(t, Config{InferUnknownAsFree: false})
	req := connect.NewRequest(&ersV2.ResolveEntitiesRequest{
		Entities: []*entity.Entity{{
			EphemeralId: "e0",
			EntityType:  &entity.Entity_EmailAddress{EmailAddress: "nobody@nowhere"},
		}},
	})
	_, err := svc.ResolveEntities(context.Background(), req)
	if err == nil {
		t.Fatal("expected error for unknown subject without infer")
	}
	if got := connect.CodeOf(err); got != connect.CodeNotFound {
		t.Errorf("code = %v, want NotFound", got)
	}
}

func TestSlugify(t *testing.T) {
	for _, tc := range []struct{ in, want string }{
		{"VIP", "vip"},
		{"Early Access", "early-access"},
		{"  Behind The Scenes  ", "behind-the-scenes"},
		{"!!!", ""},
		{"foo--bar", "foo-bar"},
		{"Tier_With_Underscores", "tier-with-underscores"},
	} {
		if got := slugify(tc.in); got != tc.want {
			t.Errorf("slugify(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}
