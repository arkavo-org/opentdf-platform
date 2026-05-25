package patreon

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"connectrpc.com/connect"
	"github.com/opentdf/platform/protocol/go/entity"
	ersV2 "github.com/opentdf/platform/protocol/go/entityresolution/v2"
	"github.com/opentdf/platform/service/logger"
	"go.opentelemetry.io/otel/trace/noop"
)

func newSvc(t *testing.T, cfg Config, client MembershipAPI) *EntityResolutionService {
	t.Helper()
	svc := NewERSWithClient(cfg, client, testLogger(t))
	svc.Tracer = noop.NewTracerProvider().Tracer("test")
	return svc
}

type stubClient struct {
	byID    map[string]*Membership
	byEmail map[string]*Membership
	self    map[string]*Membership
}

func (s *stubClient) ResolveByUserID(_ context.Context, id string) (*Membership, error) {
	if m, ok := s.byID[id]; ok {
		return m, nil
	}
	return nil, ErrMemberNotFound
}

func (s *stubClient) ResolveByEmail(_ context.Context, email string) (*Membership, error) {
	if m, ok := s.byEmail[strings.ToLower(email)]; ok {
		return m, nil
	}
	return nil, ErrMemberNotFound
}

func (s *stubClient) ResolveSelf(_ context.Context, tok string) (*Membership, error) {
	if m, ok := s.self[tok]; ok {
		return m, nil
	}
	return nil, ErrMemberNotFound
}

func testLogger(t *testing.T) *logger.Logger {
	t.Helper()
	l, err := logger.NewLogger(logger.Config{Level: "debug", Output: "stdout", Type: "text"})
	if err != nil {
		t.Fatalf("logger: %v", err)
	}
	return l
}

func TestResolveEntities_ByUserID(t *testing.T) {
	stub := &stubClient{byID: map[string]*Membership{
		"u123": {
			UserID: "u123", Email: "a@b.test", TierSlug: "patron",
			TierAmount: 1000, Status: "active",
			CampaignIDs: []string{"arkavo"},
			Benefits:    []string{"early-access", "exclusive-content"},
		},
	}}
	svc := newSvc(t, Config{}, stub)

	req := connect.NewRequest(&ersV2.ResolveEntitiesRequest{
		Entities: []*entity.Entity{{
			EphemeralId: "e0",
			EntityType:  &entity.Entity_UserName{UserName: "u123"},
		}},
	})
	resp, err := svc.ResolveEntities(context.Background(), req)
	if err != nil {
		t.Fatalf("ResolveEntities: %v", err)
	}
	reprs := resp.Msg.GetEntityRepresentations()
	if len(reprs) != 1 {
		t.Fatalf("want 1 representation, got %d", len(reprs))
	}
	props := reprs[0].GetAdditionalProps()
	if len(props) != 1 {
		t.Fatalf("want 1 props struct, got %d", len(props))
	}
	got := props[0].AsMap()
	patreon, ok := got["patreon"].(map[string]interface{})
	if !ok {
		t.Fatalf("expected patreon map, got %T", got["patreon"])
	}
	if patreon["tier_slug"] != "patron" {
		t.Errorf("tier_slug = %v, want patron", patreon["tier_slug"])
	}
	if patreon["status"] != "active" {
		t.Errorf("status = %v, want active", patreon["status"])
	}
}

func TestResolveEntities_UnknownInfersFree(t *testing.T) {
	svc := newSvc(t, Config{InferUnknownAsFree: true}, &stubClient{})
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
	patreon, ok := resp.Msg.GetEntityRepresentations()[0].GetAdditionalProps()[0].AsMap()["patreon"].(map[string]interface{})
	if !ok {
		t.Fatalf("patreon key missing or wrong type")
	}
	if patreon["tier_slug"] != "free" {
		t.Errorf("tier_slug = %v, want free", patreon["tier_slug"])
	}
}

func TestResolveEntities_UnknownErrors(t *testing.T) {
	svc := newSvc(t, Config{InferUnknownAsFree: false}, &stubClient{})
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
	if !errors.Is(err, ErrMemberNotFound) {
		t.Errorf("err = %v, want ErrMemberNotFound underlying", err)
	}
}

func TestParseMembersPage(t *testing.T) {
	payload := `{
	  "data": [
	    {
	      "id": "m1",
	      "type": "member",
	      "attributes": {
	        "email": "fan@example.com",
	        "full_name": "Fan One",
	        "patron_status": "active_patron",
	        "currently_entitled_amount_cents": 500,
	        "last_charge_date": "2024-05-01T00:00:00Z"
	      },
	      "relationships": {
	        "user":                     {"data": {"id":"u1","type":"user"}},
	        "currently_entitled_tiers": {"data": [{"id":"t1","type":"tier"}]}
	      }
	    }
	  ],
	  "included": [
	    {"id":"u1","type":"user","attributes":{"email":"fan@example.com","full_name":"Fan One"}},
	    {"id":"t1","type":"tier","attributes":{"title":"Supporter","amount_cents":500},
	     "relationships":{"benefits":{"data":[{"id":"b1","type":"benefit"},{"id":"b2","type":"benefit"}]}}},
	    {"id":"b1","type":"benefit","attributes":{"title":"Early Access"}},
	    {"id":"b2","type":"benefit","attributes":{"title":"Exclusive Content"}}
	  ],
	  "meta": {"pagination":{"cursors":{"next":""}}}
	}`
	page, err := parseMembersPage(json.RawMessage(payload))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if len(page.members) != 1 {
		t.Fatalf("want 1 member, got %d", len(page.members))
	}
	m := page.members[0]
	if m.userID != "u1" || m.email != "fan@example.com" {
		t.Errorf("user/email mismatch: %+v", m)
	}
	if m.tierSlug != "supporter" {
		t.Errorf("tier_slug = %q, want supporter", m.tierSlug)
	}
	if got := strings.Join(m.benefits, ","); got != "early-access,exclusive-content" {
		t.Errorf("benefits = %q, want early-access,exclusive-content", got)
	}
	mem := m.toMembership("arkavo")
	if mem.Status != "active" {
		t.Errorf("status = %q, want active", mem.Status)
	}
	if len(mem.CampaignIDs) != 1 || mem.CampaignIDs[0] != "arkavo" {
		t.Errorf("campaign_ids = %v, want [arkavo]", mem.CampaignIDs)
	}
}

func TestParseIdentity(t *testing.T) {
	payload := `{
	  "data": {
	    "id": "u42",
	    "type": "user",
	    "attributes": {"email":"vip@example.com","full_name":"VIP"},
	    "relationships": {"memberships": {"data": [{"id":"m99","type":"member"}]}}
	  },
	  "included": [
	    {"id":"m99","type":"member","attributes":{"patron_status":"active_patron","currently_entitled_amount_cents":5000},
	     "relationships":{"campaign":{"data":{"id":"arkavo","type":"campaign"}},
	                      "currently_entitled_tiers":{"data":[{"id":"t9","type":"tier"}]}}},
	    {"id":"t9","type":"tier","attributes":{"title":"VIP","amount_cents":5000},
	     "relationships":{"benefits":{"data":[{"id":"b9","type":"benefit"}]}}},
	    {"id":"b9","type":"benefit","attributes":{"title":"Discord"}}
	  ]
	}`
	mem, err := parseIdentity(json.RawMessage(payload))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if mem.TierSlug != "vip" {
		t.Errorf("tier_slug = %q, want vip", mem.TierSlug)
	}
	if mem.Status != "active" {
		t.Errorf("status = %q, want active", mem.Status)
	}
	if len(mem.CampaignIDs) != 1 || mem.CampaignIDs[0] != "arkavo" {
		t.Errorf("campaign_ids = %v, want [arkavo]", mem.CampaignIDs)
	}
	if len(mem.Benefits) != 1 || mem.Benefits[0] != "discord" {
		t.Errorf("benefits = %v, want [discord]", mem.Benefits)
	}
}

func TestClient_ResolveByEmail_PaginatesAndMatches(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		cursor := r.URL.Query().Get("page[cursor]")
		w.Header().Set("Content-Type", "application/json")
		switch cursor {
		case "":
			_, _ = w.Write([]byte(`{
				"data": [{"id":"m1","type":"member","attributes":{},"relationships":{"user":{"data":{"id":"u1","type":"user"}}}}],
				"included": [{"id":"u1","type":"user","attributes":{"email":"alice@example.com"}}],
				"meta": {"pagination":{"cursors":{"next":"page2"}}}
			}`))
		case "page2":
			_, _ = w.Write([]byte(`{
				"data": [{"id":"m2","type":"member","attributes":{"patron_status":"active_patron","currently_entitled_amount_cents":2500},
				          "relationships":{"user":{"data":{"id":"u2","type":"user"}},
				                           "currently_entitled_tiers":{"data":[{"id":"t1","type":"tier"}]}}}],
				"included": [
				  {"id":"u2","type":"user","attributes":{"email":"bob@example.com","full_name":"Bob"}},
				  {"id":"t1","type":"tier","attributes":{"title":"Patron","amount_cents":2500}}
				],
				"meta": {"pagination":{"cursors":{"next":""}}}
			}`))
		default:
			http.Error(w, "unexpected", http.StatusInternalServerError)
		}
	}))
	defer server.Close()

	c := NewClient(ClientOptions{
		APIBase:            server.URL,
		CreatorAccessToken: "fake-creator-token",
		CampaignIDs:        []string{"arkavo"},
	})
	mem, err := c.ResolveByEmail(context.Background(), "BOB@example.com")
	if err != nil {
		t.Fatalf("ResolveByEmail: %v", err)
	}
	if mem.UserID != "u2" {
		t.Errorf("user_id = %q, want u2", mem.UserID)
	}
	if mem.TierSlug != "patron" {
		t.Errorf("tier_slug = %q, want patron", mem.TierSlug)
	}
	if mem.Status != "active" {
		t.Errorf("status = %q, want active", mem.Status)
	}
}

func TestSlugify(t *testing.T) {
	for _, tc := range []struct{ in, want string }{
		{"VIP", "vip"},
		{"Early Access", "early-access"},
		{"  Behind The Scenes  ", "behind-the-scenes"},
		{"!!!", ""},
		{"foo--bar", "foo-bar"},
	} {
		if got := slugify(tc.in); got != tc.want {
			t.Errorf("slugify(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}
