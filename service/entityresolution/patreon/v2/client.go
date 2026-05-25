package patreon

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

const (
	defaultAPIBase     = "https://www.patreon.com/api/oauth2/v2"
	defaultTokenURL    = "https://www.patreon.com/api/oauth2/token" //nolint:gosec // URL, not a credential
	identityResource   = "/identity"
	campaignsResource  = "/campaigns"
	defaultHTTPTimeout = 15 * time.Second
	httpStatusOKBucket = 2 // numerator/100 for 2xx responses
)

var (
	ErrPatreonUnavailable = errors.New("patreon api unavailable")
	ErrMemberNotFound     = errors.New("patreon member not found")
)

// Membership is the subject-claim view of Patreon state surfaced to the
// policy engine. Field names back the .patreon.* selectors in subject
// mappings (see examples/config/policy.patreon.yaml).
type Membership struct {
	UserID       string   `json:"user_id"`
	Email        string   `json:"email"`
	FullName     string   `json:"full_name"`
	Status       string   `json:"status"`
	TierSlug     string   `json:"tier_slug"`
	TierAmount   int      `json:"tier_amount_cents"`
	CampaignIDs  []string `json:"campaign_ids"`
	Benefits     []string `json:"benefits"`
	PledgeStart  string   `json:"pledge_start,omitempty"`
	LastChargeAt string   `json:"last_charge_at,omitempty"`
}

// Client is a minimal Patreon v2 API client scoped to what the ERS needs:
// resolve a backer's membership state from an identifier (user id, email, or
// the backer's own OAuth access token).
type Client struct {
	httpClient   *http.Client
	apiBase      string
	tokenURL     string
	clientID     string
	clientSecret string
	creatorToken string
	campaignIDs  []string

	mu          sync.Mutex
	cachedToken string
	tokenExpiry time.Time
}

// ClientOptions configures the Patreon client. Either CreatorAccessToken
// (long-lived creator token used to list campaign members) or the
// ClientID/ClientSecret pair (for refreshing the creator token) must be set.
type ClientOptions struct {
	APIBase            string
	TokenURL           string
	HTTPClient         *http.Client
	ClientID           string
	ClientSecret       string
	CreatorAccessToken string
	CampaignIDs        []string
}

func NewClient(opts ClientOptions) *Client {
	httpClient := opts.HTTPClient
	if httpClient == nil {
		httpClient = &http.Client{Timeout: defaultHTTPTimeout}
	}
	apiBase := opts.APIBase
	if apiBase == "" {
		apiBase = defaultAPIBase
	}
	tokenURL := opts.TokenURL
	if tokenURL == "" {
		tokenURL = defaultTokenURL
	}
	return &Client{
		httpClient:   httpClient,
		apiBase:      strings.TrimRight(apiBase, "/"),
		tokenURL:     tokenURL,
		clientID:     opts.ClientID,
		clientSecret: opts.ClientSecret,
		creatorToken: opts.CreatorAccessToken,
		campaignIDs:  opts.CampaignIDs,
	}
}

// CampaignIDs returns the configured campaign ids this client searches.
func (c *Client) CampaignIDs() []string {
	return c.campaignIDs
}

// ResolveByUserID looks up a backer by their Patreon user id across every
// configured campaign.
func (c *Client) ResolveByUserID(ctx context.Context, userID string) (*Membership, error) {
	return c.findMember(ctx, func(m *memberRow) bool {
		return m.userID == userID
	})
}

// ResolveByEmail looks up a backer by email (case-insensitive) across every
// configured campaign.
func (c *Client) ResolveByEmail(ctx context.Context, email string) (*Membership, error) {
	wanted := strings.ToLower(strings.TrimSpace(email))
	if wanted == "" {
		return nil, ErrMemberNotFound
	}
	return c.findMember(ctx, func(m *memberRow) bool {
		return strings.EqualFold(m.email, wanted)
	})
}

// ResolveSelf calls the identity endpoint using a backer's OAuth access
// token to fetch their own membership state.
func (c *Client) ResolveSelf(ctx context.Context, userAccessToken string) (*Membership, error) {
	if userAccessToken == "" {
		return nil, ErrMemberNotFound
	}
	q := url.Values{}
	q.Set("include", "memberships,memberships.currently_entitled_tiers,memberships.campaign,memberships.currently_entitled_tiers.benefits")
	q.Set("fields[user]", "email,full_name")
	q.Set("fields[member]", "patron_status,currently_entitled_amount_cents,last_charge_date,pledge_relationship_start")
	q.Set("fields[tier]", "title,amount_cents")
	q.Set("fields[benefit]", "title")
	u := c.apiBase + identityResource + "?" + q.Encode()

	raw := json.RawMessage(nil)
	if err := c.doJSON(ctx, http.MethodGet, u, userAccessToken, &raw); err != nil {
		return nil, err
	}
	return parseIdentity(raw)
}

func (c *Client) findMember(ctx context.Context, match func(*memberRow) bool) (*Membership, error) {
	token, err := c.creatorAccessToken(ctx)
	if err != nil {
		return nil, err
	}
	campaigns := c.campaignIDs
	if len(campaigns) == 0 {
		ids, err := c.listCampaigns(ctx, token)
		if err != nil {
			return nil, err
		}
		campaigns = ids
	}

	for _, campaignID := range campaigns {
		member, err := c.searchCampaignMembers(ctx, token, campaignID, match)
		if err != nil {
			return nil, err
		}
		if member != nil {
			return member, nil
		}
	}
	return nil, ErrMemberNotFound
}

func (c *Client) searchCampaignMembers(ctx context.Context, token, campaignID string, match func(*memberRow) bool) (*Membership, error) {
	cursor := ""
	for {
		q := url.Values{}
		q.Set("include", "user,currently_entitled_tiers,currently_entitled_tiers.benefits")
		q.Set("fields[member]", "email,full_name,patron_status,currently_entitled_amount_cents,last_charge_date,pledge_relationship_start")
		q.Set("fields[user]", "email,full_name")
		q.Set("fields[tier]", "title,amount_cents")
		q.Set("fields[benefit]", "title")
		q.Set("page[count]", "100")
		if cursor != "" {
			q.Set("page[cursor]", cursor)
		}
		u := fmt.Sprintf("%s/campaigns/%s/members?%s", c.apiBase, url.PathEscape(campaignID), q.Encode())

		raw := json.RawMessage(nil)
		if err := c.doJSON(ctx, http.MethodGet, u, token, &raw); err != nil {
			return nil, err
		}
		page, err := parseMembersPage(raw)
		if err != nil {
			return nil, err
		}
		for _, row := range page.members {
			if match(&row) {
				return row.toMembership(campaignID), nil
			}
		}
		if page.nextCursor == "" {
			return nil, nil //nolint:nilnil // sentinel for "kept searching, didn't find"
		}
		cursor = page.nextCursor
	}
}

func (c *Client) listCampaigns(ctx context.Context, token string) ([]string, error) {
	u := c.apiBase + campaignsResource
	var resp struct {
		Data []struct {
			ID string `json:"id"`
		} `json:"data"`
	}
	if err := c.doJSON(ctx, http.MethodGet, u, token, &resp); err != nil {
		return nil, err
	}
	ids := make([]string, 0, len(resp.Data))
	for _, d := range resp.Data {
		ids = append(ids, d.ID)
	}
	return ids, nil
}

// creatorAccessToken returns a usable access token, refreshing via the
// client_credentials grant when a client id/secret are configured.
func (c *Client) creatorAccessToken(ctx context.Context) (string, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.cachedToken != "" && time.Now().Before(c.tokenExpiry.Add(-1*time.Minute)) {
		return c.cachedToken, nil
	}
	if c.creatorToken != "" {
		return c.creatorToken, nil
	}
	if c.clientID == "" || c.clientSecret == "" {
		return "", fmt.Errorf("%w: no creator token and no client credentials configured", ErrPatreonUnavailable)
	}

	form := url.Values{}
	form.Set("grant_type", "client_credentials")
	form.Set("client_id", c.clientID)
	form.Set("client_secret", c.clientSecret)

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.tokenURL, strings.NewReader(form.Encode()))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("%w: %w", ErrPatreonUnavailable, err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode/100 != httpStatusOKBucket {
		return "", fmt.Errorf("%w: token endpoint returned %s: %s", ErrPatreonUnavailable, resp.Status, string(body))
	}
	var tokResp struct {
		AccessToken string `json:"access_token"`
		ExpiresIn   int    `json:"expires_in"`
	}
	if err := json.Unmarshal(body, &tokResp); err != nil {
		return "", fmt.Errorf("%w: %w", ErrPatreonUnavailable, err)
	}
	c.cachedToken = tokResp.AccessToken
	c.tokenExpiry = time.Now().Add(time.Duration(tokResp.ExpiresIn) * time.Second)
	return c.cachedToken, nil
}

func (c *Client) doJSON(ctx context.Context, method, target, bearer string, out interface{}) error {
	req, err := http.NewRequestWithContext(ctx, method, target, nil)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+bearer)
	req.Header.Set("Accept", "application/json")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("%w: %w", ErrPatreonUnavailable, err)
	}
	defer resp.Body.Close()
	body, readErr := io.ReadAll(resp.Body)
	if readErr != nil {
		return fmt.Errorf("%w: read body: %w", ErrPatreonUnavailable, readErr)
	}
	if resp.StatusCode == http.StatusNotFound {
		return ErrMemberNotFound
	}
	if resp.StatusCode/100 != httpStatusOKBucket {
		return fmt.Errorf("%w: %s: %s", ErrPatreonUnavailable, resp.Status, string(body))
	}
	return json.Unmarshal(body, out)
}

// ---- JSON:API response parsing ----
//
// Patreon's API is JSON:API: a `data` array of resources and an `included`
// array of related resources. Resources reference each other via
// `relationships[name].data` ({id,type} pointers). We parse generically
// because the relationships span types (member -> user, member -> tier,
// tier -> benefit).

type memberRow struct {
	id           string
	userID       string
	email        string
	fullName     string
	status       string
	tierSlug     string
	tierAmount   int
	benefits     []string
	pledgeStart  string
	lastChargeAt string
}

func (m *memberRow) toMembership(campaignID string) *Membership {
	out := &Membership{
		UserID:       m.userID,
		Email:        m.email,
		FullName:     m.fullName,
		Status:       m.status,
		TierSlug:     m.tierSlug,
		TierAmount:   m.tierAmount,
		Benefits:     m.benefits,
		PledgeStart:  m.pledgeStart,
		LastChargeAt: m.lastChargeAt,
	}
	if campaignID != "" {
		out.CampaignIDs = []string{campaignID}
	}
	if out.TierSlug == "" {
		out.TierSlug = "free"
	}
	out.Status = normalizeStatus(out.Status)
	return out
}

type membersPage struct {
	members    []memberRow
	nextCursor string
}

type rawResource struct {
	ID            string                     `json:"id"`
	Type          string                     `json:"type"`
	Attributes    map[string]json.RawMessage `json:"attributes"`
	Relationships map[string]struct {
		// JSON:API allows data to be either a single object or an array;
		// we always normalize to a slice below.
		Data json.RawMessage `json:"data"`
	} `json:"relationships"`
}

type resourceIndex struct {
	users    map[string]rawResource
	tiers    map[string]rawResource
	benefits map[string]rawResource
	members  map[string]rawResource
}

func indexResources(included []rawResource) *resourceIndex {
	idx := &resourceIndex{
		users:    map[string]rawResource{},
		tiers:    map[string]rawResource{},
		benefits: map[string]rawResource{},
		members:  map[string]rawResource{},
	}
	for _, r := range included {
		switch r.Type {
		case "user":
			idx.users[r.ID] = r
		case "tier":
			idx.tiers[r.ID] = r
		case "benefit":
			idx.benefits[r.ID] = r
		case "member":
			idx.members[r.ID] = r
		}
	}
	return idx
}

// relRefs returns the {id,type} pointers under relationships[name].
func relRefs(r rawResource, name string) []struct{ ID, Type string } {
	raw, ok := r.Relationships[name]
	if !ok || len(raw.Data) == 0 {
		return nil
	}
	// data may be a single object or an array.
	if raw.Data[0] == '[' {
		var arr []struct {
			ID   string `json:"id"`
			Type string `json:"type"`
		}
		if err := json.Unmarshal(raw.Data, &arr); err != nil {
			return nil
		}
		out := make([]struct{ ID, Type string }, len(arr))
		for i, a := range arr {
			out[i] = struct{ ID, Type string }{a.ID, a.Type}
		}
		return out
	}
	var single struct {
		ID   string `json:"id"`
		Type string `json:"type"`
	}
	if err := json.Unmarshal(raw.Data, &single); err != nil {
		return nil
	}
	if single.ID == "" {
		return nil
	}
	return []struct{ ID, Type string }{{single.ID, single.Type}}
}

func attrString(r rawResource, key string) string {
	raw, ok := r.Attributes[key]
	if !ok {
		return ""
	}
	var s string
	if err := json.Unmarshal(raw, &s); err != nil {
		return ""
	}
	return s
}

func attrInt(r rawResource, key string) int {
	raw, ok := r.Attributes[key]
	if !ok {
		return 0
	}
	var n int
	if err := json.Unmarshal(raw, &n); err != nil {
		return 0
	}
	return n
}

func hydrateUserFields(row *memberRow, r rawResource, idx *resourceIndex) {
	refs := relRefs(r, "user")
	if len(refs) == 0 {
		return
	}
	row.userID = refs[0].ID
	u, ok := idx.users[refs[0].ID]
	if !ok {
		return
	}
	if e := attrString(u, "email"); e != "" {
		row.email = e
	}
	if n := attrString(u, "full_name"); n != "" {
		row.fullName = n
	}
}

func memberFromResource(r rawResource, idx *resourceIndex) memberRow {
	row := memberRow{
		id:           r.ID,
		email:        attrString(r, "email"),
		fullName:     attrString(r, "full_name"),
		status:       attrString(r, "patron_status"),
		tierAmount:   attrInt(r, "currently_entitled_amount_cents"),
		pledgeStart:  attrString(r, "pledge_relationship_start"),
		lastChargeAt: attrString(r, "last_charge_date"),
	}
	hydrateUserFields(&row, r, idx)
	// tiers + benefits-via-tier
	tierRefs := relRefs(r, "currently_entitled_tiers")
	bestAmount := -1
	benefitSet := map[string]struct{}{}
	for _, tref := range tierRefs {
		tier, found := idx.tiers[tref.ID]
		if !found {
			continue
		}
		amount := attrInt(tier, "amount_cents")
		if amount > bestAmount {
			bestAmount = amount
			row.tierSlug = slugify(attrString(tier, "title"))
		}
		for _, bref := range relRefs(tier, "benefits") {
			b, bfound := idx.benefits[bref.ID]
			if !bfound {
				continue
			}
			if s := slugify(attrString(b, "title")); s != "" {
				benefitSet[s] = struct{}{}
			}
		}
	}
	row.benefits = sortedKeys(benefitSet)
	return row
}

func parseMembersPage(raw json.RawMessage) (*membersPage, error) {
	var resp struct {
		Data     []rawResource `json:"data"`
		Included []rawResource `json:"included"`
		Meta     struct {
			Pagination struct {
				Cursors struct {
					Next string `json:"next"`
				} `json:"cursors"`
			} `json:"pagination"`
		} `json:"meta"`
	}
	if err := json.Unmarshal(raw, &resp); err != nil {
		return nil, err
	}
	idx := indexResources(resp.Included)
	page := &membersPage{nextCursor: resp.Meta.Pagination.Cursors.Next}
	for _, d := range resp.Data {
		page.members = append(page.members, memberFromResource(d, idx))
	}
	return page, nil
}

func parseIdentity(raw json.RawMessage) (*Membership, error) {
	var resp struct {
		Data     rawResource   `json:"data"`
		Included []rawResource `json:"included"`
	}
	if err := json.Unmarshal(raw, &resp); err != nil {
		return nil, err
	}
	idx := indexResources(resp.Included)
	mem := &Membership{
		UserID:   resp.Data.ID,
		Email:    attrString(resp.Data, "email"),
		FullName: attrString(resp.Data, "full_name"),
		TierSlug: "free",
		Status:   normalizeStatus(""),
	}
	bestAmount := -1
	benefitSet := map[string]struct{}{}
	campaignSet := map[string]struct{}{}
	for _, mref := range relRefs(resp.Data, "memberships") {
		mres, ok := idx.members[mref.ID]
		if !ok {
			continue
		}
		row := memberFromResource(mres, idx)
		if row.tierAmount > bestAmount {
			bestAmount = row.tierAmount
			mem.TierSlug = row.tierSlug
			mem.TierAmount = row.tierAmount
		}
		if row.status != "" {
			mem.Status = normalizeStatus(row.status)
		}
		if row.lastChargeAt != "" {
			mem.LastChargeAt = row.lastChargeAt
		}
		if row.pledgeStart != "" {
			mem.PledgeStart = row.pledgeStart
		}
		for _, b := range row.benefits {
			benefitSet[b] = struct{}{}
		}
		for _, cref := range relRefs(mres, "campaign") {
			campaignSet[cref.ID] = struct{}{}
		}
	}
	mem.Benefits = sortedKeys(benefitSet)
	mem.CampaignIDs = sortedKeys(campaignSet)
	return mem, nil
}

func normalizeStatus(in string) string {
	switch strings.ToLower(in) {
	case "active_patron":
		return "active"
	case "declined_patron":
		return "declined"
	case "former_patron":
		return "former"
	case "":
		return "former"
	default:
		return strings.ToLower(in)
	}
}

func slugify(in string) string {
	in = strings.ToLower(strings.TrimSpace(in))
	if in == "" {
		return ""
	}
	var b strings.Builder
	b.Grow(len(in))
	prevDash := false
	for _, r := range in {
		switch {
		case r >= 'a' && r <= 'z', r >= '0' && r <= '9':
			b.WriteRune(r)
			prevDash = false
		case r == '-' || r == '_' || r == ' ':
			if !prevDash {
				b.WriteRune('-')
				prevDash = true
			}
		}
	}
	return strings.Trim(b.String(), "-")
}

func sortedKeys(m map[string]struct{}) []string {
	if len(m) == 0 {
		return nil
	}
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	// Deterministic order for stable claims output.
	sortStrings(out)
	return out
}

// sortStrings is a tiny insertion sort to avoid pulling in sort just for
// this small set; member benefit lists are typically <20 entries.
func sortStrings(s []string) {
	for i := 1; i < len(s); i++ {
		for j := i; j > 0 && s[j-1] > s[j]; j-- {
			s[j-1], s[j] = s[j], s[j-1]
		}
	}
}
