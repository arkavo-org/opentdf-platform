package filestore

import (
	"strings"
	"testing"

	"github.com/opentdf/platform/service/internal/chaindevice"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gopkg.in/yaml.v3"
)

const (
	deviceRulesDef     = "https://patreon.arkavo.com/attr/"
	publishGrant       = deviceRulesDef + "arkavo-creator/value/publish"
	campaignDefinition = deviceRulesDef + "campaign"
	tierDefinition     = deviceRulesDef + "campaign-tier"

	// SHA-256 of M8GS7ZT95Y.com.arkavo.Arkavo and ...ArkavoCreator (pinned
	// in the chaindevice tests against authnz-rs's App Attest fixture).
	arkavoAppHash        = "543398d88f303adedb67445ee9edbf1e1733a73d92bf6992cfbf228d60763cf8"
	arkavoCreatorAppHash = "ea2defc9e7bf14b832b0fb5e4ada8f0af0e114dca9fc7741cda17d875cf1bc01"

	deviceRulesPolicy = `
namespaces:
  - name: patreon.arkavo.com
attributes:
  - namespace: patreon.arkavo.com
    name: arkavo-creator
    rule: anyOf
    values:
      - value: publish
  - namespace: patreon.arkavo.com
    name: campaign
    rule: anyOf
  - namespace: patreon.arkavo.com
    name: campaign-tier
    rule: anyOf
  - namespace: patreon.arkavo.com
    name: classification
    rule: hierarchy
    values:
      - value: public
      - value: vip
`

	// publishRulesYAML is the device_rules block of the design spec, section 3.
	publishRulesYAML = `
device_rules:
  requirements:
    - grants:
        - https://patreon.arkavo.com/attr/arkavo-creator/value/publish
      device_classes: [attested]
      apps:
        - M8GS7ZT95Y.com.arkavo.Arkavo
        - M8GS7ZT95Y.com.arkavo.ArkavoCreator
      app_envs: [production]
  caps:
    - device_class: managed
      keeps:
        - https://patreon.arkavo.com/attr/campaign
        - https://patreon.arkavo.com/attr/campaign-tier
`
)

// storeWithDeviceRules builds a store from deviceRulesPolicy plus the given
// device_rules block, decoding the YAML the way a policy file is decoded.
func storeWithDeviceRules(t *testing.T, rulesYAML string) (*Store, error) {
	t.Helper()
	var schema Schema
	require.NoError(t, yaml.Unmarshal([]byte(deviceRulesPolicy+rulesYAML), &schema))
	return NewStore(&schema)
}

// requirementYAML renders a device_rules block of one requirement. extra holds
// further fields of the requirement, one per line.
func requirementYAML(grants, classes string, extra ...string) string {
	var b strings.Builder
	b.WriteString("device_rules:\n  requirements:\n    - grants: " + grants + "\n")
	if classes != "" {
		b.WriteString("      device_classes: " + classes + "\n")
	}
	for _, line := range extra {
		b.WriteString("      " + line + "\n")
	}
	return b.String()
}

// capsYAML renders a device_rules block of caps, each "class: keeps".
func capsYAML(caps ...[2]string) string {
	var b strings.Builder
	b.WriteString("device_rules:\n  caps:\n")
	for _, c := range caps {
		b.WriteString("    - device_class: " + c[0] + "\n      keeps: " + c[1] + "\n")
	}
	return b.String()
}

func TestDeviceRules_Loads(t *testing.T) {
	store, err := storeWithDeviceRules(t, publishRulesYAML)
	require.NoError(t, err)

	rules := store.DeviceRules()
	require.NotNil(t, rules)
	require.Len(t, rules.Requirements, 1)
	assert.Equal(t, chaindevice.Requirement{
		Grants:        []string{publishGrant},
		DeviceClasses: []string{chaindevice.ClassAttested},
		AppIDHashes:   []string{arkavoAppHash, arkavoCreatorAppHash},
		AppEnvs:       []string{chaindevice.EnvProduction},
	}, rules.Requirements[0])
	assert.Equal(t, []chaindevice.Cap{{
		DeviceClass: chaindevice.ClassManaged,
		Keeps:       []string{campaignDefinition, tierDefinition},
	}}, rules.Caps)
}

// The loaded rules decide as the design says (the chaindevice tests cover the
// semantics; this pins that the loader's output is what Keeps expects).
func TestDeviceRules_LoadedRulesDecide(t *testing.T) {
	store, err := storeWithDeviceRules(t, publishRulesYAML)
	require.NoError(t, err)
	rules := store.DeviceRules()

	attested := chaindevice.Device{
		Class: chaindevice.ClassAttested, Verified: true, Bound: true,
		AppIDHash: chaindevice.AppIDHash("M8GS7ZT95Y.com.arkavo.ArkavoCreator"), AppEnv: chaindevice.EnvProduction,
	}
	managed := chaindevice.Device{Class: chaindevice.ClassManaged, Verified: true, Bound: true}

	assert.False(t, rules.Keeps(nil, publishGrant), "no device")
	assert.True(t, rules.Keeps([]chaindevice.Device{attested}, publishGrant))
	assert.False(t, rules.Keeps([]chaindevice.Device{managed}, publishGrant))
	assert.True(t, rules.Keeps([]chaindevice.Device{managed}, campaignDefinition+"/value/13167240"))
	assert.False(t, rules.Keeps([]chaindevice.Device{managed}, "https://patreon.arkavo.com/attr/classification/value/public"))
}

func TestDeviceRules_StoresLowercase(t *testing.T) {
	store, err := storeWithDeviceRules(t, `
device_rules:
  requirements:
    - grants: [HTTPS://Patreon.Arkavo.com/attr/Arkavo-Creator/value/Publish]
      device_classes: [attested]
  caps:
    - device_class: managed
      keeps: [https://PATREON.arkavo.com/attr/Campaign]
`)
	require.NoError(t, err)
	rules := store.DeviceRules()
	require.NotNil(t, rules)
	assert.Equal(t, []string{publishGrant}, rules.Requirements[0].Grants)
	assert.Equal(t, []string{campaignDefinition}, rules.Caps[0].Keeps)
}

func TestDeviceRules_AppIDIsHashedAsWritten(t *testing.T) {
	store, err := storeWithDeviceRules(t, requirementYAML(
		"["+publishGrant+"]", "[attested]", "apps: [M8GS7ZT95Y.com.arkavo.Arkavo]",
	))
	require.NoError(t, err)
	assert.Equal(t, []string{arkavoAppHash}, store.DeviceRules().Requirements[0].AppIDHashes)
}

func TestDeviceRules_NoneDeclared(t *testing.T) {
	for name, rulesYAML := range map[string]string{
		"no section":              "",
		"null section":            "device_rules:\n",
		"section without entries": "device_rules:\n  requirements: []\n  caps: []\n",
	} {
		t.Run(name, func(t *testing.T) {
			store, err := storeWithDeviceRules(t, rulesYAML)
			require.NoError(t, err)
			assert.Nil(t, store.DeviceRules())
		})
	}

	var none *Store
	assert.Nil(t, none.DeviceRules(), "a nil store has no rules")
}

func TestDeviceRules_OptionalListsStayUnset(t *testing.T) {
	store, err := storeWithDeviceRules(t, requirementYAML("["+publishGrant+"]", "[attested]"))
	require.NoError(t, err)
	req := store.DeviceRules().Requirements[0]
	assert.Empty(t, req.AppIDHashes)
	assert.Empty(t, req.AppEnvs)
}

func TestDeviceRules_RejectsAtLoad(t *testing.T) {
	const (
		validGrant = "[" + publishGrant + "]"
		classified = deviceRulesDef + "classification"
	)
	for _, tc := range []struct {
		name    string
		rules   string
		wantErr string // names the offending entry
	}{
		{"FQN does not parse", requirementYAML("[https://x/attrs/y]", "[attested]"), "https://x/attrs/y"},
		{"FQN with a trailing slash", requirementYAML("["+deviceRulesDef+"campaign/]", "[attested]"), "campaign/"},
		{"empty FQN", requirementYAML(`[""]`, "[attested]"), "grants[0]"},
		{"undeclared definition", requirementYAML("["+deviceRulesDef+"nope]", "[attested]"), deviceRulesDef + "nope"},
		{
			"undeclared definition in a value FQN",
			requirementYAML("["+deviceRulesDef+"nope/value/x]", "[attested]"), deviceRulesDef + "nope/value/x",
		},
		{
			"undeclared value under declared values",
			requirementYAML("["+deviceRulesDef+"arkavo-creator/value/pubish]", "[attested]"), "pubish",
		},
		{
			"hierarchy value in grants",
			requirementYAML("["+classified+"/value/vip]", "[attested]"), "hierarchy",
		},
		{"hierarchy definition in grants", requirementYAML("["+classified+"]", "[attested]"), "hierarchy"},
		{"hierarchy definition in keeps", capsYAML([2]string{"managed", "[" + classified + "]"}), "hierarchy"},
		{"hierarchy value in keeps", capsYAML([2]string{"managed", "[" + classified + "/value/public]"}), classified},
		{"undeclared definition in keeps", capsYAML([2]string{"managed", "[" + deviceRulesDef + "nope]"}), deviceRulesDef + "nope"},
		{"keeps does not parse", capsYAML([2]string{"managed", "[https://x/attrs/y]"}), "https://x/attrs/y"},
		{"requirement names no grants", requirementYAML("[]", "[attested]"), "requirements[0]"},
		{"empty device_classes", requirementYAML(validGrant, "[]"), "device_classes"},
		{"missing device_classes", requirementYAML(validGrant, ""), "device_classes"},
		{"unknown class in a requirement", requirementYAML(validGrant, "[atested]"), "atested"},
		{"unknown class beside a known one", requirementYAML(validGrant, "[attested, managd]"), "managd"},
		{"unknown class in a cap", capsYAML([2]string{"atested", "[" + campaignDefinition + "]"}), "atested"},
		{"cap without a class", capsYAML([2]string{`""`, "[" + campaignDefinition + "]"}), "caps[0]"},
		{
			"two caps for managed",
			capsYAML([2]string{"managed", "[" + campaignDefinition + "]"}, [2]string{"managed", "[" + tierDefinition + "]"}),
			"managed",
		},
		{
			"app without a Team ID",
			requirementYAML(validGrant, "[attested]", "apps: [com.arkavo.Arkavo]"), "com.arkavo.Arkavo",
		},
		{
			"app with an empty bundle",
			requirementYAML(validGrant, "[attested]", "apps: [M8GS7ZT95Y.]"), "M8GS7ZT95Y.",
		},
		{
			"app with a short Team ID",
			requirementYAML(validGrant, "[attested]", "apps: [M8GS7ZT95.com.arkavo.Arkavo]"), "M8GS7ZT95.com.arkavo.Arkavo",
		},
		{
			"app with a lowercase Team ID",
			requirementYAML(validGrant, "[attested]", "apps: [m8gs7zt95y.com.arkavo.Arkavo]"), "m8gs7zt95y.com.arkavo.Arkavo",
		},
		{"empty app", requirementYAML(validGrant, "[attested]", `apps: [""]`), "apps[0]"},
		{"app env prod", requirementYAML(validGrant, "[attested]", "app_envs: [prod]"), "prod"},
		{"present but empty apps", requirementYAML(validGrant, "[attested]", "apps: []"), "apps"},
		{"present but empty app_envs", requirementYAML(validGrant, "[attested]", "app_envs: []"), "app_envs"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			store, err := storeWithDeviceRules(t, tc.rules)
			require.Error(t, err)
			assert.Nil(t, store)
			assert.Contains(t, err.Error(), "filestore: device_rules: ")
			assert.Contains(t, err.Error(), tc.wantErr)
		})
	}
}

func TestDeviceRules_UnknownClassFailsLoad(t *testing.T) {
	_, err := storeWithDeviceRules(t, requirementYAML("["+publishGrant+"]", "[atested]"))
	require.ErrorContains(t, err, `"atested"`)
	require.ErrorContains(t, err, "attested", "the message lists the classes there are")

	_, err = storeWithDeviceRules(t, capsYAML([2]string{"atested", "[" + campaignDefinition + "]"}))
	require.ErrorContains(t, err, `"atested"`)
}

func TestDeviceRules_SyntheticValueAccepted(t *testing.T) {
	store, err := storeWithDeviceRules(t, requirementYAML(
		"["+campaignDefinition+"/value/13167240]", "[attested]",
	))
	require.NoError(t, err)
	assert.Equal(t, []string{campaignDefinition + "/value/13167240"}, store.DeviceRules().Requirements[0].Grants)
}

func TestDeviceRules_DeclaredValueAndDefinitionAccepted(t *testing.T) {
	_, err := storeWithDeviceRules(t, requirementYAML(
		"["+publishGrant+", "+deviceRulesDef+"arkavo-creator]", "[attested, managed]",
	))
	require.NoError(t, err)
}

func TestDeviceRules_AppEnvsBothAccepted(t *testing.T) {
	store, err := storeWithDeviceRules(t, requirementYAML(
		"["+publishGrant+"]", "[attested]", "app_envs: [production, development]",
	))
	require.NoError(t, err)
	assert.Equal(t, []string{chaindevice.EnvProduction, chaindevice.EnvDevelopment},
		store.DeviceRules().Requirements[0].AppEnvs)
}

// A capped class that keeps nothing is a valid way to drop every grant.
func TestDeviceRules_CapThatKeepsNothingAccepted(t *testing.T) {
	store, err := storeWithDeviceRules(t, capsYAML([2]string{"unverified", "[]"}))
	require.NoError(t, err)
	rules := store.DeviceRules()
	require.Len(t, rules.Caps, 1)
	assert.Empty(t, rules.Caps[0].Keeps)
}
