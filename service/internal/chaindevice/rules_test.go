package chaindevice

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
)

const (
	campaignDef   = "https://patreon.arkavo.com/attr/campaign"
	campaignValue = campaignDef + "/value/13167240"
	tierDef       = "https://patreon.arkavo.com/attr/campaign-tier"
	tierValue     = tierDef + "/value/vip"
	decryptValue  = "https://patreon.arkavo.com/attr/action/value/decrypt"
	publish       = "https://patreon.arkavo.com/attr/action/value/publish"

	arkavoApp        = "543398d88f303adedb67445ee9edbf1e1733a73d92bf6992cfbf228d60763cf8"
	arkavoCreatorApp = "ea2defc9e7bf14b832b0fb5e4ada8f0af0e114dca9fc7741cda17d875cf1bc01"
)

func TestMatch_ValueAndDefinition(t *testing.T) {
	assert.True(t, Matches(publish, publish))
	assert.True(t, Matches(campaignDef, campaignDef+"/value/13167240"))
	assert.True(t, Matches(strings.ToUpper(publish), publish))
	assert.True(t, Matches(publish, strings.ToUpper(publish)))
	assert.True(t, Matches(strings.ToUpper(campaignDef), campaignValue))
	assert.True(t, Matches(campaignDef, strings.ToUpper(campaignValue)))
}

func TestMatch_DefinitionIsNotAPrefix(t *testing.T) {
	assert.False(t, Matches(campaignDef, tierDef+"/value/x"))
}

func TestMatch_ValueDoesNotCoverOthers(t *testing.T) {
	assert.False(t, Matches(campaignDef+"/value/vip", campaignDef+"/value/paid"))
	assert.False(t, Matches(campaignValue, campaignDef))
}

func TestAppIDHash(t *testing.T) {
	assert.Equal(t, arkavoApp, AppIDHash("M8GS7ZT95Y.com.arkavo.Arkavo"))
	assert.Equal(t, arkavoCreatorApp, AppIDHash("M8GS7ZT95Y.com.arkavo.ArkavoCreator"))
}

func TestKeeps_PublishRule(t *testing.T) {
	rules := &Rules{Requirements: []Requirement{{
		Grants:        []string{publish},
		DeviceClasses: []string{ClassAttested},
		AppIDHashes:   []string{arkavoApp, arkavoCreatorApp},
		AppEnvs:       []string{EnvProduction},
	}}}
	device := func(mutate func(*Device)) Device {
		d := Device{Class: ClassAttested, Verified: true, Bound: true, AppIDHash: arkavoApp, AppEnv: EnvProduction}
		if mutate != nil {
			mutate(&d)
		}
		return d
	}
	managed := device(func(d *Device) { d.Class = ClassManaged })
	for _, tc := range []struct {
		name    string
		devices []Device
		want    bool
	}{
		{"no devices", nil, false},
		{"attested, listed app, production", []Device{device(nil)}, true},
		{"second listed app", []Device{device(func(d *Device) { d.AppIDHash = arkavoCreatorApp })}, true},
		{"managed", []Device{managed}, false},
		{"development", []Device{device(func(d *Device) { d.AppEnv = EnvDevelopment })}, false},
		{"unknown env", []Device{device(func(d *Device) { d.AppEnv = "" })}, false},
		{"no app", []Device{device(func(d *Device) { d.AppIDHash = "" })}, false},
		{"unlisted app", []Device{device(func(d *Device) { d.AppIDHash = "deadbeef" })}, false},
		{"any one device meets it", []Device{managed, device(nil)}, true},
		{"the other order", []Device{device(nil), managed}, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, rules.Keeps(tc.devices, publish))
			// A grant no rule names is only affected by the device being bound.
			assert.True(t, rules.Keeps(tc.devices, campaignValue))
		})
	}
}

func TestKeeps_RequirementWithoutAppOrEnv(t *testing.T) {
	rules := &Rules{Requirements: []Requirement{{
		Grants:        []string{campaignDef},
		DeviceClasses: []string{ClassManaged, ClassAttested},
	}}}
	managed := Device{Class: ClassManaged, Verified: true, Bound: true}
	assert.True(t, rules.Keeps([]Device{managed}, campaignValue))
	assert.False(t, rules.Keeps([]Device{{Class: ClassUnverified, Verified: true, Bound: true}}, campaignValue))
	assert.False(t, rules.Keeps(nil, campaignValue))
}

// A device with no app or an unknown environment never meets a list that
// names one, even a list that holds the empty string.
func TestKeeps_EmptyEntryDoesNotMatchUnknown(t *testing.T) {
	rules := &Rules{Requirements: []Requirement{{
		Grants:        []string{publish},
		DeviceClasses: []string{ClassAttested},
		AppIDHashes:   []string{""},
		AppEnvs:       []string{""},
	}}}
	assert.False(t, rules.Keeps([]Device{{Class: ClassAttested, Verified: true, Bound: true}}, publish))
}

func TestKeeps_EveryMatchingRequirementMustBeMet(t *testing.T) {
	rules := &Rules{Requirements: []Requirement{
		{Grants: []string{campaignDef}, DeviceClasses: []string{ClassManaged, ClassAttested}},
		{Grants: []string{campaignValue}, DeviceClasses: []string{ClassAttested}},
	}}
	managed := Device{Class: ClassManaged, Verified: true, Bound: true}
	attested := Device{Class: ClassAttested, Verified: true, Bound: true}
	assert.False(t, rules.Keeps([]Device{managed}, campaignValue))
	assert.True(t, rules.Keeps([]Device{managed}, campaignDef+"/value/other"))
	assert.True(t, rules.Keeps([]Device{attested}, campaignValue))
}

func TestKeeps_Caps(t *testing.T) {
	managed := Device{Class: ClassManaged, Verified: true, Bound: true}
	attested := Device{Class: ClassAttested, Verified: true, Bound: true}

	t.Run("a cap keeps what it names and drops the rest", func(t *testing.T) {
		rules := &Rules{Caps: []Cap{{DeviceClass: ClassManaged, Keeps: []string{campaignDef, tierDef}}}}
		assert.True(t, rules.Keeps([]Device{managed}, campaignValue))
		assert.True(t, rules.Keeps([]Device{managed}, tierValue))
		assert.False(t, rules.Keeps([]Device{managed}, decryptValue))
	})
	t.Run("a class without a cap keeps everything", func(t *testing.T) {
		rules := &Rules{Caps: []Cap{{DeviceClass: ClassManaged, Keeps: []string{campaignDef, tierDef}}}}
		for _, fqn := range []string{campaignValue, tierValue, decryptValue} {
			assert.True(t, rules.Keeps([]Device{attested}, fqn), fqn)
		}
	})
	t.Run("caps of different classes intersect", func(t *testing.T) {
		rules := &Rules{Caps: []Cap{
			{DeviceClass: ClassManaged, Keeps: []string{campaignDef}},
			{DeviceClass: ClassAttested, Keeps: []string{tierDef}},
		}}
		both := []Device{managed, attested}
		for _, fqn := range []string{campaignValue, tierValue, decryptValue} {
			assert.False(t, rules.Keeps(both, fqn), fqn)
		}
	})
	t.Run("a cap on a class no device has does nothing", func(t *testing.T) {
		rules := &Rules{Caps: []Cap{{DeviceClass: ClassManaged, Keeps: nil}}}
		assert.True(t, rules.Keeps(nil, decryptValue))
		assert.True(t, rules.Keeps([]Device{attested}, decryptValue))
	})
	t.Run("a cap with nothing to keep drops everything", func(t *testing.T) {
		rules := &Rules{Caps: []Cap{{DeviceClass: ClassManaged}}}
		assert.False(t, rules.Keeps([]Device{managed}, campaignValue))
	})
}

func TestKeeps_UnboundDeniesAll(t *testing.T) {
	unbound := []Device{{Class: ClassAttested, Verified: true, Bound: false}}
	for name, rules := range map[string]*Rules{"nil": nil, "empty": {}} {
		t.Run(name, func(t *testing.T) {
			for _, fqn := range []string{campaignValue, tierValue, decryptValue, publish} {
				assert.False(t, rules.Keeps(unbound, fqn), fqn)
			}
			assert.True(t, rules.Keeps(nil, campaignValue))
		})
	}
}

func TestKeeps_OneUnboundDeviceDeniesEvenWhenAnotherMeetsTheRule(t *testing.T) {
	rules := &Rules{Requirements: []Requirement{{Grants: []string{publish}, DeviceClasses: []string{ClassAttested}}}}
	good := Device{Class: ClassAttested, Verified: true, Bound: true}
	stray := Device{Class: ClassManaged, Verified: true, Bound: false}
	assert.False(t, rules.Keeps([]Device{good, stray}, publish))
	assert.False(t, rules.Keeps([]Device{good, stray}, campaignValue))
}

func TestNarrows(t *testing.T) {
	device := []Device{{Class: ClassManaged, Verified: true, Bound: true}}
	var nilRules *Rules
	assert.False(t, nilRules.Narrows(nil))
	assert.False(t, (&Rules{}).Narrows(nil))
	assert.True(t, nilRules.Narrows(device))
	assert.True(t, (&Rules{}).Narrows(device))
	assert.True(t, (&Rules{Requirements: []Requirement{{Grants: []string{publish}}}}).Narrows(nil))
}

// Why names the first check Keeps fails, in Keeps' order: an unbound device,
// then a requirement, then a cap.
func TestWhy(t *testing.T) {
	attested := Device{Class: ClassAttested, Verified: true, Bound: true}
	managed := Device{Class: ClassManaged, Verified: true, Bound: true}
	unbound := Device{Class: ClassAttested, Verified: true}
	rules := &Rules{
		Requirements: []Requirement{{Grants: []string{publish}, DeviceClasses: []string{ClassAttested}}},
		Caps:         []Cap{{DeviceClass: ClassManaged, Keeps: []string{campaignDef}}},
	}
	var noRules *Rules

	for _, tc := range []struct {
		name    string
		rules   *Rules
		devices []Device
		fqn     string
		want    string
	}{
		{"kept", rules, []Device{attested}, publish, ""},
		{"no rule names it", rules, nil, campaignValue, ""},
		{"unbound, no rules", noRules, []Device{unbound}, campaignValue, WhyUnboundDevice},
		{"unbound beside a device that meets the requirement", rules, []Device{attested, unbound}, publish, WhyUnboundDevice},
		{"requirement, no device", rules, nil, publish, WhyRequirement},
		{"requirement and cap both fail: the requirement is named", rules, []Device{managed}, publish, WhyRequirement},
		{"cap", rules, []Device{managed}, tierValue, WhyCap},
		{"cap beside a device that meets the requirement", rules, []Device{attested, managed}, publish, WhyCap},
	} {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, tc.rules.Why(tc.devices, tc.fqn))
		})
	}
}

// Why explains Keeps and never disagrees with it: it is empty exactly when
// Keeps keeps the grant, for every rule set, device set and FQN tried.
func TestWhy_AgreesWithKeeps(t *testing.T) {
	ruleSets := map[string]*Rules{
		"nil":   nil,
		"empty": {},
		"requirement": {Requirements: []Requirement{{
			Grants: []string{publish, tierDef}, DeviceClasses: []string{ClassAttested},
			AppIDHashes: []string{arkavoApp}, AppEnvs: []string{EnvProduction},
		}}},
		"caps": {Caps: []Cap{
			{DeviceClass: ClassManaged, Keeps: []string{campaignDef, tierDef}},
			{DeviceClass: ClassUnverified},
		}},
		"both": {
			Requirements: []Requirement{{Grants: []string{publish}, DeviceClasses: []string{ClassAttested, ClassManaged}}},
			Caps:         []Cap{{DeviceClass: ClassManaged, Keeps: []string{campaignDef, publish}}},
		},
	}
	attested := Device{Class: ClassAttested, Verified: true, Bound: true, AppIDHash: arkavoApp, AppEnv: EnvProduction}
	devSets := [][]Device{
		nil,
		{attested},
		{{Class: ClassAttested, Verified: true, Bound: true}},
		{{Class: ClassManaged, Verified: true, Bound: true}},
		{{Class: ClassUnverified, Verified: true, Bound: true}},
		{{Class: ClassUnverified}},
		{attested, {Class: ClassManaged, Verified: true, Bound: true}},
		{attested, {Class: ClassManaged, Verified: true}},
	}
	reasons := []string{"", WhyUnboundDevice, WhyRequirement, WhyCap}
	for name, rules := range ruleSets {
		for i, devices := range devSets {
			for _, fqn := range []string{publish, campaignValue, tierValue, decryptValue} {
				why := rules.Why(devices, fqn)
				assert.Contains(t, reasons, why)
				assert.Equal(t, rules.Keeps(devices, fqn), why == "", "rules %s, devices %d, %s: Why %q", name, i, fqn, why)
			}
		}
	}
}
