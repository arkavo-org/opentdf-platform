package composite

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"maps"
	"slices"
	"strings"
	"time"

	"github.com/opentdf/platform/protocol/go/entity"
	"github.com/opentdf/platform/service/entityresolution/source"
	"github.com/opentdf/platform/service/internal/agentstatus"
	"github.com/opentdf/platform/service/internal/chaindevice"
)

// claimCnf is the RFC 7800 confirmation claim. On a device token it binds the
// device's key.
const claimCnf = "cnf"

// npeAttestationExpiry is the arkavo_npe member of a device token that says
// until when, a numeric date, its class attested holds. authnz-rs sets it 15
// minutes after the device's last App Attest assertion, while the token lasts
// an hour.
const npeAttestationExpiry = "attestation_expiry"

// Why a device does not bind, as logged.
const (
	unboundNotVerified     = "not verified"
	unboundNoSubjects      = "no subjects"
	unboundIssMismatch     = "iss mismatch"
	unboundAccountMismatch = "account mismatch"
)

// resolvedEntry is one entity of a ResolveEntities request once resolved:
// its evidence, the device it is, if any, and the iss and arkavo_account_id it
// was resolved as, by which devices bind (see bindDevices).
type resolvedEntry struct {
	id       string
	category entity.Entity_Category
	ev       evidence
	device   *chaindevice.Device
	iss      string
	account  string
}

// deviceFromClaims is the device a device token's claims describe at now.
// Only a verified token says anything: its arkavo_npe gives the class,
// unverified when it is missing or not one of chaindevice.Classes, and
// attested only until its attestation_expiry (see classAt); the app ID hash,
// lowercased; and the app environment, empty unless it is production or
// development. A token that is not verified is an unverified device with no
// app. Binding is decided later, by bindDevices.
func deviceFromClaims(claims map[string]any, verified bool, now time.Time) chaindevice.Device {
	if !verified {
		return chaindevice.Device{Class: chaindevice.ClassUnverified}
	}
	npe, _ := claims[agentstatus.ClaimNpe].(map[string]any)
	class, _ := npe["class"].(string)
	if !slices.Contains(chaindevice.Classes, class) {
		class = chaindevice.ClassUnverified
	}
	class = classAt(class, attestationExpiry(claims), now)
	appIDHash, _ := npe["app_id_hash"].(string)
	appEnv, _ := npe["app_env"].(string)
	if appEnv != chaindevice.EnvProduction && appEnv != chaindevice.EnvDevelopment {
		appEnv = ""
	}
	return chaindevice.Device{
		Class:     class,
		Verified:  true,
		AppIDHash: strings.ToLower(appIDHash),
		AppEnv:    appEnv,
	}
}

// attestationExpiry is the attestation_expiry in a device token's arkavo_npe,
// in unix seconds, read as numericDate reads exp; 0 when it is absent or not a
// numeric date.
func attestationExpiry(claims map[string]any) int64 {
	npe, _ := claims[agentstatus.ClaimNpe].(map[string]any)
	expiry, ok := numericDate(npe[npeAttestationExpiry])
	if !ok {
		return 0
	}
	return expiry.Unix()
}

// classAt is a device's class at now, given its attestation expiry in unix
// seconds: attested lapses to managed unless now is before the expiry, so an
// expiry that is absent (0) or passed reads managed. Every other class is
// what it is.
func classAt(class string, attestationExpiry int64, now time.Time) string {
	if class == chaindevice.ClassAttested && attestationExpiry <= now.Unix() {
		return chaindevice.ClassManaged
	}
	return class
}

// personClaims are the claims of the person a device token used as the
// subject carries: a copy of claims without arkavo_npe and cnf, which are the
// device's, and with DeviceCheckAudience removed from aud, so KindOf judges
// them a person's. aud goes when nothing is left in it. claims is not
// modified.
func personClaims(claims map[string]any) map[string]any {
	person := maps.Clone(claims)
	delete(person, agentstatus.ClaimNpe)
	delete(person, claimCnf)
	if aud, kept := withoutAudience(person["aud"], source.DeviceCheckAudience); kept {
		person["aud"] = aud
	} else {
		delete(person, "aud")
	}
	return person
}

// withoutAudience returns aud, a string or a list as KindOf reads it, without
// drop, in a new list, and false when nothing is left. A list keeps the
// entries that are not strings. Any other aud is returned as it is.
func withoutAudience(aud any, drop string) (any, bool) {
	switch v := aud.(type) {
	case nil:
		return nil, false
	case string:
		return v, v != drop
	case []any:
		kept := make([]any, 0, len(v))
		for _, a := range v {
			if s, isString := a.(string); !isString || s != drop {
				kept = append(kept, a)
			}
		}
		return kept, len(kept) > 0
	case []string:
		kept := make([]string, 0, len(v))
		for _, s := range v {
			if s != drop {
				kept = append(kept, s)
			}
		}
		return kept, len(kept) > 0
	}
	return aud, true
}

// deviceTokenEntity resolves the claims entity id that carries token under
// chaindevice.TokenClaim. The token is verified with its issuer's verifier
// whoever the caller, since its signature is what is trusted, as with sealed
// evidence. A verified token that KindOf judges a device gives the device,
// and the evidence the token's iss and arkavo_account_id to bind it by.
// Anything else is an unverified device. The sources never resolve the
// entity, so its evidence holds no grants.
func (s *Service) deviceTokenEntity(ctx context.Context, id string, token any) (evidence, *chaindevice.Device) {
	claims, err := s.verifyDeviceToken(ctx, token)
	if err != nil {
		// Never log the token itself.
		s.logger.WarnContext(
			ctx, "composite: device token is not a verified device token; the device is unverified",
			slog.String("entity_id", id),
			slog.Any("error", err),
		)
		device := deviceFromClaims(nil, false, s.now())
		return evidence{}, &device
	}
	iss, _ := claims["iss"].(string)
	accountID, _ := claims[claimAccountID].(string)
	device := deviceFromClaims(claims, true, s.now())
	return evidence{Iss: iss, AccountID: accountID}, &device
}

// verifyDeviceToken returns the claims of token when it is a string that
// verifyToken accepts and KindOf judges a device's.
func (s *Service) verifyDeviceToken(ctx context.Context, token any) (map[string]any, error) {
	raw, isString := token.(string)
	if !isString {
		return nil, fmt.Errorf("%s is %T, not a string", chaindevice.TokenClaim, token)
	}
	claims, _, err := s.verifyToken(ctx, raw)
	if err != nil {
		return nil, err
	}
	if source.KindOf(claims) != source.KindDevice {
		return nil, errors.New("the token is not a device token")
	}
	return claims, nil
}

// sealedDeviceOf is the device sealed into ev, if any, at now. It was
// verified with the token the evidence was resolved from, but the evidence
// lasts as long as the token, so a device sealed attested reads managed once
// its sealed attestation expiry has passed, as in a chain (see classAt).
// bindDevices decides whether it binds, as for any other device.
func sealedDeviceOf(ev evidence, now time.Time) *chaindevice.Device {
	if ev.Device == nil {
		return nil
	}
	return &chaindevice.Device{
		Class:     classAt(ev.Device.Class, ev.Device.AttestationExpiry, now),
		Verified:  true,
		AppIDHash: ev.Device.AppIDHash,
		AppEnv:    ev.Device.AppEnv,
	}
}

// bindDevices sets Bound on the device of every entry that has one: whether
// unboundReason finds none.
func bindDevices(entries []resolvedEntry) {
	for i := range entries {
		if entries[i].device != nil {
			reason, _ := unboundReason(entries[i], entries)
			entries[i].device.Bound = reason == ""
		}
	}
}

// unboundReason says why the device of dev does not bind to the request's
// subjects, or "" when it binds, and names the subject that failed it, if
// any. A device binds only if it is verified, the request has at least one
// subject (an entity of any category but environment), and every subject has
// a non-empty iss and arkavo_account_id equal to the device's. A sealed
// device is its own subject's, so in a chain of that subject alone it binds
// when its evidence carries both.
func unboundReason(dev resolvedEntry, entries []resolvedEntry) (string, string) {
	if !dev.device.Verified {
		return unboundNotVerified, ""
	}
	subjects := 0
	for _, e := range entries {
		if e.category == entity.Entity_CATEGORY_ENVIRONMENT {
			continue
		}
		subjects++
		if e.iss == "" || e.iss != dev.iss {
			return unboundIssMismatch, e.id
		}
		if e.account == "" || e.account != dev.account {
			return unboundAccountMismatch, e.id
		}
	}
	if subjects == 0 {
		return unboundNoSubjects, ""
	}
	return "", ""
}

// logUnbound logs why the device of dev, which bindDevices left unbound, does
// not bind. Neither the token nor the identities compared are logged.
func (s *Service) logUnbound(ctx context.Context, dev resolvedEntry, entries []resolvedEntry) {
	reason, subjectID := unboundReason(dev, entries)
	attrs := []slog.Attr{
		slog.String("entity_id", dev.id),
		slog.String("reason", reason),
	}
	if subjectID != "" {
		attrs = append(attrs, slog.String("subject_id", subjectID))
	}
	s.logger.LogAttrs(ctx, slog.LevelWarn, "composite: device is not bound to the request's subjects; the chain is denied", attrs...)
}
