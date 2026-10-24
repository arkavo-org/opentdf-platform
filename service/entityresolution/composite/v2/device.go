package composite

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"slices"
	"strings"

	"github.com/opentdf/platform/protocol/go/entity"
	"github.com/opentdf/platform/service/entityresolution/source"
	"github.com/opentdf/platform/service/internal/agentstatus"
	"github.com/opentdf/platform/service/internal/chaindevice"
)

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

// deviceFromClaims is the device a device token's claims describe. Only a
// verified token says anything: its arkavo_npe gives the class, unverified
// when it is missing or not one of chaindevice.Classes; the app ID hash,
// lowercased; and the app environment, empty unless it is production or
// development. A token that is not verified is an unverified device with no
// app. Binding is decided later, by bindDevices.
func deviceFromClaims(claims map[string]any, verified bool) chaindevice.Device {
	if !verified {
		return chaindevice.Device{Class: chaindevice.ClassUnverified}
	}
	npe, _ := claims[agentstatus.ClaimNpe].(map[string]any)
	class, _ := npe["class"].(string)
	if !slices.Contains(chaindevice.Classes, class) {
		class = chaindevice.ClassUnverified
	}
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
		device := deviceFromClaims(nil, false)
		return evidence{}, &device
	}
	iss, _ := claims["iss"].(string)
	accountID, _ := claims[claimAccountID].(string)
	device := deviceFromClaims(claims, true)
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

// sealedDeviceOf is the device sealed into ev, if any. It was verified with
// the token the evidence was resolved from; bindDevices decides whether it
// binds, as for any other device.
func sealedDeviceOf(ev evidence) *chaindevice.Device {
	if ev.Device == nil {
		return nil
	}
	return &chaindevice.Device{
		Class:     ev.Device.Class,
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
// by construction.
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
