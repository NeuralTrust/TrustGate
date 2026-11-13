// Copyright 2026 NeuralTrust
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package mcp

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"sort"
	"time"

	appconsumer "github.com/NeuralTrust/TrustGate/pkg/app/consumer"
	"github.com/NeuralTrust/TrustGate/pkg/common/logref"
	consumerdomain "github.com/NeuralTrust/TrustGate/pkg/domain/consumer"
	"github.com/NeuralTrust/TrustGate/pkg/domain/identity"
	"github.com/NeuralTrust/TrustGate/pkg/domain/ids"
	registrydomain "github.com/NeuralTrust/TrustGate/pkg/domain/registry"
	vaultdomain "github.com/NeuralTrust/TrustGate/pkg/domain/vault"
)

// Cause codes for a call refused because a per-user header has no usable value.
const (
	// ConsentCauseUserHeaderMissing: the caller never entered a value.
	ConsentCauseUserHeaderMissing = "user_header_missing"
	// ConsentCauseUserHeaderRejected: the upstream answered 401 with the value
	// this caller entered, so it has to be entered again.
	ConsentCauseUserHeaderRejected = "user_header_rejected"
)

// applyUserHeaders sets the calling person's own value for every per-user
// header the registry declares. A required header without a usable value
// refuses the call with a connect link; an optional one is left out.
//
// A caller with no individual identity is refused before the vault is read:
// the application itself, or a group key whose owner's value would otherwise
// be sent on behalf of everyone holding the key.
func (r *credentialResolver) applyUserHeaders(
	ctx context.Context,
	rc *appconsumer.RoutableConsumer,
	reg *registrydomain.Registry,
	target *Target,
) error {
	if reg == nil || !reg.MCPTarget.HasUserHeaders() {
		return nil
	}
	principal := identity.PrincipalFromContext(ctx)
	if principal == nil || principal.Subject == "" {
		return ErrNoPrincipal
	}
	label := registryLabelFor(reg)
	if principal.KeyGroup() != "" || principal.Subject == consumerdomain.AppSubject(rc.Consumer.ID) {
		return &ApplicationNotConnectedError{Provider: label, Registry: label, UserKeys: true}
	}
	gatewayID := rc.Consumer.GatewayID
	if target.Headers == nil {
		target.Headers = map[string]string{}
	}
	resolved := make([]string, 0, len(reg.MCPTarget.UserHeaders))
	for _, h := range reg.MCPTarget.UserHeaders {
		value, cause, err := r.userHeaderValue(ctx, gatewayID, principal.Subject, reg, h)
		if err != nil {
			return err
		}
		if cause != "" {
			if !h.Required {
				continue
			}
			return r.consentRequired(ctx, rc, reg, label, principal.Subject, cause,
				"no usable value for a per-user upstream header", "header", h.Name)
		}
		target.Headers[h.Name] = h.FormatValue(value)
		resolved = append(resolved, h.Name+"\x00"+value)
	}
	// One person's upstream session is never reused for another, and a value
	// the person replaced dials a fresh session instead of riding the old one.
	sort.Strings(resolved)
	sum := sha256.New()
	sum.Write([]byte(principal.Issuer + "\x00" + principal.Subject))
	for _, v := range resolved {
		sum.Write([]byte{0})
		sum.Write([]byte(v))
	}
	target.PinKey += ":h:" + hex.EncodeToString(sum.Sum(nil)[:8])
	return nil
}

// userHeaderValue reads one person's value for one header. A non-empty cause
// means there is no usable value and says why; err is a vault failure.
func (r *credentialResolver) userHeaderValue(
	ctx context.Context,
	gatewayID ids.GatewayID,
	subject string,
	reg *registrydomain.Registry,
	h registrydomain.MCPUserHeader,
) (value, cause string, err error) {
	if r.vault == nil {
		return "", ConsentCauseUserHeaderMissing, nil
	}
	cred, err := r.vault.Find(ctx, gatewayID, subject, registrydomain.UserHeaderVaultProvider(reg.ID, h.Name))
	switch {
	case errors.Is(err, vaultdomain.ErrNotFound):
		return "", ConsentCauseUserHeaderMissing, nil
	case errors.Is(err, vaultdomain.ErrUndecryptable):
		return "", ConsentCauseUndecryptable, nil
	case err != nil:
		return "", "", err
	}
	if cred == nil || cred.AccessToken == "" {
		return "", ConsentCauseUserHeaderMissing, nil
	}
	if UserHeaderRejected(cred) {
		return "", ConsentCauseUserHeaderRejected, nil
	}
	return cred.AccessToken, "", nil
}

// UserHeaderRejected reports whether a stored per-user header value was
// refused by the upstream. A value carries no expiry of its own; the vault's
// reconnect mark (an expiry set to the moment of the refusal) is what records
// that the upstream answered 401 with it.
func UserHeaderRejected(cred *vaultdomain.Credential) bool {
	return cred != nil && !cred.ExpiresAt.IsZero() && !cred.ExpiresAt.After(time.Now())
}

// rejectUserHeaders marks the per-user header values the caller sent to this
// registry as refused, after the upstream answered 401. Only a value that is
// still the one sent is marked: a person who replaced their key while the call
// was in flight keeps the new one. It reports whether a value was marked, so
// the caller can tell the person to enter it again rather than retry.
func (r *credentialResolver) rejectUserHeaders(
	ctx context.Context,
	rc *appconsumer.RoutableConsumer,
	reg *registrydomain.Registry,
	target *Target,
) bool {
	if r.vault == nil || reg == nil || !reg.MCPTarget.HasUserHeaders() {
		return false
	}
	principal := identity.PrincipalFromContext(ctx)
	if principal == nil || principal.Subject == "" {
		return false
	}
	requirer, ok := r.vault.(vaultdomain.ReconnectRequirer)
	if !ok {
		return false
	}
	gatewayID := rc.Consumer.GatewayID
	marked := false
	for _, h := range reg.MCPTarget.UserHeaders {
		provider := registrydomain.UserHeaderVaultProvider(reg.ID, h.Name)
		cred, err := r.vault.Find(ctx, gatewayID, principal.Subject, provider)
		if err != nil || cred == nil || UserHeaderRejected(cred) {
			continue
		}
		if target == nil || target.Headers[h.Name] != h.FormatValue(cred.AccessToken) {
			continue
		}
		if err := requirer.RequireReconnect(ctx, cred); err != nil && !errors.Is(err, vaultdomain.ErrCredentialChanged) {
			r.logger.Warn("mcp user headers: could not mark a rejected value",
				"gateway_id", gatewayID.String(), "registry_id", reg.ID.String(),
				"principal_ref", logref.Opaque(principal.Subject), "header", h.Name, "error", err)
			continue
		}
		marked = true
		r.logger.Info("security audit",
			"event", "mcp_user_header_rejected",
			"gateway_id", gatewayID.String(), "registry_id", reg.ID.String(),
			"principal_ref", logref.Opaque(principal.Subject), "header", h.Name)
	}
	return marked
}

// refuseRejectedUserHeaders answers an upstream 401 on a registry whose only
// credential is its per-user headers: the values are marked refused and the
// caller gets a connect link to enter them again. The call is not retried,
// since the same values would be refused again.
//
// A 401 does not say which credential failed. When the auth mode sends one of
// its own — the admin's static key, a client-credentials token, the caller's
// forwarded or exchanged token — that one may be the cause, and marking every
// caller's key refused would make all of them enter it again for nothing, so
// the 401 is returned as it is.
func (r *credentialResolver) refuseRejectedUserHeaders(
	ctx context.Context,
	rc *appconsumer.RoutableConsumer,
	reg *registrydomain.Registry,
	target *Target,
) error {
	if auth := reg.MCPTarget.Auth; auth != nil && auth.Mode != registrydomain.MCPAuthModeNone && auth.Mode != "" {
		return errCredentialRefreshUnsupported
	}
	if !r.rejectUserHeaders(ctx, rc, reg, target) {
		return errCredentialRefreshUnsupported
	}
	principal := identity.PrincipalFromContext(ctx)
	label := registryLabelFor(reg)
	return r.consentRequired(ctx, rc, reg, label, principal.Subject, ConsentCauseUserHeaderRejected,
		"the upstream refused this caller's per-user header value")
}
