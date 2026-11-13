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

package oauth

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"time"

	appconsumer "github.com/NeuralTrust/TrustGate/pkg/app/consumer"
	"github.com/NeuralTrust/TrustGate/pkg/common/logref"
	"github.com/NeuralTrust/TrustGate/pkg/domain/ids"
	registrydomain "github.com/NeuralTrust/TrustGate/pkg/domain/registry"
	vaultdomain "github.com/NeuralTrust/TrustGate/pkg/domain/vault"
)

var (
	// ErrUserHeaderServerNotFound: the ticket cannot act on a server with
	// per-user headers by that instance id.
	ErrUserHeaderServerNotFound = errors.New("oauth connect: no server with per-user headers by that id on this link")
	// ErrUserHeaderInvalid wraps a value or field the form cannot accept. The
	// text names the header, never the value.
	ErrUserHeaderInvalid = errors.New("oauth connect: invalid per-user header value")
)

// Audit events for per-user header values. They carry the header name and an
// opaque principal reference, never the value.
const (
	UserHeaderAuditSet      = "mcp_user_header_set"
	UserHeaderAuditRemoved  = "mcp_user_header_removed"
	UserHeaderAuditReset    = "mcp_user_header_reset"
	UserHeaderAuditImported = "mcp_user_header_imported"
)

// UserHeaderField is one per-user header as the connect page shows it to the
// person whose value it is.
type UserHeaderField struct {
	Name        string
	Description string
	Required    bool
	Secret      bool
	// Set reports whether the person has a value stored.
	Set bool
	// Rejected reports whether the upstream refused the stored value, so it
	// has to be entered again.
	Rejected bool
	// Value is the stored value of a non-secret header, shown so the person
	// can check and edit it. Always empty for a secret header.
	Value string
	// UpdatedAt is when the value was last written; zero when unset.
	UpdatedAt time.Time
}

// UserHeaderServer is one registry instance whose upstream needs the
// person's own header values.
type UserHeaderServer struct {
	Registry string
	Instance string
	Code     string
	Fields   []UserHeaderField
}

// Missing reports whether a required header has no usable value, so a call
// to this server is refused until the person enters it.
func (s UserHeaderServer) Missing() bool {
	for _, f := range s.Fields {
		if f.Required && (!f.Set || f.Rejected) {
			return true
		}
	}
	return false
}

// UserHeaderEnrollment writes and removes a person's per-user header values
// through the connect link they were handed. The link is the authority, as it
// is for connecting an OAuth account: it names the principal the values are
// stored for.
type UserHeaderEnrollment interface {
	// SaveUserHeaders stores the values entered for one instance. A secret
	// field sent empty keeps the stored value; unknown fields are refused.
	SaveUserHeaders(ctx context.Context, ticketID, instanceID string, values map[string]string) error
	// RemoveUserHeaders deletes every value the person holds for one instance.
	RemoveUserHeaders(ctx context.Context, ticketID, instanceID string) error
}

var _ UserHeaderEnrollment = (*connectService)(nil)

// userHeaderServers lists the instances this ticket can enter header values
// for. An application's ticket has none: an application has no individual
// identity to hold a person's key, and the runtime refuses it before reading
// one.
func (s *connectService) userHeaderServers(
	ctx context.Context,
	gatewayID ids.GatewayID,
	ticket *ConnectTicket,
	data *appconsumer.Data,
	rc *appconsumer.RoutableConsumer,
) ([]UserHeaderServer, error) {
	if ticket.Providers != nil || strings.TrimSpace(ticket.PrincipalSub) == "" {
		return nil, nil
	}
	var out []UserHeaderServer
	for _, reg := range data.EffectiveRegistries(rc) {
		if !userHeaderRegistryAllowed(ticket, reg) {
			continue
		}
		server := UserHeaderServer{Registry: reg.Name, Instance: reg.ID.String(), Code: reg.MCPTarget.Code}
		for _, h := range reg.MCPTarget.UserHeaders {
			field := UserHeaderField{Name: h.Name, Description: h.Description, Required: h.Required, Secret: h.Secret}
			cred, err := s.vault.Find(ctx, gatewayID, ticket.PrincipalSub, registrydomain.UserHeaderVaultProvider(reg.ID, h.Name))
			switch {
			case err == nil && cred != nil && cred.AccessToken != "":
				field.Set = true
				field.Rejected = !cred.ExpiresAt.IsZero() && !cred.ExpiresAt.After(time.Now())
				field.UpdatedAt = cred.UpdatedAt
				if !h.Secret {
					field.Value = cred.AccessToken
				}
			case errors.Is(err, vaultdomain.ErrUndecryptable):
				field.Set = true
				field.Rejected = true
			case err != nil && !errors.Is(err, vaultdomain.ErrNotFound):
				return nil, fmt.Errorf("oauth connect: read per-user header: %w", err)
			}
			server.Fields = append(server.Fields, field)
		}
		out = append(out, server)
	}
	return out, nil
}

// userHeaderRegistryAllowed reports whether a person's ticket may show and
// write header values for reg. A ticket pinned to an instance reaches that
// instance only; one pinned to an OAuth provider reaches no header server.
func userHeaderRegistryAllowed(ticket *ConnectTicket, reg *registrydomain.Registry) bool {
	if reg == nil || !reg.Enabled || !reg.IsMCP() || !reg.MCPTarget.HasUserHeaders() {
		return false
	}
	if pinned := strings.TrimSpace(ticket.InstanceID); pinned != "" {
		return pinned == reg.ID.String()
	}
	if code := strings.TrimSpace(ticket.Code); code != "" {
		return code == strings.TrimSpace(reg.MCPTarget.Code)
	}
	return strings.TrimSpace(ticket.Provider) == ""
}

func (s *connectService) userHeaderRegistry(
	ctx context.Context,
	ticketID, instanceID string,
) (*ConnectTicket, ids.GatewayID, *registrydomain.Registry, error) {
	ticket, gatewayID, data, rc, err := s.resolve(ctx, ticketID)
	if err != nil {
		return nil, ids.GatewayID{}, nil, err
	}
	if ticket.Providers != nil || strings.TrimSpace(ticket.PrincipalSub) == "" {
		return nil, ids.GatewayID{}, nil, ErrUserHeaderServerNotFound
	}
	for _, reg := range data.EffectiveRegistries(rc) {
		if reg != nil && reg.ID.String() == instanceID && userHeaderRegistryAllowed(ticket, reg) {
			return ticket, gatewayID, reg, nil
		}
	}
	return nil, ids.GatewayID{}, nil, ErrUserHeaderServerNotFound
}

func (s *connectService) SaveUserHeaders(ctx context.Context, ticketID, instanceID string, values map[string]string) error {
	ticket, gatewayID, reg, err := s.userHeaderRegistry(ctx, ticketID, instanceID)
	if err != nil {
		return err
	}
	for name := range values {
		if _, ok := reg.MCPTarget.UserHeader(name); !ok {
			return fmt.Errorf("%w: %q is not a header of this server", ErrUserHeaderInvalid, name)
		}
	}
	// Every value is checked before any is written, so a bad field never
	// leaves the person half enrolled.
	writes := make(map[string]string, len(values))
	for _, h := range reg.MCPTarget.UserHeaders {
		value, sent := lookupFold(values, h.Name)
		value = strings.TrimSpace(value)
		if !sent || value == "" {
			if !h.Required {
				continue
			}
			if _, err := s.vault.Find(ctx, gatewayID, ticket.PrincipalSub, registrydomain.UserHeaderVaultProvider(reg.ID, h.Name)); err == nil {
				continue
			}
			return fmt.Errorf("%w: header %q needs a value", ErrUserHeaderInvalid, h.Name)
		}
		if err := registrydomain.ValidateUserHeaderValue(h, value); err != nil {
			return fmt.Errorf("%w: %w", ErrUserHeaderInvalid, err)
		}
		writes[h.Name] = value
	}
	for name, value := range writes {
		if err := WriteUserHeaderValue(ctx, s.vault, gatewayID, ticket.PrincipalSub, reg.ID, name, value); err != nil {
			return err
		}
		AuditUserHeader(ctx, UserHeaderAuditSet, gatewayID, reg.ID, ticket.PrincipalSub, name, "self")
	}
	return nil
}

func (s *connectService) RemoveUserHeaders(ctx context.Context, ticketID, instanceID string) error {
	ticket, gatewayID, reg, err := s.userHeaderRegistry(ctx, ticketID, instanceID)
	if err != nil {
		return err
	}
	for _, h := range reg.MCPTarget.UserHeaders {
		err := s.vault.Delete(ctx, gatewayID, ticket.PrincipalSub, registrydomain.UserHeaderVaultProvider(reg.ID, h.Name))
		if err != nil && !errors.Is(err, vaultdomain.ErrNotFound) {
			return err
		}
		if err == nil {
			AuditUserHeader(ctx, UserHeaderAuditRemoved, gatewayID, reg.ID, ticket.PrincipalSub, h.Name, "self")
		}
	}
	return nil
}

// WriteUserHeaderValue stores one person's value for one header of one
// registry instance. Writing clears a refusal mark: the value is new.
func WriteUserHeaderValue(
	ctx context.Context,
	vault vaultdomain.Repository,
	gatewayID ids.GatewayID,
	principalSub string,
	registryID ids.RegistryID,
	header, value string,
) error {
	cred, err := vaultdomain.NewCredential(gatewayID, principalSub,
		registrydomain.UserHeaderVaultProvider(registryID, header), "", value, "", nil, time.Time{})
	if err != nil {
		return err
	}
	return vault.Upsert(ctx, cred)
}

// AuditUserHeader records a change to a person's header value, without it.
// actor says who made it: "self", "admin" or "upstream".
func AuditUserHeader(
	ctx context.Context,
	event string,
	gatewayID ids.GatewayID,
	registryID ids.RegistryID,
	principalSub, header, actor string,
) {
	slog.InfoContext(ctx, "security audit",
		slog.String("event", event),
		slog.String("gateway_id", gatewayID.String()),
		slog.String("registry_id", registryID.String()),
		slog.String("principal_ref", logref.Opaque(principalSub)),
		slog.String("header", header),
		slog.String("actor", actor),
	)
}

func lookupFold(values map[string]string, name string) (string, bool) {
	if v, ok := values[name]; ok {
		return v, true
	}
	for k, v := range values {
		if strings.EqualFold(k, name) {
			return v, true
		}
	}
	return "", false
}
