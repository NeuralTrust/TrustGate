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

package registry

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"sort"
	"strings"
	"time"

	appconsumer "github.com/NeuralTrust/TrustGate/pkg/app/consumer"
	commonerrors "github.com/NeuralTrust/TrustGate/pkg/common/errors"
	"github.com/NeuralTrust/TrustGate/pkg/common/logref"
	consumerdomain "github.com/NeuralTrust/TrustGate/pkg/domain/consumer"
	"github.com/NeuralTrust/TrustGate/pkg/domain/identity"
	"github.com/NeuralTrust/TrustGate/pkg/domain/ids"
	domain "github.com/NeuralTrust/TrustGate/pkg/domain/registry"
	vaultdomain "github.com/NeuralTrust/TrustGate/pkg/domain/vault"
)

// Audit events for per-user header values. They carry the header name and an
// opaque principal reference, never the value.
const (
	UserHeaderAuditSet      = "mcp_user_header_set"
	UserHeaderAuditRemoved  = "mcp_user_header_removed"
	UserHeaderAuditReset    = "mcp_user_header_reset"
	UserHeaderAuditImported = "mcp_user_header_imported"
	UserHeaderAuditLink     = "mcp_user_header_link_issued"
)

// MaxUserHeaderImportRows bounds one bulk import request.
const MaxUserHeaderImportRows = 1000

var (
	// ErrNoUserHeaders is a registry that declares no per-user header.
	ErrNoUserHeaders = fmt.Errorf("registry: this server declares no per-user headers: %w", commonerrors.ErrConflict)
	// ErrUserHeaderImportInvalid wraps a row the import refuses. The text names
	// the row and the header, never the value.
	ErrUserHeaderImportInvalid = fmt.Errorf("registry: invalid per-user header import: %w", commonerrors.ErrValidation)
	// ErrUserHeaderAdminUnavailable is a plane whose vault cannot list or
	// reset values across people.
	ErrUserHeaderAdminUnavailable = fmt.Errorf("registry: per-user header administration is not available here: %w", commonerrors.ErrNotFound)
)

// UserHeaderValueState is what an admin sees of one person's value for one
// header: whether it exists and when it was written or refused. Never the value.
type UserHeaderValueState struct {
	Header    string
	UpdatedAt time.Time
	// RejectedAt is when the upstream refused the value with a 401; zero when
	// it has not.
	RejectedAt time.Time
}

// UserHeaderHolder is one person and the values they hold for an instance.
type UserHeaderHolder struct {
	PrincipalSub string
	Values       []UserHeaderValueState
	// Missing lists the required headers this person has no usable value for.
	Missing []string
}

// UserHeaderImportRow is one value an admin loads for one person.
type UserHeaderImportRow struct {
	PrincipalSub string
	Header       string
	Value        string
}

// UserHeaderLink is a connect page an admin hands one person to enter their
// own values.
type UserHeaderLink struct {
	Ticket       string
	ConsumerPath string
}

type UserHeaderAdmin interface {
	// Holders lists every person holding a value for the instance.
	Holders(ctx context.Context, gatewayID ids.GatewayID, registryID ids.RegistryID) ([]UserHeaderHolder, error)
	// Reset removes the values of one person, or of everyone when
	// principalSub is empty, and reports how many it removed.
	Reset(ctx context.Context, gatewayID ids.GatewayID, registryID ids.RegistryID, principalSub string) (int, error)
	// Import stores values for many people at once. Every row is checked
	// before any is written.
	Import(ctx context.Context, gatewayID ids.GatewayID, registryID ids.RegistryID, rows []UserHeaderImportRow) (int, error)
	// Link mints the connect page for one person. consumerPath is the virtual
	// MCP the person reaches the server through; empty uses the Store.
	Link(ctx context.Context, gatewayID ids.GatewayID, registryID ids.RegistryID, principalSub, consumerPath, resumeURL string) (*UserHeaderLink, error)
}

type userHeaderAdmin struct {
	registries Finder
	vault      vaultdomain.Repository
	tickets    ServerTicketMinter
	logger     *slog.Logger
}

func NewUserHeaderAdmin(registries Finder, vault vaultdomain.Repository, tickets ServerTicketMinter, logger *slog.Logger) UserHeaderAdmin {
	if logger == nil {
		logger = slog.Default()
	}
	return &userHeaderAdmin{registries: registries, vault: vault, tickets: tickets, logger: logger}
}

func (s *userHeaderAdmin) registry(ctx context.Context, gatewayID ids.GatewayID, registryID ids.RegistryID) (*domain.Registry, error) {
	reg, err := s.registries.FindByID(ctx, gatewayID, registryID)
	if err != nil {
		return nil, err
	}
	if !reg.IsMCP() || !reg.MCPTarget.HasUserHeaders() {
		return nil, ErrNoUserHeaders
	}
	return reg, nil
}

func (s *userHeaderAdmin) prefixStore() (vaultdomain.ProviderPrefixStore, error) {
	store, ok := s.vault.(vaultdomain.ProviderPrefixStore)
	if !ok {
		return nil, ErrUserHeaderAdminUnavailable
	}
	return store, nil
}

func (s *userHeaderAdmin) Holders(ctx context.Context, gatewayID ids.GatewayID, registryID ids.RegistryID) ([]UserHeaderHolder, error) {
	reg, err := s.registry(ctx, gatewayID, registryID)
	if err != nil {
		return nil, err
	}
	store, err := s.prefixStore()
	if err != nil {
		return nil, err
	}
	summaries, err := store.ListByProviderPrefix(ctx, gatewayID, domain.UserHeaderVaultPrefix(reg.ID))
	if err != nil {
		return nil, err
	}
	byName := map[string]string{}
	for _, h := range reg.MCPTarget.UserHeaders {
		byName[domain.UserHeaderVaultProvider(reg.ID, h.Name)] = h.Name
	}
	holders := map[string]*UserHeaderHolder{}
	now := time.Now()
	for _, sum := range summaries {
		name, declared := byName[sum.Provider]
		if !declared {
			// A value for a header the admin has since removed is not used;
			// it is not shown either.
			continue
		}
		holder := holders[sum.PrincipalSub]
		if holder == nil {
			holder = &UserHeaderHolder{PrincipalSub: sum.PrincipalSub}
			holders[sum.PrincipalSub] = holder
		}
		state := UserHeaderValueState{Header: name, UpdatedAt: sum.UpdatedAt}
		if !sum.ExpiresAt.IsZero() && !sum.ExpiresAt.After(now) {
			state.RejectedAt = sum.ExpiresAt
		}
		holder.Values = append(holder.Values, state)
	}
	out := make([]UserHeaderHolder, 0, len(holders))
	for _, holder := range holders {
		usable := map[string]bool{}
		for _, v := range holder.Values {
			usable[strings.ToLower(v.Header)] = v.RejectedAt.IsZero()
		}
		for _, h := range reg.MCPTarget.UserHeaders {
			if h.Required && !usable[strings.ToLower(h.Name)] {
				holder.Missing = append(holder.Missing, h.Name)
			}
		}
		out = append(out, *holder)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].PrincipalSub < out[j].PrincipalSub })
	return out, nil
}

func (s *userHeaderAdmin) Reset(ctx context.Context, gatewayID ids.GatewayID, registryID ids.RegistryID, principalSub string) (int, error) {
	reg, err := s.registries.FindByID(ctx, gatewayID, registryID)
	if err != nil {
		return 0, err
	}
	principalSub = strings.TrimSpace(principalSub)
	if principalSub == "" {
		store, err := s.prefixStore()
		if err != nil {
			return 0, err
		}
		n, err := store.DeleteByProviderPrefix(ctx, gatewayID, domain.UserHeaderVaultPrefix(reg.ID))
		if err != nil {
			return 0, err
		}
		s.audit(ctx, UserHeaderAuditReset, gatewayID, reg.ID, "*", "*")
		return n, nil
	}
	removed := 0
	var headers []domain.MCPUserHeader
	if reg.MCPTarget != nil {
		headers = reg.MCPTarget.UserHeaders
	}
	for _, h := range headers {
		err := s.vault.Delete(ctx, gatewayID, principalSub, domain.UserHeaderVaultProvider(reg.ID, h.Name))
		switch {
		case err == nil:
			removed++
			s.audit(ctx, UserHeaderAuditReset, gatewayID, reg.ID, principalSub, h.Name)
		case !errors.Is(err, vaultdomain.ErrNotFound):
			return removed, err
		}
	}
	return removed, nil
}

func (s *userHeaderAdmin) Import(ctx context.Context, gatewayID ids.GatewayID, registryID ids.RegistryID, rows []UserHeaderImportRow) (int, error) {
	reg, err := s.registry(ctx, gatewayID, registryID)
	if err != nil {
		return 0, err
	}
	if len(rows) == 0 {
		return 0, fmt.Errorf("%w: no rows", ErrUserHeaderImportInvalid)
	}
	if len(rows) > MaxUserHeaderImportRows {
		return 0, fmt.Errorf("%w: at most %d rows per request", ErrUserHeaderImportInvalid, MaxUserHeaderImportRows)
	}
	creds := make([]*vaultdomain.Credential, 0, len(rows))
	seen := map[string]int{}
	for i, row := range rows {
		sub := strings.TrimSpace(row.PrincipalSub)
		if sub == "" {
			return 0, fmt.Errorf("%w: row %d has no principal", ErrUserHeaderImportInvalid, i+1)
		}
		if !personSubject(sub) {
			return 0, fmt.Errorf("%w: row %d names an application or an instance, not a person", ErrUserHeaderImportInvalid, i+1)
		}
		h, ok := reg.MCPTarget.UserHeader(row.Header)
		if !ok {
			return 0, fmt.Errorf("%w: row %d: %q is not a header of this server", ErrUserHeaderImportInvalid, i+1, row.Header)
		}
		value := strings.TrimSpace(row.Value)
		if err := domain.ValidateUserHeaderValue(h, value); err != nil {
			return 0, fmt.Errorf("%w: row %d: %w", ErrUserHeaderImportInvalid, i+1, err)
		}
		key := sub + "\x00" + strings.ToLower(h.Name)
		if prev, dup := seen[key]; dup {
			return 0, fmt.Errorf("%w: rows %d and %d set the same header for the same principal", ErrUserHeaderImportInvalid, prev, i+1)
		}
		seen[key] = i + 1
		cred, err := vaultdomain.NewCredential(gatewayID, sub, domain.UserHeaderVaultProvider(reg.ID, h.Name), "", value, "", nil, time.Time{})
		if err != nil {
			return 0, fmt.Errorf("%w: row %d: %w", ErrUserHeaderImportInvalid, i+1, err)
		}
		creds = append(creds, cred)
	}
	written := 0
	for _, cred := range creds {
		if err := WriteUserHeaderCredential(ctx, s.vault, cred); err != nil {
			return written, err
		}
		written++
		s.audit(ctx, UserHeaderAuditImported, gatewayID, reg.ID, cred.PrincipalSub, headerOfProvider(cred.Provider))
	}
	return written, nil
}

func (s *userHeaderAdmin) Link(
	ctx context.Context,
	gatewayID ids.GatewayID,
	registryID ids.RegistryID,
	principalSub, consumerPath, resumeURL string,
) (*UserHeaderLink, error) {
	reg, err := s.registry(ctx, gatewayID, registryID)
	if err != nil {
		return nil, err
	}
	principalSub = strings.TrimSpace(principalSub)
	if principalSub == "" || !personSubject(principalSub) {
		return nil, fmt.Errorf("%w: a person's principal is required", ErrUserHeaderImportInvalid)
	}
	if s.tickets == nil {
		return nil, fmt.Errorf("registry: connect is not available: %w", commonerrors.ErrNotFound)
	}
	consumerPath = strings.TrimSpace(consumerPath)
	if consumerPath == "" {
		consumerPath = appconsumer.MCPPath(consumerdomain.StoreSlug)
	}
	ticket, err := s.tickets.CreateResumableServerTicket(
		ctx, gatewayID, principalSub, consumerPath, reg.MCPTarget.Code, reg.ID.String(), strings.TrimSpace(resumeURL),
	)
	if err != nil {
		return nil, err
	}
	s.audit(ctx, UserHeaderAuditLink, gatewayID, reg.ID, principalSub, "*")
	return &UserHeaderLink{Ticket: ticket, ConsumerPath: consumerPath}, nil
}

func (s *userHeaderAdmin) audit(ctx context.Context, event string, gatewayID ids.GatewayID, registryID ids.RegistryID, principalSub, header string) {
	AuditUserHeader(ctx, s.logger, event, gatewayID, registryID, principalSub, header, "admin")
}

// WriteUserHeaderCredential stores a per-user header value where the MCP data
// plane reads it. A control-plane vault writes Postgres and reads the shared
// Redis behind it; the data plane reads only that Redis, so the write goes to
// both. Writing clears a refusal mark: the value is new.
func WriteUserHeaderCredential(ctx context.Context, vault vaultdomain.Repository, cred *vaultdomain.Credential) error {
	if replicated, ok := vault.(vaultdomain.ReplicatedUpserter); ok {
		return replicated.UpsertReplicated(ctx, cred)
	}
	return vault.Upsert(ctx, cred)
}

// AuditUserHeader records a change to a person's header value, without it.
// actor says who made it: "self", "admin" or "upstream".
func AuditUserHeader(
	ctx context.Context,
	logger *slog.Logger,
	event string,
	gatewayID ids.GatewayID,
	registryID ids.RegistryID,
	principalSub, header, actor string,
) {
	if logger == nil {
		logger = slog.Default()
	}
	ref := principalSub
	if principalSub != "*" {
		ref = logref.Opaque(principalSub)
	}
	logger.InfoContext(ctx, "security audit",
		slog.String("event", event),
		slog.String("gateway_id", gatewayID.String()),
		slog.String("registry_id", registryID.String()),
		slog.String("principal_ref", ref),
		slog.String("header", header),
		slog.String("actor", actor),
	)
}

func headerOfProvider(provider string) string {
	if i := strings.LastIndex(provider, ":"); i >= 0 {
		return provider[i+1:]
	}
	return provider
}

// personSubject reports whether sub can hold a person's values: any subject a
// token carries, or an end user an application named (app:<consumer>:<user>).
// The application itself and an instance's own account are nobody.
func personSubject(sub string) bool {
	lowered := strings.ToLower(strings.TrimSpace(sub))
	switch {
	case lowered == "":
		return false
	case strings.HasPrefix(lowered, identity.InstanceSubjectPrefix):
		return false
	case strings.HasPrefix(lowered, identity.AppSubjectPrefix):
		rest := strings.TrimPrefix(lowered, identity.AppSubjectPrefix)
		consumer, endUser, ok := strings.Cut(rest, ":")
		return ok && consumer != "" && strings.TrimSpace(endUser) != ""
	default:
		return true
	}
}

// userHeaderValuesCleaner removes every person's header values for a registry
// once it is deleted, so no value outlives the server it was entered for.
type userHeaderValuesCleaner struct {
	store  vaultdomain.ProviderPrefixStore
	logger *slog.Logger
}

// NewUserHeaderValuesCleaner returns the registry-delete cleanup for per-user
// header values, or nil when the vault cannot remove values across people.
func NewUserHeaderValuesCleaner(vault vaultdomain.Repository, logger *slog.Logger) DependentCleaner {
	store, ok := vault.(vaultdomain.ProviderPrefixStore)
	if !ok {
		return nil
	}
	return &userHeaderValuesCleaner{store: store, logger: logger}
}

func (c *userHeaderValuesCleaner) DeleteByRegistry(ctx context.Context, gatewayID ids.GatewayID, registryID ids.RegistryID) error {
	n, err := c.store.DeleteByProviderPrefix(ctx, gatewayID, domain.UserHeaderVaultPrefix(registryID))
	if err != nil {
		return err
	}
	if n > 0 {
		AuditUserHeader(ctx, c.logger, UserHeaderAuditReset, gatewayID, registryID, "*", "*", "registry_deleted")
	}
	return nil
}
