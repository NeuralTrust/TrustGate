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
	"log/slog"
)

const (
	connectAuditTicketCreated    = "mcp_connect_ticket_created"
	connectAuditProviderLinked   = "mcp_provider_linked"
	connectAuditProviderUnlinked = "mcp_provider_unlinked"
)

type ConnectAuditIdentity struct {
	GatewayID  string
	ConsumerID string
	AuthID     string
}

//go:generate mockery --name=ConnectAuditor --dir=. --output=./mocks --filename=oauth_connect_auditor_mock.go --case=underscore --with-expecter
type ConnectAuditor interface {
	TicketCreated(ctx context.Context, identity ConnectAuditIdentity)
	ProviderLinked(ctx context.Context, identity ConnectAuditIdentity, providerID string)
	ProviderUnlinked(ctx context.Context, identity ConnectAuditIdentity, providerID string)
}

type connectAuditor struct {
	logger *slog.Logger
}

func NewConnectAuditor(logger *slog.Logger) ConnectAuditor {
	return &connectAuditor{logger: logger}
}

func (a *connectAuditor) TicketCreated(ctx context.Context, identity ConnectAuditIdentity) {
	a.log(ctx, connectAuditTicketCreated, identity)
}

func (a *connectAuditor) ProviderLinked(
	ctx context.Context,
	identity ConnectAuditIdentity,
	providerID string,
) {
	a.log(ctx, connectAuditProviderLinked, identity, slog.String("provider_id", providerID))
}

func (a *connectAuditor) ProviderUnlinked(
	ctx context.Context,
	identity ConnectAuditIdentity,
	providerID string,
) {
	a.log(ctx, connectAuditProviderUnlinked, identity, slog.String("provider_id", providerID))
}

func (a *connectAuditor) log(
	ctx context.Context,
	event string,
	identity ConnectAuditIdentity,
	extra ...slog.Attr,
) {
	attrs := []slog.Attr{
		slog.String("event", event),
		slog.String("gateway_id", identity.GatewayID),
		slog.String("consumer_id", identity.ConsumerID),
		slog.String("auth_id", identity.AuthID),
	}
	attrs = append(attrs, extra...)
	a.logger.LogAttrs(ctx, slog.LevelInfo, "security audit", attrs...)
}

func connectAuditIdentity(ticket *ConnectTicket) (ConnectAuditIdentity, bool) {
	if ticket == nil || ticket.ConsumerID == "" || ticket.AuthID == "" {
		return ConnectAuditIdentity{}, false
	}
	return ConnectAuditIdentity{
		GatewayID:  ticket.GatewayID,
		ConsumerID: ticket.ConsumerID,
		AuthID:     ticket.AuthID,
	}, true
}
