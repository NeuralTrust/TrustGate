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
	"strings"
	"time"

	consumerdomain "github.com/NeuralTrust/TrustGate/pkg/domain/consumer"
	installationdomain "github.com/NeuralTrust/TrustGate/pkg/domain/installation"
)

const (
	// ModelRequestPagePath is where a person says why they need a provider's
	// models, on the MCP Store's own path.
	ModelRequestPagePath = "/" + consumerdomain.StoreSlug + "/mcp/request-models"
	// ModelRequestTicketTTL is how long a link the Store hands out stays good.
	ModelRequestTicketTTL = 15 * time.Minute
	// ModelRequestReasonField is the form field the page collects the words in.
	ModelRequestReasonField = "reason"
)

var (
	// ErrModelRequestLinkGone: the link expired, or its request was already sent.
	ErrModelRequestLinkGone = errors.New("oauth model request: this link has expired or was already used; ask your assistant for a new one")
	// ErrModelRequestReasonRequired: the form was sent without the person's words.
	ErrModelRequestReasonRequired = errors.New("oauth model request: tell the administrator why you need these models")
)

// ModelAccessStatus is the console's answer to a request for a provider's
// models, checked or filed.
type ModelAccessStatus string

const (
	// ModelAccessOK: the request can be filed (check).
	ModelAccessOK ModelAccessStatus = "ok"
	// ModelAccessChooseRegistry: the provider has several registries the person
	// does not reach; the request names one (check).
	ModelAccessChooseRegistry ModelAccessStatus = "choose_registry"
	// ModelAccessRequested: the request was filed (file).
	ModelAccessRequested    ModelAccessStatus = "requested"
	ModelAccessHasAccess    ModelAccessStatus = "has_access"
	ModelAccessAlreadyAsked ModelAccessStatus = "already_requested"
	ModelAccessUnknown      ModelAccessStatus = "unknown_provider"
	ModelAccessUnavailable  ModelAccessStatus = "unavailable"
	ModelAccessRateLimited  ModelAccessStatus = "rate_limited"
)

// ModelAccessQuery names who asks, on which gateway, for what: a provider in
// the person's words, or one registry of it.
type ModelAccessQuery struct {
	TeamID     string
	GatewayID  string
	UserID     string
	Provider   string
	RegistryID string
}

// ModelAccessFiling is a request to file, with the person's own words.
type ModelAccessFiling struct {
	ModelAccessQuery
	Reason string
}

// ModelAccessChoice is one registry of a provider the person could ask for.
type ModelAccessChoice struct {
	RegistryID string
	Name       string
}

// ModelAccessProvider is a provider the gateway has.
type ModelAccessProvider struct {
	Provider string
	Name     string
}

// ModelAccessAnswer is what the console answered.
type ModelAccessAnswer struct {
	Status ModelAccessStatus
	// Name is what a person reads: the registry's or the provider's name.
	Name string
	// Provider and RegistryID are what the request resolved to.
	Provider   string
	RegistryID string
	// Error says, in a sentence, why the request cannot be filed.
	Error string
	// Registries are the choices of a ModelAccessChooseRegistry answer.
	Registries []ModelAccessChoice
	// Providers are the gateway's, for a ModelAccessUnknown answer.
	Providers []ModelAccessProvider
}

// ModelAccessConsole is where requests for a provider's models live: the
// console files them and Access → Approvals decides them, as for the Portal's.
// console.ModelAccessRequests is the signed client.
type ModelAccessConsole interface {
	// Check resolves what the person named and says whether it can be asked for.
	Check(ctx context.Context, q ModelAccessQuery) (*ModelAccessAnswer, error)
	// File files the request with the person's words.
	File(ctx context.Context, f ModelAccessFiling) (*ModelAccessAnswer, error)
}

// ModelRequestTicket is what a Store link carries: whose request, on which
// gateway, for what the console resolved it to when the tool was called.
type ModelRequestTicket struct {
	TeamID       string `json:"team_id"`
	GatewayID    string `json:"gateway_id"`
	PrincipalSub string `json:"principal_sub"`
	Provider     string `json:"provider"`
	RegistryID   string `json:"registry_id,omitempty"`
	Name         string `json:"name"`
}

// ModelRequestStore keeps tickets for ModelRequestTicketTTL.
type ModelRequestStore interface {
	SaveTicket(ctx context.Context, id string, t ModelRequestTicket) error
	// GetTicket returns nil when there is no such ticket.
	GetTicket(ctx context.Context, id string) (*ModelRequestTicket, error)
	DeleteTicket(ctx context.Context, id string) error
}

// ModelRequestPage is what the page renders.
type ModelRequestPage struct {
	// Name is what is asked for: "Mistral", "Amazon Bedrock".
	Name string
	// Sent: the request was filed; the link will not open again.
	Sent bool
	// Notice says why nothing was filed, in the console's words.
	Notice string
	// Closed: the notice is final (already reached, already asked) and the
	// link will not open again.
	Closed bool
}

// ModelRequestPages is the MCP Store's page where a person asks for a
// provider's models: the form the request tool links to, as the install tool
// links to one for an MCP server outside their access.
//
// The person writes the reason, in their browser: an agent asked for one
// would paraphrase its own task and present it to an approver as the person's.
// So the tool takes no reason, and the request is filed when the person sends
// this form. The link alone is the authority, as for the MCP request form: it
// files a request for its owner, which an administrator still decides.
type ModelRequestPages interface {
	CreateTicket(ctx context.Context, t ModelRequestTicket) (string, error)
	Page(ctx context.Context, ticketID string) (*ModelRequestPage, error)
	Submit(ctx context.Context, ticketID, reason string) (*ModelRequestPage, error)
}

type modelRequestPages struct {
	store   ModelRequestStore
	console ModelAccessConsole
}

// NewModelRequestPages wires the page over the ticket store and the console.
func NewModelRequestPages(store ModelRequestStore, console ModelAccessConsole) (ModelRequestPages, error) {
	if store == nil || console == nil {
		return nil, errors.New("oauth model request: a ticket store and the console are required")
	}
	return &modelRequestPages{store: store, console: console}, nil
}

func (p *modelRequestPages) CreateTicket(ctx context.Context, t ModelRequestTicket) (string, error) {
	if strings.TrimSpace(t.TeamID) == "" || strings.TrimSpace(t.GatewayID) == "" || strings.TrimSpace(t.PrincipalSub) == "" ||
		(strings.TrimSpace(t.Provider) == "" && strings.TrimSpace(t.RegistryID) == "") {
		return "", errors.New("oauth model request: team, gateway, principal and provider are required")
	}
	id, err := randomToken()
	if err != nil {
		return "", err
	}
	if err := p.store.SaveTicket(ctx, id, t); err != nil {
		return "", err
	}
	return id, nil
}

func (p *modelRequestPages) Page(ctx context.Context, ticketID string) (*ModelRequestPage, error) {
	t, err := p.ticket(ctx, ticketID)
	if err != nil {
		return nil, err
	}
	return &ModelRequestPage{Name: t.Name}, nil
}

func (p *modelRequestPages) Submit(ctx context.Context, ticketID, reason string) (*ModelRequestPage, error) {
	t, err := p.ticket(ctx, ticketID)
	if err != nil {
		return nil, err
	}
	reason = trimModelRequestReason(reason)
	if reason == "" {
		return nil, ErrModelRequestReasonRequired
	}
	answer, err := p.console.File(ctx, ModelAccessFiling{
		ModelAccessQuery: ModelAccessQuery{
			TeamID:     t.TeamID,
			GatewayID:  t.GatewayID,
			UserID:     t.PrincipalSub,
			Provider:   t.Provider,
			RegistryID: t.RegistryID,
		},
		Reason: reason,
	})
	if err != nil {
		return nil, fmt.Errorf("oauth model request: file: %w", err)
	}
	page := &ModelRequestPage{Name: t.Name}
	switch answer.Status {
	case ModelAccessRequested:
		page.Sent = true
	case ModelAccessHasAccess, ModelAccessAlreadyAsked:
		page.Notice, page.Closed = answer.Error, true
	default:
		// Worth another try later (a limit) or not at all: either way the
		// person reads why, and the form stays for a later send.
		page.Notice = answer.Error
		return page, nil
	}
	// Spent: a second send would only be refused as already asked.
	_ = p.store.DeleteTicket(ctx, ticketID)
	return page, nil
}

func (p *modelRequestPages) ticket(ctx context.Context, id string) (*ModelRequestTicket, error) {
	if strings.TrimSpace(id) == "" {
		return nil, ErrModelRequestLinkGone
	}
	t, err := p.store.GetTicket(ctx, id)
	if err != nil {
		return nil, err
	}
	if t == nil {
		return nil, ErrModelRequestLinkGone
	}
	return t, nil
}

// MaxModelRequestReasonLength bounds the words as the console does: in UTF-16
// code units, a JavaScript string's length and a textarea's maxlength.
const MaxModelRequestReasonLength = installationdomain.MaxReasonLength

// trimModelRequestReason shortens a long answer to what the console keeps
// rather than have it refused.
func trimModelRequestReason(reason string) string {
	reason = strings.TrimSpace(reason)
	units := 0
	for i, r := range reason {
		n := 1
		if r >= 0x10000 {
			n = 2
		}
		if units+n > MaxModelRequestReasonLength {
			return strings.TrimSpace(reason[:i])
		}
		units += n
	}
	return reason
}
