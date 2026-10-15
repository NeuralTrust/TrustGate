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
	"crypto/subtle"
	"errors"
	"fmt"
	"log/slog"
	"net/url"
	"strings"
	"time"

	appauth "github.com/NeuralTrust/TrustGate/pkg/app/auth"
	authdomain "github.com/NeuralTrust/TrustGate/pkg/domain/auth"
	consumerdomain "github.com/NeuralTrust/TrustGate/pkg/domain/consumer"
	"github.com/NeuralTrust/TrustGate/pkg/domain/ids"
)

const (
	// PersonalKeyPagePath is where a person creates, rotates or revokes their
	// personal key, on the MCP Store's own path.
	PersonalKeyPagePath = "/" + consumerdomain.StoreSlug + "/mcp/personal-key"
	// PersonalKeyReturnPath is where the browser comes back from signing in.
	PersonalKeyReturnPath = PersonalKeyPagePath + "/return"

	// PersonalKeyTicketTTL is how long a link the Store hands out stays good.
	PersonalKeyTicketTTL = 15 * time.Minute
)

// The page's actions, as its forms post them.
const (
	PersonalKeyActionCreate = "create"
	PersonalKeyActionRotate = "rotate"
	PersonalKeyActionRevoke = "revoke"
)

var (
	// ErrPersonalKeyLinkGone: the link expired, or was used to show a secret.
	ErrPersonalKeyLinkGone = errors.New("oauth personal key: this link has expired or was already used")
	// ErrPersonalKeyNotSignedIn: the browser has not shown who it is for this
	// link, or the form did not come from the page it showed.
	ErrPersonalKeyNotSignedIn = errors.New("oauth personal key: sign in again to continue")
	// ErrPersonalKeyUnknownAction: the form asked for something the page does not do.
	ErrPersonalKeyUnknownAction = errors.New("oauth personal key: unknown action")
)

// PersonalKeyWrongAccountError: the browser is signed in as someone other than
// the person the link was made for.
type PersonalKeyWrongAccountError struct {
	// Email is who the browser is signed in as, so the page can say so.
	Email string
}

func (e *PersonalKeyWrongAccountError) Error() string {
	return "oauth personal key: signed in as another account"
}

// PersonalKeyTicket is what a Store link carries: whose key, on which gateway,
// and where that person's tools and models are served, for the page's usage.
type PersonalKeyTicket struct {
	GatewayID    string `json:"gateway_id"`
	PrincipalSub string `json:"principal_sub"`
	MCPURL       string `json:"mcp_url"`
	// LLMURL is the LLM Store's base URL; empty when the gateway has no models
	// a personal key reaches.
	LLMURL string `json:"llm_url,omitempty"`
}

// PersonalKeySession is a browser that signed in as the ticket's owner.
type PersonalKeySession struct {
	Ticket  string   `json:"ticket"`
	Subject string   `json:"subject"`
	Email   string   `json:"email,omitempty"`
	Groups  []string `json:"groups,omitempty"`
	CSRF    string   `json:"csrf"`
}

// PersonalKeyPageStore keeps tickets and sessions for PersonalKeyTicketTTL.
type PersonalKeyPageStore interface {
	SaveTicket(ctx context.Context, id string, t PersonalKeyTicket) error
	// GetTicket returns nil when there is no such ticket.
	GetTicket(ctx context.Context, id string) (*PersonalKeyTicket, error)
	DeleteTicket(ctx context.Context, id string) error
	SaveSession(ctx context.Context, id string, s PersonalKeySession) error
	// GetSession returns nil when there is no such session.
	GetSession(ctx context.Context, id string) (*PersonalKeySession, error)
	DeleteSession(ctx context.Context, id string) error
}

// PersonalKeySummary is a key as the page shows it: never its secret.
type PersonalKeySummary struct {
	Prefix    string
	Suffix    string
	ExpiresAt *time.Time
	Expired   bool
}

// PersonalKeyView is what the page renders.
type PersonalKeyView struct {
	// Email is who the browser signed in as.
	Email string
	// Key is the person's key; nil when they have none.
	Key *PersonalKeySummary
	// Secret is the key itself, set once, right after it was created or rotated.
	Secret string
	// Revoked: the key was just revoked.
	Revoked bool
	// Done: the link has served its purpose and will not open again.
	Done bool
	// Unavailable says why the key cannot be issued here (a hybrid gateway).
	Unavailable string
	// Notice is a one-line answer to what the person just asked for.
	Notice string
	CSRF   string
	MCPURL string
	LLMURL string
}

// PersonalKeyPages is the MCP Store's personal key page: the window a person
// opens from a Store link to create, rotate or revoke the key that reaches
// their tools and models from code, with what the console's Portal offers.
//
// The link alone opens nothing that matters: it went through a model, and
// maybe its logs. The browser signs in through the gateway's default identity
// provider (instantly, for a person signed in to the console) and has to come
// back as the person the link was made for. The secret is shown once, and the
// link is spent with it.
type PersonalKeyPages interface {
	// CreateTicket mints the link's ticket.
	CreateTicket(ctx context.Context, ticket PersonalKeyTicket) (string, error)
	// Open answers the page for the browser holding sessionID, or, when that
	// browser has not signed in for this ticket, where to send it to.
	Open(ctx context.Context, baseURL, ticketID, sessionID string) (*PersonalKeyView, string, error)
	// Return takes the browser back from signing in and opens its session.
	Return(ctx context.Context, ticketID, proof string) (string, error)
	// Act does what the page's form asked.
	Act(ctx context.Context, ticketID, sessionID, csrf, action string) (*PersonalKeyView, error)
}

// PersonalKeyLimiter bounds how often one person changes their key, as the
// Portal does.
type PersonalKeyLimiter interface {
	Check(ctx context.Context, scope ConnectAttemptScope, subject string) error
}

type personalKeyPages struct {
	store   PersonalKeyPageStore
	signIn  BrowserSignIn
	issuer  appauth.PersonalKeyIssuer
	limiter PersonalKeyLimiter
	logger  *slog.Logger
	now     func() time.Time
}

// NewPersonalKeyPages returns the page service.
func NewPersonalKeyPages(
	store PersonalKeyPageStore,
	signIn BrowserSignIn,
	issuer appauth.PersonalKeyIssuer,
	limiter PersonalKeyLimiter,
	logger *slog.Logger,
) (PersonalKeyPages, error) {
	if store == nil || signIn == nil || issuer == nil {
		return nil, errors.New("oauth personal key: store, sign-in and issuer are required")
	}
	if limiter == nil {
		limiter = NewNoopConnectAttemptLimiter()
	}
	if logger == nil {
		logger = slog.Default()
	}
	return &personalKeyPages{store: store, signIn: signIn, issuer: issuer, limiter: limiter, logger: logger, now: time.Now}, nil
}

func (p *personalKeyPages) CreateTicket(ctx context.Context, ticket PersonalKeyTicket) (string, error) {
	if _, err := ids.Parse[ids.GatewayKind](ticket.GatewayID); err != nil || strings.TrimSpace(ticket.PrincipalSub) == "" {
		return "", errors.New("oauth personal key: a ticket names a gateway and a person")
	}
	id, err := randomToken()
	if err != nil {
		return "", err
	}
	if err := p.store.SaveTicket(ctx, id, ticket); err != nil {
		return "", fmt.Errorf("oauth personal key: save ticket: %w", err)
	}
	return id, nil
}

func (p *personalKeyPages) Open(ctx context.Context, baseURL, ticketID, sessionID string) (*PersonalKeyView, string, error) {
	ticket, err := p.ticket(ctx, ticketID)
	if err != nil {
		return nil, "", err
	}
	session, err := p.session(ctx, ticketID, sessionID, ticket)
	if errors.Is(err, ErrPersonalKeyNotSignedIn) {
		returnTo := strings.TrimRight(baseURL, "/") + PersonalKeyReturnPath + "?" + url.Values{"ticket": {ticketID}}.Encode()
		location, err := p.signIn.BeginBrowserSignIn(ctx, baseURL, returnTo)
		if err != nil {
			return nil, "", err
		}
		return nil, location, nil
	}
	if err != nil {
		return nil, "", err
	}
	view := p.view(ticket, session)
	if err := p.loadKey(ctx, ticket, view); err != nil {
		return nil, "", err
	}
	return view, "", nil
}

func (p *personalKeyPages) Return(ctx context.Context, ticketID, proof string) (string, error) {
	ticket, err := p.ticket(ctx, ticketID)
	if err != nil {
		return "", err
	}
	who, err := p.signIn.TakeBrowserSignIn(ctx, proof)
	if err != nil {
		return "", err
	}
	if who.GatewayID != ticket.GatewayID || who.Subject != ticket.PrincipalSub {
		p.logger.WarnContext(ctx, "mcp_store_personal_key_wrong_account",
			slog.String("gateway_id", ticket.GatewayID))
		return "", &PersonalKeyWrongAccountError{Email: who.Email}
	}
	csrf, err := randomToken()
	if err != nil {
		return "", err
	}
	id, err := randomToken()
	if err != nil {
		return "", err
	}
	if err := p.store.SaveSession(ctx, id, PersonalKeySession{
		Ticket: ticketID, Subject: who.Subject, Email: who.Email, Groups: who.Groups, CSRF: csrf,
	}); err != nil {
		return "", fmt.Errorf("oauth personal key: save session: %w", err)
	}
	return id, nil
}

func (p *personalKeyPages) Act(ctx context.Context, ticketID, sessionID, csrf, action string) (*PersonalKeyView, error) {
	ticket, err := p.ticket(ctx, ticketID)
	if err != nil {
		return nil, err
	}
	session, err := p.session(ctx, ticketID, sessionID, ticket)
	if err != nil {
		return nil, err
	}
	if csrf == "" || subtle.ConstantTimeCompare([]byte(csrf), []byte(session.CSRF)) != 1 {
		return nil, ErrPersonalKeyNotSignedIn
	}
	switch action {
	case PersonalKeyActionCreate, PersonalKeyActionRotate, PersonalKeyActionRevoke:
	default:
		return nil, ErrPersonalKeyUnknownAction
	}
	gatewayID, err := ids.Parse[ids.GatewayKind](ticket.GatewayID)
	if err != nil {
		return nil, ErrPersonalKeyLinkGone
	}
	if err := p.limiter.Check(ctx, ConnectAttemptScopePersonalKey, ticket.GatewayID+"|"+ticket.PrincipalSub); err != nil {
		return nil, err
	}

	view := p.view(ticket, session)
	var issued *appauth.PersonalKey
	switch action {
	case PersonalKeyActionCreate:
		issued, err = p.issuer.Create(ctx, gatewayID, appauth.PersonalKeyOwner{ID: ticket.PrincipalSub, Email: session.Email}, session.Groups)
		if errors.Is(err, authdomain.ErrOwnedKeyExists) {
			// Another tab, or the Portal, got there first: show the key there is.
			view.Notice = "You already have a personal key on this gateway. Rotate it to get a new secret."
			if err := p.loadKey(ctx, ticket, view); err != nil {
				return nil, err
			}
			return view, nil
		}
	case PersonalKeyActionRotate:
		issued, err = p.issuer.Rotate(ctx, gatewayID, ticket.PrincipalSub)
	case PersonalKeyActionRevoke:
		err = p.issuer.Revoke(ctx, gatewayID, ticket.PrincipalSub)
		if errors.Is(err, authdomain.ErrNotFound) {
			err = nil
		}
		view.Revoked = err == nil
	}
	if errors.Is(err, authdomain.ErrNotFound) {
		view.Notice = "You have no personal key on this gateway yet."
		return view, nil
	}
	if errors.Is(err, consumerdomain.ErrHybridPersonal) {
		view.Unavailable = personalKeyHybridNotice
		return view, nil
	}
	if err != nil {
		return nil, err
	}
	if issued != nil {
		view.Secret = issued.Auth.RawKey
		view.Key = summarize(issued.Auth, p.now())
	}
	// The link has done its job: a secret is shown once, and a revoked key is
	// not a reason to keep a door open.
	view.Done = true
	if err := p.store.DeleteTicket(ctx, ticketID); err != nil {
		p.logger.WarnContext(ctx, "oauth personal key: spend ticket", slog.String("error", err.Error()))
	}
	if err := p.store.DeleteSession(ctx, sessionID); err != nil {
		p.logger.WarnContext(ctx, "oauth personal key: end session", slog.String("error", err.Error()))
	}
	p.logger.InfoContext(ctx, "mcp_store_personal_key_"+action+"d",
		slog.String("gateway_id", ticket.GatewayID))
	return view, nil
}

const personalKeyHybridNotice = "Personal keys are not available on this gateway: it runs on your own infrastructure."

func (p *personalKeyPages) ticket(ctx context.Context, id string) (*PersonalKeyTicket, error) {
	if strings.TrimSpace(id) == "" {
		return nil, ErrPersonalKeyLinkGone
	}
	ticket, err := p.store.GetTicket(ctx, id)
	if err != nil {
		return nil, fmt.Errorf("oauth personal key: load ticket: %w", err)
	}
	if ticket == nil {
		return nil, ErrPersonalKeyLinkGone
	}
	return ticket, nil
}

// session is the browser's, when it signed in for this ticket as its owner.
func (p *personalKeyPages) session(ctx context.Context, ticketID, sessionID string, ticket *PersonalKeyTicket) (*PersonalKeySession, error) {
	if strings.TrimSpace(sessionID) == "" {
		return nil, ErrPersonalKeyNotSignedIn
	}
	session, err := p.store.GetSession(ctx, sessionID)
	if err != nil {
		return nil, fmt.Errorf("oauth personal key: load session: %w", err)
	}
	if session == nil || session.Ticket != ticketID || session.Subject != ticket.PrincipalSub {
		return nil, ErrPersonalKeyNotSignedIn
	}
	return session, nil
}

func (p *personalKeyPages) view(ticket *PersonalKeyTicket, session *PersonalKeySession) *PersonalKeyView {
	return &PersonalKeyView{Email: session.Email, CSRF: session.CSRF, MCPURL: ticket.MCPURL, LLMURL: ticket.LLMURL}
}

func (p *personalKeyPages) loadKey(ctx context.Context, ticket *PersonalKeyTicket, view *PersonalKeyView) error {
	gatewayID, err := ids.Parse[ids.GatewayKind](ticket.GatewayID)
	if err != nil {
		return ErrPersonalKeyLinkGone
	}
	key, err := p.issuer.Get(ctx, gatewayID, ticket.PrincipalSub)
	switch {
	case errors.Is(err, authdomain.ErrNotFound):
		view.Key = nil
		return nil
	case err != nil:
		return fmt.Errorf("oauth personal key: load key: %w", err)
	}
	view.Key = summarize(key.Auth, p.now())
	return nil
}

func summarize(a *authdomain.Auth, now time.Time) *PersonalKeySummary {
	if a == nil {
		return nil
	}
	return &PersonalKeySummary{Prefix: a.KeyPrefix, Suffix: a.KeySuffix, ExpiresAt: a.ExpiresAt, Expired: a.IsExpired(now)}
}
