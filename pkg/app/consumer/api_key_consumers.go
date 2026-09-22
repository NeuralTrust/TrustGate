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

package consumer

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"

	appauth "github.com/NeuralTrust/TrustGate/pkg/app/auth"
	authdomain "github.com/NeuralTrust/TrustGate/pkg/domain/auth"
	domain "github.com/NeuralTrust/TrustGate/pkg/domain/consumer"
	"github.com/NeuralTrust/TrustGate/pkg/domain/ids"
	registrydomain "github.com/NeuralTrust/TrustGate/pkg/domain/registry"
	vaultdomain "github.com/NeuralTrust/TrustGate/pkg/domain/vault"
)

// ErrAPIKeyUnknown: no enabled api key of this gateway matches. It is the
// single answer for a key that does not exist, one that belongs to another
// gateway and one that has been disabled, so the endpoint never confirms which
// of those is true.
var ErrAPIKeyUnknown = errors.New("consumer: no consumer is reachable with this api key")

// KeyConsumer is one consumer an api key reaches, as its holder may know it.
//
// It carries no identifiers: the caller holds the key, so the slugs and names
// are already theirs, and the ids behind them are the gateway's business.
type KeyConsumer struct {
	Slug   string
	Name   string
	Type   domain.Type
	Active bool
	// Upstreams are the bound MCP servers that read an account from the vault,
	// and whether one is there. Nil for a consumer that binds none, and nil on
	// a plane that cannot read the vault — a client must not be told everything
	// is connected by a gateway that did not look.
	Upstreams []KeyUpstream
}

// KeyUpstreamAccount is whose account an instance reads: the one it holds for
// everyone, or one per caller.
type KeyUpstreamAccount string

const (
	KeyUpstreamShared KeyUpstreamAccount = "shared"
	KeyUpstreamUser   KeyUpstreamAccount = "user"
)

// Who has to act before a request that runs as the application can reach an
// upstream. Empty means nobody: it is ready.
const (
	// KeyBlockedAdministrator: the instance holds the account for everyone and
	// nobody has connected it — or it has gone stale and cannot refresh itself.
	// No caller can fix this; a connect link handed to one would let them bind
	// the account every other caller rides on.
	KeyBlockedAdministrator = "administrator"
	// KeyBlockedEndUser: the instance keeps an account per caller, and a request
	// running as the application is nobody. Naming the person it acts for
	// (X-NeuralTrust-End-User) makes it that person's account, which they can
	// connect.
	KeyBlockedEndUser = "end_user"
)

// KeyUpstream is one MCP server an application is bound to, and what it is
// still waiting for.
//
// Only servers that read a stored credential appear: one carrying its own
// (static, client credentials) or forwarding the caller's token needs nothing
// linked, so there is nothing to report and nothing to wait for.
type KeyUpstream struct {
	// Server is the instance's name, as the console shows it.
	Server   string
	Provider string
	Account  KeyUpstreamAccount
	// Connected answers for this caller — the application itself. A shared
	// instance answers for the one account it holds; a per-caller instance
	// never has one for an application, which is what Blocked then says.
	Connected bool
	// NeedsReconnect: connected once, and the account has expired with nothing
	// to refresh it with.
	NeedsReconnect bool
	Blocked        string
}

// KeyDescription is everything the holder of an api key can learn about it.
type KeyDescription struct {
	Key       KeyInfo
	Consumers []KeyConsumer
}

// KeyInfo is the calling key itself. The secret is never echoed: its holder
// has it, and a copy in a response is a copy in a log.
type KeyInfo struct {
	Name string
	// ExpiresAt is when the key retires itself. Nil means never, which is the
	// answer for every key created before expiry existed.
	ExpiresAt *time.Time
}

// APIKeyConsumers answers what an api key reaches.
//
// A key is attached to consumers, and a consumer has one type, so an agent
// that calls both tools and models holds two of them — an MCP consumer and an
// LLM one — behind the same key. Nothing told the holder of that key which
// slugs those are; they were chosen by whoever created them, in the console.
// This is how a client stops having to be told.
//
//go:generate mockery --name=APIKeyConsumers --dir=. --output=./mocks --filename=consumer_api_key_consumers_mock.go --case=underscore --with-expecter
type APIKeyConsumers interface {
	ForAPIKey(ctx context.Context, gatewayID ids.GatewayID, rawKey string) (*KeyDescription, error)
}

type apiKeyConsumers struct {
	consumers DataFinder
	apiKeys   appauth.APIKeyFinder
	// vault is optional: a plane without it answers the same question with the
	// upstream part left out rather than refusing it.
	vault vaultdomain.Repository
}

func NewAPIKeyConsumers(
	consumers DataFinder,
	apiKeys appauth.APIKeyFinder,
	vault vaultdomain.Repository,
) (APIKeyConsumers, error) {
	if consumers == nil || apiKeys == nil {
		return nil, errors.New("consumer api key consumers: consumers and api keys are required")
	}
	return &apiKeyConsumers{consumers: consumers, apiKeys: apiKeys, vault: vault}, nil
}

func (s *apiKeyConsumers) ForAPIKey(
	ctx context.Context,
	gatewayID ids.GatewayID,
	rawKey string,
) (*KeyDescription, error) {
	key := strings.TrimSpace(rawKey)
	if gatewayID.IsNil() || key == "" {
		return nil, ErrAPIKeyUnknown
	}
	auth, err := s.apiKeys.FindByAPIKey(ctx, key)
	if err != nil {
		if errors.Is(err, authdomain.ErrNotFound) {
			return nil, ErrAPIKeyUnknown
		}
		return nil, fmt.Errorf("consumer api key consumers: find api key: %w", err)
	}
	if auth == nil || !auth.Enabled ||
		auth.Type != authdomain.TypeAPIKey || auth.GatewayID != gatewayID {
		return nil, ErrAPIKeyUnknown
	}
	data, err := s.consumers.FindByGateway(ctx, gatewayID)
	if err != nil {
		return nil, fmt.Errorf("consumer api key consumers: find consumers: %w", err)
	}

	described := &KeyDescription{
		Key:       KeyInfo{Name: auth.Name, ExpiresAt: auth.ExpiresAt},
		Consumers: make([]KeyConsumer, 0, 2),
	}
	for i := range data.Consumers {
		cons := data.Consumers[i].Consumer
		if cons == nil || cons.GatewayID != gatewayID || !holdsAuth(cons, auth.ID) {
			continue
		}
		described.Consumers = append(described.Consumers, KeyConsumer{
			Slug:      cons.Slug,
			Name:      cons.Name,
			Type:      cons.Type,
			Active:    cons.Active,
			Upstreams: s.upstreams(ctx, gatewayID, &data.Consumers[i]),
		})
	}
	if len(described.Consumers) == 0 {
		// The key verified but reaches nothing. Saying so is not a leak — the
		// holder proved it is theirs — and it is the one answer that sends
		// them to the right place, which is an admin, not their own code.
		return described, nil
	}
	// Stable order: a client that has to pick between two consumers of a type
	// should be told about them the same way every time.
	sort.Slice(described.Consumers, func(i, j int) bool {
		return described.Consumers[i].Slug < described.Consumers[j].Slug
	})
	return described, nil
}

// upstreams is what a first call would fail on, answered before it is made.
//
// A request authenticated by an api key runs as the application itself, so this
// reads the vault as the application: a shared instance answers with the one
// account it holds, and a per-caller instance has nothing for an application at
// all — it wants the person the application is acting for.
func (s *apiKeyConsumers) upstreams(
	ctx context.Context,
	gatewayID ids.GatewayID,
	rc *RoutableConsumer,
) []KeyUpstream {
	if s.vault == nil || rc.Consumer == nil || rc.Consumer.Type != domain.TypeMCP {
		return nil
	}
	var out []KeyUpstream
	for _, reg := range rc.Registries {
		cfg := reg.ForwardedAuth()
		if !cfg.NeedsLinkedAccount() {
			continue
		}
		out = append(out, s.upstreamOf(ctx, gatewayID, reg, cfg))
	}
	if len(out) == 0 {
		return nil
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Server < out[j].Server })
	return out
}

func (s *apiKeyConsumers) upstreamOf(
	ctx context.Context,
	gatewayID ids.GatewayID,
	reg *registrydomain.Registry,
	cfg *registrydomain.MCPAuth,
) KeyUpstream {
	up := KeyUpstream{
		Server:   reg.Name,
		Provider: cfg.Provider,
		Account:  KeyUpstreamUser,
		Blocked:  KeyBlockedEndUser,
	}
	if !cfg.Shared() {
		return up
	}
	up.Account = KeyUpstreamShared
	up.Blocked = KeyBlockedAdministrator
	cred, err := s.vault.Find(
		ctx, gatewayID,
		registrydomain.SharedAccountSubject(reg.ID),
		registrydomain.ForwardedVaultProvider(reg),
	)
	switch {
	case err == nil:
		up.Connected = true
		up.NeedsReconnect = cred.RefreshToken == "" && cred.Expired(0)
	case errors.Is(err, vaultdomain.ErrUndecryptable):
		// It was connected and the vault key changed under it. Reporting "not
		// connected" would hide the only fact that explains the failures.
		up.Connected = true
		up.NeedsReconnect = true
	}
	if up.Connected && !up.NeedsReconnect {
		up.Blocked = ""
	}
	return up
}

func holdsAuth(cons *domain.Consumer, authID ids.AuthID) bool {
	for _, id := range cons.AuthIDs {
		if id == authID {
			return true
		}
	}
	return false
}
