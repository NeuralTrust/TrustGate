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

package response

import (
	"time"

	appoauth "github.com/NeuralTrust/TrustGate/pkg/app/oauth"
)

// ConsumerUpstreamAccount is one bound MCP server and what it wants from the
// application.
type ConsumerUpstreamAccount struct {
	RegistryID string `json:"registry_id"`
	Registry   string `json:"registry"`
	Code       string `json:"code,omitempty"`
	// Mode is the server's upstream auth mode: none, static, client_credentials,
	// forwarded, passthrough or exchange.
	Mode string `json:"mode"`
	// NeedsLinkedAccount is true only for a server that forwards a stored
	// credential; the rest carry their own or need none.
	NeedsLinkedAccount bool       `json:"needs_linked_account"`
	Provider           string     `json:"provider,omitempty"`
	Linked             bool       `json:"linked"`
	AccountRef         string     `json:"account_ref,omitempty"`
	Scopes             []string   `json:"scopes,omitempty"`
	ExpiresAt          *time.Time `json:"expires_at,omitempty"`
	NeedsReconnect     bool       `json:"needs_reconnect"`
}

// ConsumerUpstreamAccounts is an application's whole upstream picture. It names
// no credential: the accounts belong to the consumer, so every api key and
// certificate it holds reaches the same ones.
type ConsumerUpstreamAccounts struct {
	ConsumerID string `json:"consumer_id"`
	Slug       string `json:"slug"`
	// PrincipalSub is the identity the upstream accounts hang off:
	// app:<consumer_id>, the application itself.
	PrincipalSub string                    `json:"principal_sub"`
	NeedsLinking bool                      `json:"needs_linking"`
	Accounts     []ConsumerUpstreamAccount `json:"accounts"`
}

func NewConsumerUpstreamAccounts(state *appoauth.ConsumerUpstreamState) ConsumerUpstreamAccounts {
	if state == nil {
		return ConsumerUpstreamAccounts{Accounts: []ConsumerUpstreamAccount{}}
	}
	out := ConsumerUpstreamAccounts{
		ConsumerID:   state.ConsumerID.String(),
		Slug:         state.Slug,
		PrincipalSub: state.PrincipalSub,
		NeedsLinking: state.NeedsLinking(),
		Accounts:     make([]ConsumerUpstreamAccount, 0, len(state.Accounts)),
	}
	for _, a := range state.Accounts {
		row := ConsumerUpstreamAccount{
			RegistryID:         a.RegistryID.String(),
			Registry:           a.Registry,
			Code:               a.Code,
			Mode:               string(a.Mode),
			NeedsLinkedAccount: a.NeedsLinkedAccount,
			Provider:           a.Provider,
			Linked:             a.Linked,
			AccountRef:         a.AccountRef,
			Scopes:             a.Scopes,
			NeedsReconnect:     a.NeedsReconnect,
		}
		if !a.ExpiresAt.IsZero() {
			expires := a.ExpiresAt
			row.ExpiresAt = &expires
		}
		out.Accounts = append(out.Accounts, row)
	}
	return out
}

// ConsumerConnectLink is a connect ticket for an application's own accounts.
// The URL is composed by the caller from the gateway's public MCP host and
// consumer_path, which is the only host that serves the connect page.
type ConsumerConnectLink struct {
	Ticket       string    `json:"ticket"`
	ConsumerPath string    `json:"consumer_path"`
	ConnectPath  string    `json:"connect_path"`
	Providers    []string  `json:"providers"`
	ExpiresAt    time.Time `json:"expires_at"`
}

func NewConsumerConnectLink(link *appoauth.ConsumerConnectLink) ConsumerConnectLink {
	if link == nil {
		return ConsumerConnectLink{Providers: []string{}}
	}
	providers := link.Providers
	if providers == nil {
		providers = []string{}
	}
	return ConsumerConnectLink{
		Ticket:       link.Ticket,
		ConsumerPath: link.ConsumerPath,
		ConnectPath:  link.ConsumerPath + "/connect",
		Providers:    providers,
		ExpiresAt:    link.ExpiresAt,
	}
}
