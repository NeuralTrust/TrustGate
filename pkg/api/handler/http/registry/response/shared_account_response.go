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

	appregistry "github.com/NeuralTrust/TrustGate/pkg/app/registry"
)

// SharedAccountResponse is the account an MCP instance holds for every caller.
// It names the account (what the provider calls it) and never the token.
type SharedAccountResponse struct {
	Provider       string    `json:"provider"`
	Connected      bool      `json:"connected"`
	AccountRef     string    `json:"account_ref,omitempty"`
	Scopes         []string  `json:"scopes,omitempty"`
	ExpiresAt      time.Time `json:"expires_at,omitempty"`
	NeedsReconnect bool      `json:"needs_reconnect,omitempty"`
}

func FromSharedAccount(a *appregistry.SharedAccount) SharedAccountResponse {
	if a == nil {
		return SharedAccountResponse{}
	}
	return SharedAccountResponse{
		Provider:       a.Provider,
		Connected:      a.Connected,
		AccountRef:     a.AccountRef,
		Scopes:         a.Scopes,
		ExpiresAt:      a.ExpiresAt,
		NeedsReconnect: a.NeedsReconnect,
	}
}

// SharedAccountLinkResponse is the connect page an admin walks. The ticket is a
// bearer capability to authorize this instance's account, so it is handed to
// the admin who asked and nowhere else.
type SharedAccountLinkResponse struct {
	Ticket       string `json:"ticket"`
	ConsumerPath string `json:"consumer_path"`
}

func FromSharedAccountLink(l *appregistry.SharedAccountLink) SharedAccountLinkResponse {
	if l == nil {
		return SharedAccountLinkResponse{}
	}
	return SharedAccountLinkResponse{Ticket: l.Ticket, ConsumerPath: l.ConsumerPath}
}
