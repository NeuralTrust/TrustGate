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

import "time"

type Grant struct {
	CatalogCode string   `json:"catalog_code"`
	RegistryID  string   `json:"registry_id,omitempty"`
	Groups      []string `json:"groups"`
	Users       []string `json:"users"`
}

type Grants struct {
	Items []Grant `json:"items"`
	Total int     `json:"total"`
}

type Policy struct {
	PrincipalType string `json:"principal_type"`
	PrincipalID   string `json:"principal_id"`
	Mode          string `json:"mode"`
}

type Policies struct {
	Items []Policy `json:"items"`
	Total int      `json:"total"`
}

type InstanceChoice struct {
	RegistryID string `json:"registry_id"`
	Name       string `json:"name"`
}

type Install struct {
	Code               string `json:"code"`
	Name               string `json:"name"`
	Status             string `json:"status,omitempty"`
	InstanceID         string `json:"instance_id,omitempty"`
	Pending            bool   `json:"pending"`
	AlreadyInstalled   bool   `json:"already_installed"`
	RequiresAuth       bool   `json:"requires_auth"`
	RequiresConfig     bool   `json:"requires_config"`
	RequiresAdminSetup bool   `json:"requires_admin_setup"`
	// RequiresReason is an install the caller must ask about first: it is outside
	// the user's access, so it files a request an approver decides on, and the
	// requester's words are what they read. A caller whose view of the access
	// level was stale asked for an install and gets this instead of a refusal.
	RequiresReason         bool             `json:"requires_reason"`
	RequiresInstanceChoice bool             `json:"requires_instance_choice"`
	InstanceChoices        []InstanceChoice `json:"instance_choices,omitempty"`
}

type PrincipalInstall struct {
	InstanceID  string `json:"instance_id"`
	Code        string `json:"code"`
	Name        string `json:"name"`
	RegistryID  string `json:"registry_id,omitempty"`
	Registry    string `json:"registry,omitempty"`
	Status      string `json:"status"`
	InstalledBy string `json:"installed_by,omitempty"`
	// NeedsConfig names the per-user values this installation is still missing.
	// An approved request is recorded the moment the approver says yes, before
	// anyone has asked the requester for their own account URL — the row reads
	// as installed while its first tool call cannot resolve the server's URL.
	NeedsConfig []string  `json:"needs_config,omitempty"`
	CreatedAt   time.Time `json:"created_at"`
	UpdatedAt   time.Time `json:"updated_at"`
}

type PrincipalConnection struct {
	Provider       string     `json:"provider"`
	Code           string     `json:"code,omitempty"`
	RegistryID     string     `json:"registry_id"`
	Registry       string     `json:"registry"`
	Linked         bool       `json:"linked"`
	AccountRef     string     `json:"account_ref,omitempty"`
	ExpiresAt      *time.Time `json:"expires_at,omitempty"`
	NeedsReconnect bool       `json:"needs_reconnect"`
}

type Principal struct {
	PrincipalSub string                `json:"principal_sub"`
	Installs     []PrincipalInstall    `json:"installs"`
	Connections  []PrincipalConnection `json:"connections"`
}

// PrincipalConnectLink is a connect ticket for one user's own account on one
// Store server. Like a consumer's, the URL is composed by the caller from the
// gateway's public MCP host and consumer_path: the admin API answers on another
// host and only the MCP one serves the connect page.
type PrincipalConnectLink struct {
	Ticket       string    `json:"ticket"`
	ConsumerPath string    `json:"consumer_path"`
	ConnectPath  string    `json:"connect_path"`
	ExpiresAt    time.Time `json:"expires_at"`
}

// PrincipalConfigureLink is the hosted form for one user's own settings on one
// server. The URL is composed by the caller from the gateway's public MCP host
// and consumer_path, as for the connect link.
type PrincipalConfigureLink struct {
	Ticket        string    `json:"ticket"`
	ConsumerPath  string    `json:"consumer_path"`
	ConfigurePath string    `json:"configure_path"`
	ExpiresAt     time.Time `json:"expires_at"`
}

type PendingRequest struct {
	InstanceID   string `json:"instance_id"`
	PrincipalSub string `json:"principal_sub"`
	Code         string `json:"code"`
	Name         string `json:"name"`
	InstalledBy  string `json:"installed_by,omitempty"`
	// Reason is why the requester asked for the server, in their own words.
	// Omitted when they gave none.
	Reason string `json:"reason,omitempty"`
	// RequesterGroups are the groups the requester carried when they filed, and
	// the only ones an approval may grant instead of the person.
	RequesterGroups []string  `json:"requester_groups,omitempty"`
	RequestedAt     time.Time `json:"requested_at"`
}

type PendingRequests struct {
	Items []PendingRequest `json:"items"`
	Total int              `json:"total"`
}

type DecidedRequest struct {
	InstanceID   string `json:"instance_id"`
	PrincipalSub string `json:"principal_sub"`
	Code         string `json:"code"`
	Name         string `json:"name"`
	RegistryID   string `json:"registry_id,omitempty"`
	// Reason is what the requester wrote when they asked, kept with the verdict.
	Reason      string    `json:"reason,omitempty"`
	Decision    string    `json:"decision"`
	DecidedBy   string    `json:"decided_by,omitempty"`
	DecidedAt   time.Time `json:"decided_at"`
	RequestedAt time.Time `json:"requested_at"`
}

type History struct {
	Items []DecidedRequest `json:"items"`
	Total int              `json:"total"`
}
