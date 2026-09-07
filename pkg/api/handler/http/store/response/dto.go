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
	Code                   string           `json:"code"`
	Name                   string           `json:"name"`
	Status                 string           `json:"status,omitempty"`
	InstanceID             string           `json:"instance_id,omitempty"`
	Pending                bool             `json:"pending"`
	AlreadyInstalled       bool             `json:"already_installed"`
	RequiresAuth           bool             `json:"requires_auth"`
	RequiresConfig         bool             `json:"requires_config"`
	RequiresAdminSetup     bool             `json:"requires_admin_setup"`
	RequiresInstanceChoice bool             `json:"requires_instance_choice"`
	InstanceChoices        []InstanceChoice `json:"instance_choices,omitempty"`
}

type PrincipalInstall struct {
	InstanceID  string    `json:"instance_id"`
	Code        string    `json:"code"`
	Name        string    `json:"name"`
	RegistryID  string    `json:"registry_id,omitempty"`
	Registry    string    `json:"registry,omitempty"`
	Status      string    `json:"status"`
	InstalledBy string    `json:"installed_by,omitempty"`
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

type PendingRequest struct {
	InstanceID   string    `json:"instance_id"`
	PrincipalSub string    `json:"principal_sub"`
	Code         string    `json:"code"`
	Name         string    `json:"name"`
	InstalledBy  string    `json:"installed_by,omitempty"`
	RequestedAt  time.Time `json:"requested_at"`
}

type PendingRequests struct {
	Items []PendingRequest `json:"items"`
	Total int              `json:"total"`
}

type DecidedRequest struct {
	InstanceID   string    `json:"instance_id"`
	PrincipalSub string    `json:"principal_sub"`
	Code         string    `json:"code"`
	Name         string    `json:"name"`
	RegistryID   string    `json:"registry_id,omitempty"`
	Decision     string    `json:"decision"`
	DecidedBy    string    `json:"decided_by,omitempty"`
	DecidedAt    time.Time `json:"decided_at"`
	RequestedAt  time.Time `json:"requested_at"`
}

type History struct {
	Items []DecidedRequest `json:"items"`
	Total int              `json:"total"`
}
