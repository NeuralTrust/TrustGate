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

// UserHeaderHoldersResponse lists who holds a value for an instance's
// per-user headers. Values are never returned.
type UserHeaderHoldersResponse struct {
	Holders []UserHeaderHolderResponse `json:"holders"`
}

type UserHeaderHolderResponse struct {
	PrincipalSub string                    `json:"principal_sub"`
	Values       []UserHeaderValueResponse `json:"values"`
	// Missing lists the required headers this person has no usable value for.
	Missing []string `json:"missing,omitempty"`
}

type UserHeaderValueResponse struct {
	Header    string    `json:"header"`
	UpdatedAt time.Time `json:"updated_at"`
	// RejectedAt is set when the upstream refused the value with a 401.
	RejectedAt *time.Time `json:"rejected_at,omitempty"`
}

// UserHeaderCountResponse reports how many values a reset or import touched.
type UserHeaderCountResponse struct {
	Count int `json:"count"`
}

// UserHeaderLinkResponse is the connect page one person walks.
type UserHeaderLinkResponse struct {
	Ticket       string `json:"ticket"`
	ConsumerPath string `json:"consumer_path"`
}

func FromUserHeaderHolders(holders []appregistry.UserHeaderHolder) UserHeaderHoldersResponse {
	out := UserHeaderHoldersResponse{Holders: make([]UserHeaderHolderResponse, 0, len(holders))}
	for _, h := range holders {
		row := UserHeaderHolderResponse{PrincipalSub: h.PrincipalSub, Missing: h.Missing}
		for _, v := range h.Values {
			value := UserHeaderValueResponse{Header: v.Header, UpdatedAt: v.UpdatedAt}
			if !v.RejectedAt.IsZero() {
				rejected := v.RejectedAt
				value.RejectedAt = &rejected
			}
			row.Values = append(row.Values, value)
		}
		out.Holders = append(out.Holders, row)
	}
	return out
}

func FromUserHeaderLink(l *appregistry.UserHeaderLink) UserHeaderLinkResponse {
	if l == nil {
		return UserHeaderLinkResponse{}
	}
	return UserHeaderLinkResponse{Ticket: l.Ticket, ConsumerPath: l.ConsumerPath}
}
