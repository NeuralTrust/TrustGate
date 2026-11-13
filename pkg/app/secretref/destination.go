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

package secretref

import (
	"context"

	"encoding/json"
	"maps"

	"github.com/NeuralTrust/TrustGate/pkg/domain/ids"
	domain "github.com/NeuralTrust/TrustGate/pkg/domain/secretref"

	"github.com/NeuralTrust/TrustGate/pkg/domain/registry"
)

// Stored is what a registry held before a write: its reference-shaped values
// (whole and embedded) and where it sends its credentials.
type Stored struct {
	Uses        []Use
	Destination string
}

// EntityRefs is what one write of an entity holds at its declared locations.
type EntityRefs struct {
	GatewayID ids.GatewayID
	Entity    domain.Entity
	ID        string
	Uses      []Use
	Embedded  []Use
	// Destination fingerprints where the entity sends its credentials; a
	// change re-checks every reference it holds.
	Destination string
}

// Stored returns what to compare the next write of the entity with.
func (e EntityRefs) Stored() *Stored {
	return &Stored{Uses: append(append([]Use(nil), e.Uses...), e.Embedded...), Destination: e.Destination}
}

// EntityValidator checks the references a write of an entity holds before
// it is saved, and returns the audit to record once it is.
type EntityValidator interface {
	ValidateEntity(ctx context.Context, current EntityRefs, previous *Stored) (func(), error)
}

// StoredOf captures r before a write changes it.
func StoredOf(r *registry.Registry) *Stored {
	uses, embedded := RegistryReferences(r)
	return &Stored{Uses: append(uses, embedded...), Destination: RegistryDestination(r)}
}

// RegistryDestination fingerprints every field that decides which host a
// registry's credentials are sent to: the provider and its options, the
// Azure endpoint, the AWS region and role, the OAuth token URL, the MCP URL
// and authorization endpoints, and the A2A card and agent endpoints. Two
// values that differ mean the credentials may now reach another host.
func RegistryDestination(r *registry.Registry) string {
	if r == nil {
		return ""
	}
	var d struct {
		Provider     string         `json:"p,omitempty"`
		Options      map[string]any `json:"o,omitempty"`
		AuthType     string         `json:"t,omitempty"`
		Azure        string         `json:"az,omitempty"`
		AWSRegion    string         `json:"r,omitempty"`
		AWSRole      string         `json:"ro,omitempty"`
		OAuthToken   string         `json:"ot,omitempty"`
		MCPURL       string         `json:"mu,omitempty"`
		MCPAuthorize string         `json:"ma,omitempty"`
		MCPToken     string         `json:"mt,omitempty"`
		A2ACard      string         `json:"ac,omitempty"`
		A2AEndpoint  string         `json:"ae,omitempty"`
		A2AToken     string         `json:"at,omitempty"`
	}
	if t := r.LLMTarget; t != nil {
		d.Provider = t.Provider
		if len(t.ProviderOptions) > 0 {
			d.Options = maps.Clone(t.ProviderOptions)
			delete(d.Options, headersKey)
		}
		if a := t.Auth; a != nil {
			d.AuthType = string(a.Type)
			if a.Azure != nil {
				d.Azure = a.Azure.Endpoint
			}
			if a.AWS != nil {
				d.AWSRegion, d.AWSRole = a.AWS.Region, a.AWS.Role
			}
			if a.OAuth != nil {
				d.OAuthToken = a.OAuth.TokenURL
			}
		}
	}
	if t := r.MCPTarget; t != nil {
		d.MCPURL = t.URL
		if t.Auth != nil {
			d.MCPAuthorize, d.MCPToken = t.Auth.AuthorizeURL, t.Auth.TokenURL
		}
	}
	if t := r.A2ATarget; t != nil {
		d.A2ACard, d.A2AEndpoint = t.CardURL, t.Endpoint()
		if t.Auth != nil {
			d.A2AToken = t.Auth.TokenURL
		}
	}
	raw, err := json.Marshal(d)
	if err != nil {
		return "unencodable"
	}
	return string(raw)
}
