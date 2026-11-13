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

	appsecretstore "github.com/NeuralTrust/TrustGate/pkg/app/secretstore"
)

// ListSecretStoresResponse is the secret stores a gateway may reference.
type ListSecretStoresResponse struct {
	// Supported is false when the gateway cannot hold secret references.
	Supported bool `json:"supported"`
	// Source is where the stores are configured: data_plane (the Helm values
	// of the gateway's data plane) or control_plane (the platform's Helm
	// values). Empty when not supported.
	Source string `json:"source,omitempty" enums:"data_plane,control_plane"`
	// LiveInstances counts the live data planes of a data_plane source.
	LiveInstances int                       `json:"live_instances"`
	TooOld        []SecretStoreInstance     `json:"too_old"`
	Stores        []SecretStoreItemResponse `json:"stores"`
}

// SecretStoreItemResponse is one store.
type SecretStoreItemResponse struct {
	Name         string                `json:"name"`
	Type         string                `json:"type"`
	AllowedPaths []string              `json:"allowed_paths"`
	Status       string                `json:"status" enums:"ok,degraded,down,not_reported"`
	Consistent   bool                  `json:"consistent"`
	Usages       int                   `json:"usages"`
	Instances    []SecretStoreInstance `json:"instances"`
}

// SecretStoreInstance is what one plane reports about a store.
type SecretStoreInstance struct {
	InstanceID string     `json:"instance_id"`
	Version    string     `json:"version,omitempty"`
	State      string     `json:"state"`
	ErrorClass string     `json:"error_class,omitempty"`
	CheckedAt  *time.Time `json:"checked_at,omitempty"`
}

// FromSource builds the response. Stores referenced by the gateway but not
// reported by its source are listed as not_reported.
func FromSource(src appsecretstore.Source, usages map[string][]appsecretstore.Usage) ListSecretStoresResponse {
	out := ListSecretStoresResponse{
		Supported: src.Supported, Source: string(src.Kind), LiveInstances: src.Live,
		TooOld: instances(src.TooOld), Stores: []SecretStoreItemResponse{},
	}
	reported := map[string]bool{}
	for _, st := range src.Stores {
		reported[st.Name] = true
		out.Stores = append(out.Stores, SecretStoreItemResponse{
			Name: st.Name, Type: string(st.Type), AllowedPaths: nonNil(st.AllowedPaths), Status: st.Status,
			Consistent: st.Consistent, Usages: len(usages[st.Name]), Instances: instances(st.Instances),
		})
	}
	for name, uses := range usages {
		if reported[name] {
			continue
		}
		out.Stores = append(out.Stores, SecretStoreItemResponse{
			Name: name, AllowedPaths: []string{}, Status: appsecretstore.StatusNotReported,
			Consistent: true, Usages: len(uses), Instances: []SecretStoreInstance{},
		})
	}
	return out
}

func instances(in []appsecretstore.InstanceView) []SecretStoreInstance {
	out := make([]SecretStoreInstance, 0, len(in))
	for _, v := range in {
		item := SecretStoreInstance{InstanceID: v.InstanceID, Version: v.Version, State: v.State, ErrorClass: v.ErrorClass}
		if !v.CheckedAt.IsZero() {
			t := v.CheckedAt
			item.CheckedAt = &t
		}
		out = append(out, item)
	}
	return out
}

func nonNil(s []string) []string {
	if s == nil {
		return []string{}
	}
	return s
}
