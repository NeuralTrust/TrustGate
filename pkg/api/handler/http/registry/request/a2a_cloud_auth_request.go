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

package request

import (
	domain "github.com/NeuralTrust/TrustGate/pkg/domain/registry"
)

// A2ACloudAuthRequest is the cloud credential of a hosted agent; set the one
// its provider accepts.
type A2ACloudAuthRequest struct {
	AWS   *A2AAWSAuthRequest `json:"aws,omitempty"`
	Azure *AzureAuthRequest  `json:"azure,omitempty"`
	GCP   *A2AGCPAuthRequest `json:"gcp,omitempty"`
}

func (c *A2ACloudAuthRequest) toDomain() *domain.A2ACloudAuth {
	if c == nil {
		return nil
	}
	out := &domain.A2ACloudAuth{Azure: c.Azure.ToDomain()}
	if c.AWS != nil {
		out.AWS = &domain.A2AAWSAuth{AWSAuth: *c.AWS.ToDomain(), ExternalID: c.AWS.ExternalID}
	}
	if c.GCP != nil {
		out.GCP = &domain.A2AGCPAuth{
			ServiceAccountJSON:        string(c.GCP.ServiceAccountJSON),
			ImpersonateServiceAccount: c.GCP.ImpersonateServiceAccount,
		}
	}
	return out
}
