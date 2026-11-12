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
	"github.com/NeuralTrust/TrustGate/pkg/common/secret"
	domain "github.com/NeuralTrust/TrustGate/pkg/domain/registry"
)

// A2ACloudAuthResponse is a hosted agent's cloud credential, masked.
type A2ACloudAuthResponse struct {
	AWS   *A2AAWSAuthResponse `json:"aws,omitempty"`
	Azure *AzureAuthResponse  `json:"azure,omitempty"`
	GCP   *A2AGCPAuthResponse `json:"gcp,omitempty"`
}

func fromA2ACloudAuth(c *domain.A2ACloudAuth) *A2ACloudAuthResponse {
	if c == nil {
		return nil
	}
	out := &A2ACloudAuthResponse{Azure: fromAzureAuth(c.Azure)}
	if c.AWS != nil {
		out.AWS = &A2AAWSAuthResponse{AWSAuthResponse: *fromAWSAuth(&c.AWS.AWSAuth), ExternalID: c.AWS.ExternalID}
	}
	if c.GCP != nil {
		out.GCP = &A2AGCPAuthResponse{
			ServiceAccountJSON:        secret.Mask(c.GCP.ServiceAccountJSON),
			ImpersonateServiceAccount: c.GCP.ImpersonateServiceAccount,
		}
	}
	return out
}
