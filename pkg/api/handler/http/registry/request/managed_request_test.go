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

package request_test

import (
	"errors"
	"testing"

	"github.com/NeuralTrust/TrustGate/pkg/api/handler/http/registry/request"
	commonerrors "github.com/NeuralTrust/TrustGate/pkg/common/errors"
)

func TestCreateRegistryRequest_Managed(t *testing.T) {
	t.Parallel()
	ok := request.CreateRegistryRequest{Name: "OpenAI (NeuralTrust)", Provider: "openai", Managed: true}
	if err := ok.Validate(); err != nil {
		t.Fatalf("managed without auth: %v", err)
	}
	if ok.ToLLMTarget().Auth != nil {
		t.Fatal("managed request built stored auth")
	}

	withAuth := ok
	withAuth.Auth = &request.TargetAuthRequest{Type: "api_key", APIKey: &request.APIKeyAuthRequest{APIKey: "sk-1"}}
	if err := withAuth.Validate(); !errors.Is(err, commonerrors.ErrValidation) {
		t.Fatalf("managed with auth: err = %v, want a validation error", err)
	}

	mcp := ok
	mcp.Type = "MCP"
	if err := mcp.Validate(); !errors.Is(err, commonerrors.ErrValidation) {
		t.Fatalf("managed MCP: err = %v, want a validation error", err)
	}
}
