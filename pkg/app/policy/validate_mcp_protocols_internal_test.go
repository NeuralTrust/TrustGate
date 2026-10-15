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

package policy

import (
	"errors"
	"testing"
	"time"

	appplugins "github.com/NeuralTrust/TrustGate/pkg/app/plugins"
	domain "github.com/NeuralTrust/TrustGate/pkg/domain/policy"
	"github.com/NeuralTrust/TrustGate/pkg/infra/plugins/azurecontentsafety"
	"github.com/NeuralTrust/TrustGate/pkg/infra/plugins/bedrockguardrail"
	"github.com/NeuralTrust/TrustGate/pkg/infra/plugins/googlemodelarmor"
	"github.com/NeuralTrust/TrustGate/pkg/infra/plugins/openaimoderation"
	"github.com/NeuralTrust/TrustGate/pkg/infra/providers/adapter"
)

// TestValidateMCPScopePlugin_RejectsEveryExternalGuardrail pins RUN-1672's
// background fact directly against the real plugins, not a stand-in for
// them: none of the four external guardrails (azure_content_safety,
// bedrock_guardrail, google_model_armor, openai_moderation) declares
// appplugins.ProtocolMCP, so validateMCPScopePlugin must refuse every one of
// them the same way it refuses any other LLM-only plugin. This is an
// internal (package policy) test, not policy_test, because
// validateMCPScopePlugin is unexported; registering the real infra plugin
// packages here does not create an import cycle since none of them imports
// pkg/app/policy.
func TestValidateMCPScopePlugin_RejectsEveryExternalGuardrail(t *testing.T) {
	t.Parallel()

	reg := appplugins.NewRegistry()
	adapterRegistry := adapter.NewRegistry()
	plugins := []appplugins.Plugin{
		azurecontentsafety.New(adapterRegistry, nil),
		bedrockguardrail.New(adapterRegistry, nil),
		googlemodelarmor.New(adapterRegistry, "", time.Second, true, nil),
		openaimoderation.New(adapterRegistry, "", time.Second, nil),
	}
	for _, p := range plugins {
		if err := reg.Register(p); err != nil {
			t.Fatalf("Register(%s): %v", p.Name(), err)
		}
	}

	for _, p := range plugins {
		p := p
		t.Run(p.Name(), func(t *testing.T) {
			t.Parallel()
			err := validateMCPScopePlugin(reg, p.Name())
			if !errors.Is(err, domain.ErrInvalidMCPScope) {
				t.Fatalf("validateMCPScopePlugin(%s) = %v, want ErrInvalidMCPScope", p.Name(), err)
			}
		})
	}
}

// TestValidateMCPScopePlugin_ExternalGuardrailsDeclareNoMCPProtocol is the
// narrower, structural half of the same guarantee: each plugin's own
// SupportedProtocols() excludes appplugins.ProtocolMCP. Kept alongside the
// registry-level test above (not instead of it) because SupportedProtocols
// is the fact validateMCPScopePlugin actually reads — this pins the
// assumption the other test's real-registry exercise relies on.
func TestValidateMCPScopePlugin_ExternalGuardrailsDeclareNoMCPProtocol(t *testing.T) {
	t.Parallel()

	adapterRegistry := adapter.NewRegistry()
	plugins := []appplugins.Plugin{
		azurecontentsafety.New(adapterRegistry, nil),
		bedrockguardrail.New(adapterRegistry, nil),
		googlemodelarmor.New(adapterRegistry, "", time.Second, true, nil),
		openaimoderation.New(adapterRegistry, "", time.Second, nil),
	}
	for _, p := range plugins {
		for _, protocol := range p.SupportedProtocols() {
			if protocol == appplugins.ProtocolMCP {
				t.Fatalf("%s declares ProtocolMCP; RUN-1672's background assumes it does not", p.Name())
			}
		}
	}
}
