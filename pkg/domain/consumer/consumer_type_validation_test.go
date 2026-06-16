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

package consumer

import (
	"errors"
	"testing"
)

func mcpParams() CreateParams {
	p := validParams()
	p.Type = TypeMCP
	return p
}

func TestConsumer_MCP_DefaultsFailModeClosed(t *testing.T) {
	t.Parallel()
	c, err := New(mcpParams())
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if c.FailMode() != FailModeClosed {
		t.Fatalf("FailMode = %q, want %q", c.FailMode(), FailModeClosed)
	}
}

func TestConsumer_LLM_RejectsMCPPolicy(t *testing.T) {
	t.Parallel()
	p := validParams()
	p.MCP = &MCPPolicy{FailMode: FailModeOpen}
	if _, err := New(p); !errors.Is(err, ErrInvalidType) {
		t.Fatalf("error = %v, want ErrInvalidType", err)
	}
}

func TestConsumer_LLM_DefaultsAlgorithmWhenLBEnabled(t *testing.T) {
	t.Parallel()
	p := validParams()
	regID := p.RegistryIDs[0]
	p.ModelPolicies = ModelPolicies{regID: {Allowed: []string{"gpt-5"}}}
	p.LBConfig = &LBConfig{Enabled: true, Members: []LBPoolMember{{RegistryID: regID}}}
	c, err := New(p)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if c.LBConfig.Algorithm == "" {
		t.Fatal("Algorithm should default when load balancing is enabled")
	}
}

func TestConsumer_A2A_RejectsMCPPolicy(t *testing.T) {
	t.Parallel()
	p := validParams()
	p.Type = TypeA2A
	p.MCP = &MCPPolicy{}
	if _, err := New(p); !errors.Is(err, ErrInvalidType) {
		t.Fatalf("error = %v, want ErrInvalidType", err)
	}
}
