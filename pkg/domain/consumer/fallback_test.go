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
	"time"

	"github.com/NeuralTrust/TrustGate/pkg/domain/ids"
	"github.com/NeuralTrust/TrustGate/pkg/domain/registry"
)

func TestFallback_Validate(t *testing.T) {
	t.Parallel()
	id1, id2 := ids.New[ids.RegistryKind](), ids.New[ids.RegistryKind]()

	cases := []struct {
		name    string
		fb      *Fallback
		wantErr bool
	}{
		{"nil is valid", nil, false},
		{"disabled is valid regardless", &Fallback{Enabled: false}, false},
		{
			name: "enabled valid",
			fb: &Fallback{
				Enabled:  true,
				Triggers: []FallbackTrigger{TriggerHTTP5xx},
				Budget:   FallbackBudget{MaxAttempts: 3},
				Chain:    registry.Registries{id1, id2},
			},
		},
		{
			name:    "enabled without triggers",
			fb:      &Fallback{Enabled: true, Budget: FallbackBudget{MaxAttempts: 3}, Chain: registry.Registries{id1}},
			wantErr: true,
		},
		{
			name:    "unknown trigger",
			fb:      &Fallback{Enabled: true, Triggers: []FallbackTrigger{"nope"}, Budget: FallbackBudget{MaxAttempts: 3}, Chain: registry.Registries{id1}},
			wantErr: true,
		},
		{
			name: "max attempts zero is auto (valid)",
			fb:   &Fallback{Enabled: true, Triggers: []FallbackTrigger{TriggerHTTP5xx}, Budget: FallbackBudget{MaxAttempts: 0}, Chain: registry.Registries{id1}},
		},
		{
			name:    "negative max attempts",
			fb:      &Fallback{Enabled: true, Triggers: []FallbackTrigger{TriggerHTTP5xx}, Budget: FallbackBudget{MaxAttempts: -1}, Chain: registry.Registries{id1}},
			wantErr: true,
		},
		{
			name:    "negative latency",
			fb:      &Fallback{Enabled: true, Triggers: []FallbackTrigger{TriggerHTTP5xx}, Budget: FallbackBudget{MaxAttempts: 1, MaxTotalLatency: -time.Second}, Chain: registry.Registries{id1}},
			wantErr: true,
		},
		{
			name:    "empty chain",
			fb:      &Fallback{Enabled: true, Triggers: []FallbackTrigger{TriggerHTTP5xx}, Budget: FallbackBudget{MaxAttempts: 1}},
			wantErr: true,
		},
		{
			name:    "duplicate chain entries",
			fb:      &Fallback{Enabled: true, Triggers: []FallbackTrigger{TriggerHTTP5xx}, Budget: FallbackBudget{MaxAttempts: 1}, Chain: registry.Registries{id1, id1}},
			wantErr: true,
		},
		{
			name:    "nil chain entry",
			fb:      &Fallback{Enabled: true, Triggers: []FallbackTrigger{TriggerHTTP5xx}, Budget: FallbackBudget{MaxAttempts: 1}, Chain: registry.Registries{{}}},
			wantErr: true,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := tc.fb.Validate()
			if tc.wantErr {
				if err == nil {
					t.Fatal("expected error, got nil")
				}
				if !errors.Is(err, ErrInvalidFallback) {
					t.Fatalf("error = %v, want ErrInvalidFallback", err)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
		})
	}
}

func TestFallback_HasTrigger(t *testing.T) {
	t.Parallel()
	fb := &Fallback{Triggers: []FallbackTrigger{TriggerProviderError}}
	if !fb.HasTrigger(TriggerProviderError) {
		t.Fatal("expected provider_error trigger present")
	}
	if fb.HasTrigger(TriggerPluginReject) {
		t.Fatal("did not expect plugin_rejection trigger")
	}
	var nilFB *Fallback
	if nilFB.HasTrigger(TriggerHTTP5xx) {
		t.Fatal("nil fallback must not report triggers")
	}
}
