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

	commonerrors "github.com/NeuralTrust/TrustGate/pkg/common/errors"
	"github.com/NeuralTrust/TrustGate/pkg/domain/ids"
	"github.com/NeuralTrust/TrustGate/pkg/domain/registry"
)

func TestAudience(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		in       string
		want     Audience
		wantName Audience
		wantErr  bool
	}{
		{in: "", want: "", wantName: AudienceApplication},
		{in: "application", want: "", wantName: AudienceApplication},
		{in: "personal", want: AudiencePersonal, wantName: AudiencePersonal},
		{in: "team", wantErr: true},
		{in: "Personal", wantErr: true},
	} {
		t.Run(tc.in, func(t *testing.T) {
			t.Parallel()
			parsed, parseErr := ParseAudience(tc.in)
			registryID := ids.New[ids.RegistryKind]()
			created, newErr := New(CreateParams{
				GatewayID: ids.New[ids.GatewayKind](), Name: "chat", Type: TypeLLM, Audience: Audience(tc.in),
				RegistryIDs: []ids.RegistryID{registryID}, ModelPolicies: ModelPolicies{registryID: {Default: "gpt-4o"}},
			})
			if tc.wantErr {
				if !errors.Is(parseErr, ErrInvalidAudience) || !errors.Is(newErr, ErrInvalidAudience) {
					t.Fatalf("errors = %v, %v; want ErrInvalidAudience", parseErr, newErr)
				}
				return
			}
			if parseErr != nil || newErr != nil {
				t.Fatalf("errors = %v, %v", parseErr, newErr)
			}
			rehydrated := Rehydrate(RehydrateParams{Audience: Audience(tc.in)})
			if parsed != tc.want || created.Audience != tc.want || rehydrated.Audience != tc.want {
				t.Fatalf("parsed %q, created %q, rehydrated %q; want %q", parsed, created.Audience, rehydrated.Audience, tc.want)
			}
			if created.AudienceName() != tc.wantName || created.IsPersonal() != (tc.want == AudiencePersonal) {
				t.Fatalf("AudienceName() = %q, IsPersonal() = %v", created.AudienceName(), created.IsPersonal())
			}
		})
	}
}

func personalParams(primary, fallback ids.RegistryID, policies ModelPolicies) CreateParams {
	return CreateParams{
		GatewayID:     ids.New[ids.GatewayKind](),
		Name:          "personal",
		Type:          TypeLLM,
		Audience:      AudiencePersonal,
		RegistryIDs:   []ids.RegistryID{primary, fallback},
		ModelPolicies: policies,
		Fallback:      &Fallback{Enabled: true, Triggers: []FallbackTrigger{TriggerHTTP5xx}, Chain: registry.Registries{fallback}},
	}
}

func TestConsumer_Validate_Personal(t *testing.T) {
	t.Parallel()
	r1, r2 := ids.New[ids.RegistryKind](), ids.New[ids.RegistryKind]()
	for _, tc := range []struct {
		name    string
		mutate  func(*CreateParams)
		wantErr error
	}{
		{name: "personal LLM with a default", mutate: func(*CreateParams) {}},
		{name: "personal MCP", mutate: func(p *CreateParams) { p.Type = TypeMCP }, wantErr: ErrInvalidAudience},
		{name: "no default", mutate: func(p *CreateParams) { p.ModelPolicies = ModelPolicies{r1: {Allowed: []string{"gpt-4o*"}}} }, wantErr: ErrPersonalNoDefault},
		{name: "glob default", mutate: func(p *CreateParams) { p.ModelPolicies = ModelPolicies{r1: {Default: "gpt-4o*"}} }, wantErr: ErrInvalidModelPolicy},
		{name: "default only on a fallback", mutate: func(p *CreateParams) { p.ModelPolicies = ModelPolicies{r2: {Default: "gpt-4o"}} }, wantErr: ErrPersonalNoDefault},
		{name: "default on a disabled fallback chain", mutate: func(p *CreateParams) {
			p.ModelPolicies = ModelPolicies{r2: {Default: "gpt-4o"}}
			p.Fallback.Enabled = false
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			params := personalParams(r1, r2, ModelPolicies{r1: {Default: "gpt-4o"}})
			tc.mutate(&params)
			_, err := New(params)
			if tc.wantErr == nil {
				if err != nil {
					t.Fatalf("New() error = %v", err)
				}
				return
			}
			if !errors.Is(err, tc.wantErr) || !errors.Is(err, commonerrors.ErrValidation) {
				t.Fatalf("New() error = %v, want %v wrapping ErrValidation", err, tc.wantErr)
			}
		})
	}
}
