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
	authdomain "github.com/NeuralTrust/TrustGate/pkg/domain/auth"
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

func TestValidateAuthConfig_Audience(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name     string
		audience Audience
		auth     authdomain.Auth
		wantErr  bool
	}{
		{name: "application key on an application consumer", auth: authdomain.Auth{Type: authdomain.TypeAPIKey}},
		{name: "oauth2 auth on an application consumer", auth: authdomain.Auth{Type: authdomain.TypeOAuth2}},
		{name: "owned key on an application consumer", auth: authdomain.Auth{Type: authdomain.TypeAPIKey, OwnerID: "alice"}, wantErr: true},
		{name: "owned key on a personal consumer", audience: AudiencePersonal, auth: authdomain.Auth{Type: authdomain.TypeAPIKey, OwnerID: "alice"}},
		{name: "application key on a personal consumer", audience: AudiencePersonal, auth: authdomain.Auth{Type: authdomain.TypeAPIKey}, wantErr: true},
		{name: "oauth2 auth on a personal consumer", audience: AudiencePersonal, auth: authdomain.Auth{Type: authdomain.TypeOAuth2}, wantErr: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			err := ValidateAuthConfig(&Consumer{Type: TypeLLM, Audience: tc.audience}, &tc.auth)
			if (!tc.wantErr && err != nil) || (tc.wantErr && (!errors.Is(err, ErrAudienceMismatch) || !errors.Is(err, commonerrors.ErrValidation))) {
				t.Fatalf("ValidateAuthConfig() = %v, wantErr %v", err, tc.wantErr)
			}
		})
	}
}

func TestConsumer_ValidateRegistryDetach(t *testing.T) {
	t.Parallel()
	r1, r2, r3 := ids.New[ids.RegistryKind](), ids.New[ids.RegistryKind](), ids.New[ids.RegistryKind]()
	activeFallback := func(chain ...ids.RegistryID) *Fallback {
		return &Fallback{Enabled: true, Chain: registry.Registries(chain)}
	}
	for _, tc := range []struct {
		name     string
		audience Audience
		policies ModelPolicies
		fallback *Fallback
		detach   ids.RegistryID
		refused  bool
	}{
		{name: "primary default whose only other default is on an active fallback", audience: AudiencePersonal,
			policies: ModelPolicies{r1: {Default: "gpt-4o"}, r2: {Default: "gpt-4o-mini"}}, fallback: activeFallback(r2), detach: r1, refused: true},
		{name: "detaching the fallback registry", audience: AudiencePersonal,
			policies: ModelPolicies{r1: {Default: "gpt-4o"}, r2: {Default: "gpt-4o-mini"}}, fallback: activeFallback(r2), detach: r2},
		{name: "a disabled fallback counts as primary", audience: AudiencePersonal,
			policies: ModelPolicies{r1: {Default: "gpt-4o"}, r2: {Default: "gpt-4o-mini"}}, fallback: &Fallback{Chain: registry.Registries{r2}}, detach: r1},
		{name: "another primary default remains", audience: AudiencePersonal,
			policies: ModelPolicies{r1: {Default: "gpt-4o"}, r3: {Default: "gpt-4o"}}, fallback: activeFallback(r2), detach: r1},
		{name: "already without a primary default, detaching a primary", audience: AudiencePersonal,
			policies: ModelPolicies{r2: {Default: "gpt-4o-mini"}}, fallback: activeFallback(r2), detach: r1},
		{name: "already without a primary default, detaching the fallback", audience: AudiencePersonal,
			policies: ModelPolicies{r2: {Default: "gpt-4o-mini"}}, fallback: activeFallback(r2), detach: r2},
		{name: "a registry the consumer does not hold", audience: AudiencePersonal,
			policies: ModelPolicies{r1: {Default: "gpt-4o"}}, detach: ids.New[ids.RegistryKind]()},
		{name: "an application consumer is never refused",
			policies: ModelPolicies{r1: {Default: "gpt-4o"}}, fallback: activeFallback(r2), detach: r1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			c := &Consumer{
				ID: ids.New[ids.ConsumerKind](), Type: TypeLLM, Audience: tc.audience,
				RegistryIDs: []ids.RegistryID{r1, r2, r3}, ModelPolicies: tc.policies, Fallback: tc.fallback,
			}
			err := c.ValidateRegistryDetach(tc.detach)
			if !tc.refused {
				if err != nil {
					t.Fatalf("ValidateRegistryDetach() = %v, want nil", err)
				}
				return
			}
			if !errors.Is(err, ErrPersonalNoDefault) || !errors.Is(err, commonerrors.ErrValidation) || errors.Is(err, commonerrors.ErrHasDependents) {
				t.Fatalf("ValidateRegistryDetach() = %v, want ErrPersonalNoDefault (422) only", err)
			}
		})
	}
}
