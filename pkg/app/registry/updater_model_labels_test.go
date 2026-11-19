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

package registry_test

import (
	"context"
	"maps"
	"testing"

	appregistry "github.com/NeuralTrust/TrustGate/pkg/app/registry"
	"github.com/NeuralTrust/TrustGate/pkg/domain/ids"
	domain "github.com/NeuralTrust/TrustGate/pkg/domain/registry"
	repomocks "github.com/NeuralTrust/TrustGate/pkg/domain/registry/mocks"
	"github.com/NeuralTrust/TrustGate/pkg/infra/cache/event"
	cachemocks "github.com/NeuralTrust/TrustGate/pkg/infra/cache/mocks"
	"github.com/stretchr/testify/mock"
)

func TestUpdater_Update_ModelLabels(t *testing.T) {
	t.Parallel()

	const arn = "arn:aws:bedrock:eu-west-1:123456789012:application-inference-profile/abc123"
	stored := map[string]string{arn: "Stored"}
	tests := []struct {
		name string
		in   appregistry.UpdateInput
		want map[string]string
	}{
		{
			name: "absent keeps the stored map",
			in:   appregistry.UpdateInput{Name: ptr("renamed")},
			want: stored,
		},
		{
			name: "empty map clears",
			in:   appregistry.UpdateInput{SetModelLabels: true, ModelLabels: map[string]string{}},
			want: nil,
		},
		{
			name: "present map replaces and is trimmed",
			in:   appregistry.UpdateInput{SetModelLabels: true, ModelLabels: map[string]string{" gpt-4o ": " GPT-4o "}},
			want: map[string]string{"gpt-4o": "GPT-4o"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			repo := repomocks.NewRepository(t)
			existing, err := domain.NewLLMRegistry(ids.New[ids.GatewayKind](), "old", "", &domain.LLMTarget{
				Provider: "bedrock", Auth: domain.NewAPIKeyAuth("sk-real"), ModelLabels: maps.Clone(stored),
			})
			if err != nil {
				t.Fatalf("NewLLMRegistry: %v", err)
			}
			repo.EXPECT().FindByID(mock.Anything, existing.ID).Return(existing, nil).Once()
			repo.EXPECT().Update(mock.Anything, mock.MatchedBy(func(b *domain.Registry) bool {
				return maps.Equal(b.ModelLabels(), tt.want)
			})).Return(nil).Once()
			publisher := cachemocks.NewEventPublisher(t)
			publisher.EXPECT().
				Publish(mock.Anything, event.InvalidateRegistryCacheEvent{GatewayID: existing.GatewayID.String(), RegistryID: existing.ID.String()}).
				Return(nil).
				Once()

			in := tt.in
			in.ID = existing.ID
			got, err := appregistry.NewUpdater(repo, newCacheManager(), publisher, newTestLogger(), nil, nil).Update(context.Background(), in)
			if err != nil {
				t.Fatalf("Update: %v", err)
			}
			if !maps.Equal(got.ModelLabels(), tt.want) {
				t.Fatalf("model labels = %v, want %v", got.ModelLabels(), tt.want)
			}
		})
	}
}
