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

package catalog

import (
	"context"
	"testing"

	domain "github.com/NeuralTrust/TrustGate/pkg/domain/catalog"
)

type listOnlyRepo struct {
	fakeRepo
	models []domain.Model
}

func (r *listOnlyRepo) ListModelsByProviderCode(_ context.Context, _ string) ([]domain.Model, error) {
	return r.models, nil
}

// A model the sync withdrew stays stored so pricing can still resolve it, but it
// must not be offered in the listing the model pickers are built from.
func TestService_ListModels_OmitsDisabledModels(t *testing.T) {
	t.Parallel()
	repo := &listOnlyRepo{models: []domain.Model{
		{Slug: "global.anthropic.claude-opus-5", Enabled: true},
		{Slug: "us.anthropic.claude-opus-5", Enabled: false},
		{Slug: "amazon.nova-pro-v1:0", Enabled: true},
	}}

	got, err := NewService(repo).ListModels(context.Background(), "bedrock")
	if err != nil {
		t.Fatalf("ListModels error: %v", err)
	}

	if len(got) != 2 {
		t.Fatalf("got %d models, want 2: %+v", len(got), got)
	}
	for _, model := range got {
		if !model.Enabled {
			t.Fatalf("disabled model %q was listed", model.Slug)
		}
	}
}
