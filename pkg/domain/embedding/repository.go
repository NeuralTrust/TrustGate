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

package embedding

import "context"

//go:generate mockery --name=Repository --dir=. --output=./mocks --filename=embedding_repository_mock.go --case=underscore --with-expecter
type Repository interface {
	Count(ctx context.Context, index, keyQuery string) (int, error)
	Store(ctx context.Context, targetID string, embeddingData *Embedding, key string) error
	GetByTargetID(ctx context.Context, targetID string) (*Embedding, error)
	StoreWithHMSet(ctx context.Context, index, key, gatewayID string, embeddingData *Embedding, data []byte) error
	Search(ctx context.Context, index, query string, embeddingData *Embedding) ([]SearchResult, error)
}
