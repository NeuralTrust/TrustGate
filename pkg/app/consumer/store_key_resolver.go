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
	"context"
	"errors"
	"fmt"
	"time"

	appauth "github.com/NeuralTrust/TrustGate/pkg/app/auth"
	commonerrors "github.com/NeuralTrust/TrustGate/pkg/common/errors"
	authdomain "github.com/NeuralTrust/TrustGate/pkg/domain/auth"
	"github.com/NeuralTrust/TrustGate/pkg/domain/ids"
)

// ErrStoreKeyRejected is the single answer for a key the store does not
// accept, so the caller never learns which check failed.
var ErrStoreKeyRejected = errors.New("store: key rejected")

// StoreKeyResolver resolves the personal key presented on the store of a
// gateway.
//
//go:generate mockery --name=StoreKeyResolver --dir=. --output=./mocks --filename=consumer_store_key_resolver_mock.go --case=underscore --with-expecter
type StoreKeyResolver interface {
	Resolve(ctx context.Context, gatewayID ids.GatewayID, rawKey string) (*authdomain.Auth, error)
}

type storeKeyResolver struct {
	apiKeys appauth.APIKeyFinder
	now     func() time.Time
}

func NewStoreKeyResolver(apiKeys appauth.APIKeyFinder, now func() time.Time) StoreKeyResolver {
	if now == nil {
		now = func() time.Time { return time.Now().UTC() }
	}
	return &storeKeyResolver{apiKeys: apiKeys, now: now}
}

func (r *storeKeyResolver) Resolve(ctx context.Context, gatewayID ids.GatewayID, rawKey string) (*authdomain.Auth, error) {
	if rawKey == "" {
		return nil, ErrStoreKeyRejected
	}
	key, err := r.apiKeys.FindByAPIKey(ctx, rawKey)
	if err != nil {
		if errors.Is(err, commonerrors.ErrNotFound) {
			return nil, ErrStoreKeyRejected
		}
		return nil, fmt.Errorf("store: find api key: %w", err)
	}
	if !key.AcceptsAPIKey(authdomain.HashAPIKey(rawKey), r.now()) || !key.IsOwned() || key.GatewayID != gatewayID {
		return nil, ErrStoreKeyRejected
	}
	return key, nil
}
