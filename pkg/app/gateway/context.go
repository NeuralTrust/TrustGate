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

package gateway

import (
	"context"

	domain "github.com/NeuralTrust/TrustGate/pkg/domain/gateway"
)

type contextKey string

const gatewayKey contextKey = "auth.gateway"

func WithGateway(ctx context.Context, gw *domain.Gateway) context.Context {
	return context.WithValue(ctx, gatewayKey, gw)
}

func FromContext(ctx context.Context) (*domain.Gateway, bool) {
	gw, ok := ctx.Value(gatewayKey).(*domain.Gateway)
	return gw, ok
}
