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

package grpc

import (
	"context"

	"github.com/NeuralTrust/TrustGate/pkg/domain/configsyncrevocation"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// errInvalidToken is the single answer for a token the channel will not
// serve, so a revoked token cannot be told apart from a forged one.
var errInvalidToken = status.Error(codes.Unauthenticated, "missing or invalid config-sync token")

// TokenGate decides whether a verified config-sync token may use the channel.
// A nil TokenGate admits every verified token.
type TokenGate interface {
	// Admit reports whether the RPC may proceed with this token.
	Admit(ctx context.Context, id configsyncrevocation.Identity) bool
	// Revoked reports whether an open stream with this token must end now.
	Revoked(id configsyncrevocation.Identity) bool
}
