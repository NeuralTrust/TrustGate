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

package plugins

import (
	"context"
	"errors"
	"fmt"
)

const (
	// SlugTrustGuard and SlugTrustGuardV2 are the two plugins that evaluate against TrustGuard.
	// A gateway uses the one of the TrustGuard engine its organisation is on.
	SlugTrustGuard   = "trustguard"
	SlugTrustGuardV2 = "trustguard_v2"
)

// ErrWrongTrustGuardEngine is a write of the TrustGuard plugin of the other engine.
var ErrWrongTrustGuardEngine = errors.New("plugin does not match the gateway's TrustGuard version")

// GatewayEngines says which TrustGuard engine a gateway is on. An answer it cannot give, or
// a gateway TrustGuard v2 does not know, is v1: nothing changes for anyone until v2 is in use.
type GatewayEngines interface {
	TrustGuardV2(ctx context.Context, gatewayID string) bool
}

// CheckTrustGuardEngine refuses trustguard_v2 on a v1 gateway and trustguard on a v2 one. Any
// other slug, or no resolver, passes.
func CheckTrustGuardEngine(ctx context.Context, engines GatewayEngines, gatewayID, slug string) error {
	if engines == nil || (slug != SlugTrustGuard && slug != SlugTrustGuardV2) {
		return nil
	}
	onV2 := engines.TrustGuardV2(ctx, gatewayID)
	switch {
	case slug == SlugTrustGuardV2 && !onV2:
		return fmt.Errorf("%w: %s is for organisations on TrustGuard v2; this gateway is on TrustGuard v1, use %s",
			ErrWrongTrustGuardEngine, SlugTrustGuardV2, SlugTrustGuard)
	case slug == SlugTrustGuard && onV2:
		return fmt.Errorf("%w: %s is for organisations on TrustGuard v1; this gateway is on TrustGuard v2, use %s",
			ErrWrongTrustGuardEngine, SlugTrustGuard, SlugTrustGuardV2)
	}
	return nil
}
