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

package store

import (
	"context"

	appgateway "github.com/NeuralTrust/TrustGate/pkg/app/gateway"
	gatewaydomain "github.com/NeuralTrust/TrustGate/pkg/domain/gateway"
	"github.com/NeuralTrust/TrustGate/pkg/domain/identity"
)

// EffectiveStoreMode is the Store access that applies to the calling principal:
// their per-principal store_access claim (open/curated/none) when the control
// plane minted one, otherwise the gateway's stamped default. The claim is the
// admin's explicit decision for that user/group, so it overrides the default in
// both directions. Without a resolved gateway in the context the mode is
// unknown, so it fails closed to curated rather than opening the Store.
//
// The three modes are the whole governance model:
//   - open ("All"): every catalog server installs instantly;
//   - curated ("Selected"): what is granted to the principal installs
//     instantly, anything else becomes an approval request;
//   - none: nothing is browsable or installable.
func EffectiveStoreMode(ctx context.Context) string {
	switch identity.PrincipalFromContext(ctx).StoreAccess() {
	case gatewaydomain.StoreModeOpen:
		return gatewaydomain.StoreModeOpen
	case gatewaydomain.StoreModeCurated:
		return gatewaydomain.StoreModeCurated
	case gatewaydomain.StoreModeNone:
		return gatewaydomain.StoreModeNone
	}
	if gw, ok := appgateway.FromContext(ctx); ok && gw != nil {
		return gw.StoreMode()
	}
	return gatewaydomain.StoreModeCurated
}
