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

package request

import (
	"github.com/NeuralTrust/TrustGate/pkg/api/handler/http/httpio"
	appauth "github.com/NeuralTrust/TrustGate/pkg/app/auth"
)

// expiryChange maps an optional wire field onto the change the service takes:
// absent leaves the stored expiry alone, an empty string clears it, and an
// instant sets it. The empty string is the only way to say "no expiry" on an
// admin update that omits the field to mean "leave it alone": an absent field
// and a null one are the same thing to encoding/json, so a third word was
// needed for clearing.
func expiryChange(raw *string) (*appauth.ExpiryChange, error) {
	if raw == nil {
		return nil, nil
	}
	at, err := httpio.ParseExpiresAt(*raw)
	if err != nil {
		return nil, err
	}
	return &appauth.ExpiryChange{At: at}, nil
}
