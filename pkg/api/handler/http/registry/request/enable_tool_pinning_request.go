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
	"errors"
	"fmt"

	domain "github.com/NeuralTrust/TrustGate/pkg/domain/registry"
)

// MaxPinnedTools bounds the confirmed list of one tool-pinning call.
const MaxPinnedTools = 1000

// ErrBadToolPinning marks a tool-pinning body the handler answers with 400.
var ErrBadToolPinning = errors.New("invalid tool pinning request")

// EnableToolPinningRequest turns pinning on with the tools the admin confirmed,
// identified by the (name, fingerprint) that GET .../tools returned. The server
// re-reads the live tool list and builds the approved definitions from it, so a
// client never supplies a definition: round-tripping one through JSON would
// change number literals and with them the fingerprint. tools is required but
// may be empty (a server whose tools are per principal).
type EnableToolPinningRequest struct {
	Tools []ToolRefRequest `json:"tools"`
}

// Refs validates the list and returns it as domain refs.
func (r EnableToolPinningRequest) Refs() ([]domain.ToolRef, error) {
	if r.Tools == nil {
		return nil, fmt.Errorf("%w: tools is required (it may be empty)", ErrBadToolPinning)
	}
	if len(r.Tools) > MaxPinnedTools {
		return nil, fmt.Errorf("%w: at most %d tools", ErrBadToolPinning, MaxPinnedTools)
	}
	for _, t := range r.Tools {
		if err := t.validate(); err != nil {
			return nil, fmt.Errorf("%w: %w", ErrBadToolPinning, err)
		}
	}
	return toRefs(r.Tools), nil
}
