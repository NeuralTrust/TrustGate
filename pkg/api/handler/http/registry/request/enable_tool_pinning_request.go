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
	"encoding/json"
	"errors"
	"fmt"

	domain "github.com/NeuralTrust/TrustGate/pkg/domain/registry"
)

const (
	// MaxPinnedTools bounds the confirmed list of one tool-pinning call.
	MaxPinnedTools = 1000
	// maxPinnedToolBytes bounds one tool's name, description and input schema.
	maxPinnedToolBytes = 64 << 10
)

// ErrBadToolPinning marks a tool-pinning body the handler answers with 400.
var ErrBadToolPinning = errors.New("invalid tool pinning request")

// PinnedToolRequest is one tool of the confirmed list, as the upstream declared
// it. The fingerprint is computed by the server from these three fields.
type PinnedToolRequest struct {
	Name        string          `json:"name"`
	Description string          `json:"description"`
	InputSchema json.RawMessage `json:"inputSchema"`
}

// EnableToolPinningRequest turns pinning on with the list the admin confirmed.
// tools is required but may be empty, as for a server whose tools are per
// principal; every listed tool is approved.
type EnableToolPinningRequest struct {
	Tools []PinnedToolRequest `json:"tools"`
}

// ToCandidates validates the list and builds each candidate through the domain,
// so the stored fingerprint is the one the data plane will compute for the same
// definition.
func (r EnableToolPinningRequest) ToCandidates() ([]domain.ToolCandidate, error) {
	if r.Tools == nil {
		return nil, fmt.Errorf("%w: tools is required (it may be empty)", ErrBadToolPinning)
	}
	if len(r.Tools) > MaxPinnedTools {
		return nil, fmt.Errorf("%w: at most %d tools", ErrBadToolPinning, MaxPinnedTools)
	}
	out := make([]domain.ToolCandidate, 0, len(r.Tools))
	for _, t := range r.Tools {
		switch {
		case t.Name == "":
			return nil, fmt.Errorf("%w: every tool needs a name", ErrBadToolPinning)
		case len(t.Name) > maxToolNameLen:
			return nil, fmt.Errorf("%w: tool name too long (max %d)", ErrBadToolPinning, maxToolNameLen)
		case len(t.Name)+len(t.Description)+len(t.InputSchema) > maxPinnedToolBytes:
			return nil, fmt.Errorf("%w: tool %q is larger than %d bytes", ErrBadToolPinning, t.Name, maxPinnedToolBytes)
		}
		c, err := domain.NewToolCandidate(t.Name, t.Description, t.InputSchema)
		if err != nil {
			return nil, err
		}
		out = append(out, c)
	}
	return out, nil
}
