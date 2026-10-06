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

const (
	// MaxToolDecisionRefs bounds each list of one decisions call.
	MaxToolDecisionRefs = 1000
	maxToolNameLen      = 256
	maxFingerprintLen   = 128
)

// ErrBadToolDecision marks a decisions body the handler answers with 400: it is
// malformed or contradicts itself, as opposed to naming refs that do not exist
// (422, decided by the repository).
var ErrBadToolDecision = errors.New("invalid tool decision request")

// ToolRefRequest identifies one tool definition: its name and the fingerprint
// shown by the pinned-tools list.
type ToolRefRequest struct {
	Name        string `json:"name"`
	Fingerprint string `json:"fingerprint"`
}

// PinnedToolDecisionsRequest approves and rejects tool definitions in one call.
// It is applied atomically: if any ref does not exist for the registry, none is.
type PinnedToolDecisionsRequest struct {
	Approve []ToolRefRequest `json:"approve"`
	Reject  []ToolRefRequest `json:"reject"`
}

func (r PinnedToolDecisionsRequest) Validate() error {
	if len(r.Approve)+len(r.Reject) == 0 {
		return fmt.Errorf("%w: approve or reject at least one tool", ErrBadToolDecision)
	}
	if len(r.Approve) > MaxToolDecisionRefs || len(r.Reject) > MaxToolDecisionRefs {
		return fmt.Errorf("%w: at most %d tools per list", ErrBadToolDecision, MaxToolDecisionRefs)
	}
	approved := make(map[ToolRefRequest]struct{}, len(r.Approve))
	for _, ref := range r.Approve {
		if err := ref.validate(); err != nil {
			return err
		}
		approved[ref] = struct{}{}
	}
	for _, ref := range r.Reject {
		if err := ref.validate(); err != nil {
			return err
		}
		if _, both := approved[ref]; both {
			return fmt.Errorf("%w: %q is in both approve and reject", ErrBadToolDecision, ref.Name)
		}
	}
	return nil
}

func (r ToolRefRequest) validate() error {
	switch {
	case r.Name == "" || r.Fingerprint == "":
		return fmt.Errorf("%w: name and fingerprint are required", ErrBadToolDecision)
	case len(r.Name) > maxToolNameLen || len(r.Fingerprint) > maxFingerprintLen:
		return fmt.Errorf("%w: name or fingerprint too long", ErrBadToolDecision)
	}
	return nil
}

func (r PinnedToolDecisionsRequest) Approvals() []domain.ToolRef  { return toRefs(r.Approve) }
func (r PinnedToolDecisionsRequest) Rejections() []domain.ToolRef { return toRefs(r.Reject) }

func toRefs(in []ToolRefRequest) []domain.ToolRef {
	out := make([]domain.ToolRef, 0, len(in))
	for _, r := range in {
		out = append(out, domain.ToolRef{Name: r.Name, Fingerprint: r.Fingerprint})
	}
	return out
}
