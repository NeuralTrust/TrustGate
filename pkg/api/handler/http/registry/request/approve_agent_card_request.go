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
	"fmt"
	"strings"

	commonerrors "github.com/NeuralTrust/TrustGate/pkg/common/errors"
)

// ApproveAgentCardRequest names the reviewed digest of the card to pin.
type ApproveAgentCardRequest struct {
	Digest string `json:"digest"`
}

func (r ApproveAgentCardRequest) Validate() error {
	if !strings.HasPrefix(r.Digest, "sha256:") {
		return fmt.Errorf("digest must be a sha256:<hex> card digest: %w", commonerrors.ErrValidation)
	}
	return nil
}
