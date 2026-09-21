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
	"fmt"
	"strings"

	commonerrors "github.com/NeuralTrust/TrustGate/pkg/common/errors"
	"github.com/NeuralTrust/TrustGate/pkg/domain/policy"
)

// PreviewPolicyRequest is a candidate plugin configuration and the sample request
// to run it against. It is not a policy: nothing is stored, and no scope, consumer
// or gateway binding takes part.
type PreviewPolicyRequest struct {
	Slug     string              `json:"slug"`
	Settings map[string]any      `json:"settings"`
	Mode     string              `json:"mode,omitempty"`
	Body     json.RawMessage     `json:"body"`
	Headers  map[string][]string `json:"headers,omitempty"`
}

const (
	// maxSampleBodyBytes bounds the pasted request. A preview illustrates a call; it
	// is not a load test, and the render path concatenates per template.
	maxSampleBodyBytes = 256 * 1024
	// maxSettingsBytes bounds the candidate configuration. Settings arrive straight
	// from the caller here rather than from a stored policy, and the number of
	// templates drives quadratic work in the renderer.
	maxSettingsBytes = 256 * 1024
)

func (r *PreviewPolicyRequest) Validate() error {
	if strings.TrimSpace(r.Slug) == "" {
		return fmt.Errorf("slug is required: %w", commonerrors.ErrValidation)
	}
	if len(r.Body) == 0 {
		return fmt.Errorf("body is required: %w", commonerrors.ErrValidation)
	}
	if len(r.Body) > maxSampleBodyBytes {
		return fmt.Errorf("body must be at most %d bytes: %w", maxSampleBodyBytes, commonerrors.ErrValidation)
	}
	// The decoders downstream expect an object; a bare array, string or number is
	// valid JSON that would otherwise fail deep inside a plugin and surface as a 500.
	var probe map[string]json.RawMessage
	if err := json.Unmarshal(r.Body, &probe); err != nil {
		return fmt.Errorf("body must be a JSON object: %w", commonerrors.ErrValidation)
	}
	if encoded, err := json.Marshal(r.Settings); err == nil && len(encoded) > maxSettingsBytes {
		return fmt.Errorf("settings must be at most %d bytes: %w", maxSettingsBytes, commonerrors.ErrValidation)
	}
	if r.Mode != "" && !policy.Mode(r.Mode).IsValid() {
		return fmt.Errorf("mode %q is not a valid policy mode: %w", r.Mode, commonerrors.ErrValidation)
	}
	return nil
}
