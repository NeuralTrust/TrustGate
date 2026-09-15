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

package proxy

import (
	"strings"

	infracontext "github.com/NeuralTrust/TrustGate/pkg/infra/context"
)

// RequestedModelRef returns the model reference the client asked for, read from
// the request body or, for path-encoded formats such as Gemini, from the path.
// It resolves the same reference the forwarder routes on, so telemetry can stamp
// it on requests that never reach routing. An unusable reference yields "".
func RequestedModelRef(req *infracontext.RequestContext) string {
	if req == nil {
		return ""
	}
	ref, err := modelRefFromRequest(req)
	if err != nil {
		return ""
	}
	return strings.TrimSpace(ref)
}
