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

package trustguard

import (
	"bytes"
	"encoding/json"
)

// marshalNoEscape is json.Marshal without HTML escaping. json.Marshal rewrites
// <, > and & as six-byte \u00XX sequences, which inflates markup- and
// code-heavy text up to sixfold and can push a body TrustGate accepted past the
// size TrustGuard accepts. The body is read as JSON on the other side and never
// rendered, so the escaping protects nothing. Encode appends a newline that
// Marshal does not; it is trimmed so the bytes match Marshal's shape.
func marshalNoEscape(v any) ([]byte, error) {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(v); err != nil {
		return nil, err
	}
	return bytes.TrimSuffix(buf.Bytes(), []byte("\n")), nil
}
