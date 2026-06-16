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

package secret

import "strings"

// Redacted is the prefix the API uses to mark a masked secret. A masked value is
// the prefix optionally followed by the last few characters of the stored secret
// (e.g. "***abcd"). Masked values are never persisted: on writes they are treated
// as "no change" so a read-modify-write round-trip cannot overwrite a real
// credential with its mask.
const Redacted = "***"

// revealedTail is how many trailing characters Mask exposes for recognizability,
// and is only revealed when the secret is long enough that the tail stays a small
// fraction of it.
const revealedTail = 4

// Resolve implements the merge-on-omit rule for secret fields on update: when the
// incoming value is empty or a masked value echoed back from a response, the
// existing stored value is kept; otherwise the incoming value replaces it.
func Resolve(incoming, existing string) string {
	if incoming == "" || IsMasked(incoming) {
		return existing
	}
	return incoming
}

// Mask returns a masked representation of a stored secret ("***" plus its last
// few characters), or empty when there is no secret, so responses signal that a
// credential exists and which one without exposing it.
func Mask(v string) string {
	if v == "" {
		return ""
	}
	if len(v) <= revealedTail*2 {
		return Redacted
	}
	return Redacted + v[len(v)-revealedTail:]
}

// IsMasked reports whether a value was produced by Mask (it carries the redaction
// prefix). It is used both to detect a masked secret echoed back on update and to
// reject a masked value as a literal secret where there is no stored value to keep
// (create, auth type switch, first-time config).
func IsMasked(v string) bool {
	return strings.HasPrefix(v, Redacted)
}
