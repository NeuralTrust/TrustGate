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

// Package checks holds the deterministic rules behind each hook. Every check
// is a pure function over strings or lines so it can be tested without git.
package checks

import (
	"fmt"

	"github.com/NeuralTrust/TrustGate/tools/nt-hooks/internal/gitx"
)

// EscapeMarker on a line exempts it from the content checks.
const EscapeMarker = "nolint:confidential"

// Finding is one violation at a file position.
type Finding struct {
	Path string
	Line int
	Msg  string
}

func (f Finding) String() string {
	if f.Line > 0 {
		return fmt.Sprintf("%s:%d: %s", f.Path, f.Line, f.Msg)
	}
	return fmt.Sprintf("%s: %s", f.Path, f.Msg)
}

func at(l gitx.Line, msg string) Finding {
	return Finding{Path: l.Path, Line: l.No, Msg: msg}
}
