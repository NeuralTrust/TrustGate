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

package prompttemplate

import (
	"encoding/json"
	"fmt"
	"strings"
)

// fragmentError is a rendered template the target shape cannot carry, with a
// message the caller can act on.
type fragmentError struct {
	msg string
	// clientOwned marks an error caused by the client's own body (a system
	// field the template cannot be merged into), which is refused as an
	// unsupported shape, unlike an error in the operator's template, which
	// stays a render failure. reason names it.
	clientOwned bool
	reason      string
}

func (e *fragmentError) Error() string { return e.msg }

// fragmentTurn is one non-system message of a rendered template.
type fragmentTurn struct {
	role  string
	texts []string
}

// fragment is a rendered Mode B template read as text. A plain string is
// plain; a messages array is split into the system text, which every shape
// that keeps its system prompt apart merges into it, and the other turns.
type fragment struct {
	isPlain bool
	plain   string
	system  string
	turns   []fragmentTurn
}

// parseFragment reads a rendered template. Empty system text is dropped, and
// a turn with null or no content is dropped as no text (the messages path
// accepts both). Content with no text equivalent is an error rather than
// silently dropped.
func parseFragment(rendered string) (fragment, error) {
	if !strings.HasPrefix(strings.TrimSpace(rendered), "[") {
		return fragment{isPlain: true, plain: rendered}, nil
	}
	var raw []struct {
		Role    string          `json:"role"`
		Content json.RawMessage `json:"content"`
	}
	if err := json.Unmarshal([]byte(rendered), &raw); err != nil {
		return fragment{}, fmt.Errorf("parse rendered messages fragment: %w", err)
	}
	var out fragment
	var system []string
	for _, m := range raw {
		texts, err := fragmentTexts(m.Content)
		if err != nil {
			return fragment{}, err
		}
		if m.Role == roleSystem {
			if text := strings.Join(texts, "\n\n"); text != "" {
				system = append(system, text)
			}
			continue
		}
		if len(texts) == 0 {
			continue
		}
		out.turns = append(out.turns, fragmentTurn{role: m.Role, texts: texts})
	}
	out.system = strings.Join(system, "\n\n")
	return out, nil
}

// foldError reports that the client's own system field cannot take the
// template's system message, naming the field so the caller can fix it.
func foldError(field, reason string) error {
	return &fragmentError{
		msg:         "the request's " + field + " field cannot be read (" + reason + "), so the rendered template's system message cannot be merged into it",
		clientOwned: true,
		reason:      reason,
	}
}
