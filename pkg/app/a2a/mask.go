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

package a2a

import (
	"bytes"
	"encoding/json"
	"errors"

	appplugins "github.com/NeuralTrust/TrustGate/pkg/app/plugins"
)

// A policy that masks (TrustGuard's DLP) rewrites the parts it was given, in
// the normalised body (appplugins.A2ABody). The gateway writes each rewritten
// value back where the part came from (Content.Paths): into the caller's
// JSON-RPC body before it is sent, or into the agent's result before it is
// relayed. Only the masked values change; the rest of the document keeps its
// keys and values, so the agent acts on what the policies checked.

// edit is one value a policy rewrote: a text part's text (a string) or a data
// part's data (a JSON value).
type edit struct {
	path  Path
	value any
}

// errUnwritable is a rewrite the gateway cannot write to the call: another
// number or kind of parts, a changed file part, data that is not JSON, or a
// part with nowhere to write.
var errUnwritable = errors.New("a2a: rewrite cannot be written to the call")

// edits compares the parts a policy was given with the normalised body it
// rewrote them into, and returns what changed, with where to write it.
func edits(sent []Part, paths []Path, rewritten []byte) ([]edit, error) {
	var got appplugins.A2ABody
	if err := json.Unmarshal(rewritten, &got); err != nil {
		return nil, errUnwritable
	}
	if len(got.Parts) != len(sent) {
		return nil, errUnwritable
	}
	var out []edit
	for i, was := range sent {
		now := got.Parts[i]
		if now.Type != was.Type {
			return nil, errUnwritable
		}
		var value any
		switch was.Type {
		case PartText:
			if now.Text == was.Text {
				continue
			}
			value = now.Text
		case PartData:
			if sameJSON(now.Data, was.Data) {
				continue
			}
			if !json.Valid(now.Data) {
				return nil, errUnwritable
			}
			value = json.RawMessage(bytes.TrimSpace(now.Data))
		default:
			if now.URL != was.URL || now.Raw != was.Raw || now.MediaType != was.MediaType || now.Filename != was.Filename {
				return nil, errUnwritable
			}
			continue
		}
		if i >= len(paths) || paths[i] == nil {
			return nil, errUnwritable
		}
		out = append(out, edit{path: paths[i], value: value})
	}
	return out, nil
}

// sameJSON reports whether a and b are the same JSON value, whatever their
// spacing.
func sameJSON(a, b json.RawMessage) bool {
	if bytes.Equal(a, b) {
		return true
	}
	var ca, cb bytes.Buffer
	if json.Compact(&ca, a) != nil || json.Compact(&cb, b) != nil {
		return false
	}
	return bytes.Equal(ca.Bytes(), cb.Bytes())
}

// apply writes each edit into doc and returns the new document. Numbers keep
// their literal and keys their names; only the edited values change.
func apply(doc []byte, eds []edit) ([]byte, error) {
	dec := json.NewDecoder(bytes.NewReader(doc))
	dec.UseNumber()
	var root any
	if err := dec.Decode(&root); err != nil {
		return nil, errUnwritable
	}
	for _, e := range eds {
		var ok bool
		if root, ok = setAt(root, e.path, e.value); !ok {
			return nil, errUnwritable
		}
	}
	var out bytes.Buffer
	enc := json.NewEncoder(&out)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(root); err != nil {
		return nil, errUnwritable
	}
	return bytes.TrimRight(out.Bytes(), "\n"), nil
}

// setAt sets the value at path in v, which must already hold a value there,
// and returns v. ok is false when path does not lead to one.
func setAt(v any, path Path, value any) (any, bool) {
	if len(path) == 0 {
		return value, true
	}
	switch seg := path[0].(type) {
	case string:
		obj, isObj := v.(map[string]any)
		if !isObj {
			return v, false
		}
		child, has := obj[seg]
		if !has {
			return v, false
		}
		next, ok := setAt(child, path[1:], value)
		obj[seg] = next
		return obj, ok
	case int:
		list, isList := v.([]any)
		if !isList || seg < 0 || seg >= len(list) {
			return v, false
		}
		next, ok := setAt(list[seg], path[1:], value)
		list[seg] = next
		return list, ok
	}
	return v, false
}
