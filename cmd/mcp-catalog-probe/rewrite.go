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

package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
)

// orderedObject is a JSON object that keeps its key order, so rewriting one
// field of a catalog entry leaves the rest of the file byte for byte as it was.
type orderedObject struct {
	keys   []string
	values map[string]json.RawMessage
}

func (o *orderedObject) UnmarshalJSON(data []byte) error {
	dec := json.NewDecoder(bytes.NewReader(data))
	if tok, err := dec.Token(); err != nil || tok != json.Delim('{') {
		return fmt.Errorf("catalog entry is not an object")
	}
	o.values = map[string]json.RawMessage{}
	for dec.More() {
		tok, err := dec.Token()
		if err != nil {
			return err
		}
		key, _ := tok.(string)
		var value json.RawMessage
		if err := dec.Decode(&value); err != nil {
			return err
		}
		if _, dup := o.values[key]; !dup {
			o.keys = append(o.keys, key)
		}
		o.values[key] = value
	}
	_, err := dec.Token()
	return err
}

func (o orderedObject) MarshalJSON() ([]byte, error) {
	var buf bytes.Buffer
	buf.WriteByte('{')
	for i, key := range o.keys {
		if i > 0 {
			buf.WriteByte(',')
		}
		k, err := marshalNoEscape(key)
		if err != nil {
			return nil, err
		}
		buf.Write(k)
		buf.WriteByte(':')
		buf.Write(o.values[key])
	}
	buf.WriteByte('}')
	return buf.Bytes(), nil
}

func (o *orderedObject) set(key string, value any) {
	raw, err := marshalNoEscape(value)
	if err != nil {
		fatalf("encode %s: %v", key, err)
	}
	if _, ok := o.values[key]; !ok {
		o.keys = append(o.keys, key)
	}
	o.values[key] = raw
}

func (o *orderedObject) del(key string) {
	if _, ok := o.values[key]; !ok {
		return
	}
	delete(o.values, key)
	for i, k := range o.keys {
		if k == key {
			o.keys = append(o.keys[:i], o.keys[i+1:]...)
			return
		}
	}
}

// marshalNoEscape encodes without HTML escaping: the catalog holds "&" in
// vendor names and descriptions, and json.Marshal would rewrite it as &.
func marshalNoEscape(v any) ([]byte, error) {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(v); err != nil {
		return nil, err
	}
	return bytes.TrimRight(buf.Bytes(), "\n"), nil
}

// rewriteCatalog applies edit to every server of the catalog file at path and
// writes it back in the file's own layout (two-space indent, keys in place).
// edit reports whether it changed the entry.
func rewriteCatalog(path string, edit func(i int, server *orderedObject) bool) int {
	raw, err := os.ReadFile(path)
	if err != nil {
		fatalf("read catalog: %v", err)
	}
	var doc struct {
		Servers []*orderedObject `json:"servers"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		fatalf("parse catalog: %v", err)
	}
	changed := 0
	for i, s := range doc.Servers {
		if edit(i, s) {
			changed++
		}
	}
	compact, err := marshalNoEscape(doc)
	if err != nil {
		fatalf("encode catalog: %v", err)
	}
	var out bytes.Buffer
	if err := json.Indent(&out, compact, "", "  "); err != nil {
		fatalf("indent catalog: %v", err)
	}
	out.WriteByte('\n')
	if err := os.WriteFile(path, out.Bytes(), 0o644); err != nil { // #nosec G306 -- a tracked source file, not a secret
		fatalf("write catalog: %v", err)
	}
	return changed
}
