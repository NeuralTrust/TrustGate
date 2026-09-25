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

package adapter

import (
	"bytes"
	"encoding/json"
	"errors"
	"sort"
	"strconv"
	"strings"
)

var errRawJSON = errors.New("malformed json")

type rawSpan struct{ start, end int }

type rawField struct {
	key   string
	entry rawSpan
	value rawSpan
}

type rawPatch struct {
	at   rawSpan
	with []byte
}

func skipRawSpace(b []byte, i int) int {
	for i < len(b) && (b[i] == ' ' || b[i] == '\t' || b[i] == '\n' || b[i] == '\r') {
		i++
	}
	return i
}

func rawRoot(b []byte) (rawSpan, error) {
	start := skipRawSpace(b, 0)
	end, err := rawValueEnd(b, start)
	if err != nil {
		return rawSpan{}, err
	}
	return rawSpan{start, end}, nil
}

func rawValueEnd(b []byte, i int) (int, error) {
	if i >= len(b) {
		return 0, errRawJSON
	}
	switch b[i] {
	case '"':
		return rawStringEnd(b, i)
	case '{', '[':
		return rawContainerEnd(b, i)
	}
	j := i
	for j < len(b) && strings.IndexByte(",}] \t\r\n", b[j]) < 0 {
		j++
	}
	if j == i {
		return 0, errRawJSON
	}
	return j, nil
}

func rawStringEnd(b []byte, i int) (int, error) {
	for j := i + 1; j < len(b); j++ {
		switch b[j] {
		case '\\':
			j++
		case '"':
			return j + 1, nil
		}
	}
	return 0, errRawJSON
}

func rawContainerEnd(b []byte, i int) (int, error) {
	closer := byte(']')
	if b[i] == '{' {
		closer = '}'
	}
	j := skipRawSpace(b, i+1)
	if j < len(b) && b[j] == closer {
		return j + 1, nil
	}
	for {
		var err error
		if closer == '}' {
			if j, err = rawStringEnd(b, j); err != nil {
				return 0, err
			}
			j = skipRawSpace(b, j)
			if j >= len(b) || b[j] != ':' {
				return 0, errRawJSON
			}
			j = skipRawSpace(b, j+1)
		}
		if j, err = rawValueEnd(b, j); err != nil {
			return 0, err
		}
		j = skipRawSpace(b, j)
		if j >= len(b) {
			return 0, errRawJSON
		}
		if b[j] == closer {
			return j + 1, nil
		}
		if b[j] != ',' {
			return 0, errRawJSON
		}
		j = skipRawSpace(b, j+1)
	}
}

func rawFields(b []byte, s rawSpan) ([]rawField, error) {
	if s.end-s.start < 2 || b[s.start] != '{' {
		return nil, errRawJSON
	}
	var fields []rawField
	j := skipRawSpace(b, s.start+1)
	for j < s.end-1 {
		keyEnd, err := rawStringEnd(b, j)
		if err != nil {
			return nil, err
		}
		var key string
		if err := json.Unmarshal(b[j:keyEnd], &key); err != nil {
			return nil, err
		}
		v := skipRawSpace(b, skipRawSpace(b, keyEnd)+1)
		vEnd, err := rawValueEnd(b, v)
		if err != nil {
			return nil, err
		}
		fields = append(fields, rawField{key: key, entry: rawSpan{j, vEnd}, value: rawSpan{v, vEnd}})
		j = skipRawSpace(b, vEnd)
		if j < len(b) && b[j] == ',' {
			j = skipRawSpace(b, j+1)
		}
	}
	return fields, nil
}

func rawItems(b []byte, s rawSpan) ([]rawSpan, error) {
	if s.end-s.start < 2 || b[s.start] != '[' {
		return nil, errRawJSON
	}
	var items []rawSpan
	j := skipRawSpace(b, s.start+1)
	for j < s.end-1 {
		end, err := rawValueEnd(b, j)
		if err != nil {
			return nil, err
		}
		items = append(items, rawSpan{j, end})
		j = skipRawSpace(b, end)
		if j < len(b) && b[j] == ',' {
			j = skipRawSpace(b, j+1)
		}
	}
	return items, nil
}

// rawFieldOf returns the last field named key, as encoding/json does for
// duplicate keys.
func rawFieldOf(b []byte, s rawSpan, key string) (rawSpan, bool) {
	fields, err := rawFields(b, s)
	if err != nil {
		return rawSpan{}, false
	}
	found, ok := rawSpan{}, false
	for _, f := range fields {
		if f.key == key {
			found, ok = f.value, true
		}
	}
	return found, ok
}

func rawAt(b []byte, s rawSpan, path []string) (rawSpan, bool) {
	for _, step := range path {
		switch {
		case s.end > s.start && b[s.start] == '{':
			var ok bool
			if s, ok = rawFieldOf(b, s, step); !ok {
				return rawSpan{}, false
			}
		case s.end > s.start && b[s.start] == '[':
			idx, err := strconv.Atoi(step)
			items, itemsErr := rawItems(b, s)
			if err != nil || itemsErr != nil || idx < 0 || idx >= len(items) {
				return rawSpan{}, false
			}
			s = items[idx]
		default:
			return rawSpan{}, false
		}
	}
	return s, true
}

func rawString(b []byte, s rawSpan) (string, bool) {
	if s.end-s.start < 2 || b[s.start] != '"' {
		return "", false
	}
	var v string
	if json.Unmarshal(b[s.start:s.end], &v) != nil {
		return "", false
	}
	return v, true
}

func marshalRawString(s string) []byte {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	if enc.Encode(s) != nil {
		return nil
	}
	return bytes.TrimSuffix(buf.Bytes(), []byte("\n"))
}

// rawListEdits edits the entries of one object or array in place: drop[i]
// removes entry i with one separator, replace[i] swaps its bytes, and added
// entries go before the closing bracket at closeAt. Bytes between kept
// entries are untouched.
func rawListEdits(entries []rawSpan, closeAt int, drop []bool, replace map[int][]byte, added [][]byte) []rawPatch {
	var patches []rawPatch
	kept := 0
	for i := range entries {
		if drop[i] {
			continue
		}
		kept++
		if with, ok := replace[i]; ok {
			patches = append(patches, rawPatch{at: entries[i], with: with})
		}
	}
	for i := 0; i < len(entries); {
		if !drop[i] {
			i++
			continue
		}
		j := i
		for j+1 < len(entries) && drop[j+1] {
			j++
		}
		switch {
		case j+1 < len(entries):
			patches = append(patches, rawPatch{at: rawSpan{entries[i].start, entries[j+1].start}})
		case i > 0:
			patches = append(patches, rawPatch{at: rawSpan{entries[i-1].end, entries[j].end}})
		default:
			patches = append(patches, rawPatch{at: rawSpan{entries[i].start, entries[j].end}})
		}
		i = j + 1
	}
	if len(added) > 0 {
		var ins []byte
		for n, a := range added {
			if kept > 0 || n > 0 {
				ins = append(ins, ',')
			}
			ins = append(ins, a...)
		}
		at := closeAt
		if kept > 0 {
			for i := len(entries) - 1; i >= 0; i-- {
				if !drop[i] {
					at = entries[i].end
					break
				}
			}
		}
		patches = append(patches, rawPatch{at: rawSpan{at, at}, with: ins})
	}
	return patches
}

func applyRawPatches(b []byte, patches []rawPatch) ([]byte, error) {
	sorted := append([]rawPatch(nil), patches...)
	sort.SliceStable(sorted, func(i, j int) bool {
		if sorted[i].at.start != sorted[j].at.start {
			return sorted[i].at.start < sorted[j].at.start
		}
		return sorted[i].at.end == sorted[i].at.start && sorted[j].at.end != sorted[j].at.start
	})
	out := make([]byte, 0, len(b))
	pos := 0
	for _, p := range sorted {
		if p.at.start < pos || p.at.end < p.at.start || p.at.end > len(b) {
			return nil, errRawJSON
		}
		out = append(out, b[pos:p.at.start]...)
		out = append(out, p.with...)
		pos = p.at.end
	}
	return append(out, b[pos:]...), nil
}
