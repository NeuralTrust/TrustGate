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

package tool_call_validation

import (
	"encoding/json"
	"strconv"
	"strings"

	"github.com/PaesslerAG/jsonpath"
)

type pathToken struct {
	key     string
	index   int
	isIndex bool
}

func stringArgumentValue(arguments, path string) (string, bool) {
	if arguments == "" {
		return "", false
	}
	var obj any
	if err := json.Unmarshal([]byte(arguments), &obj); err != nil {
		return "", false
	}
	val, err := jsonpath.Get(path, obj)
	if err != nil {
		return "", false
	}
	s, ok := val.(string)
	if !ok {
		return "", false
	}
	return s, true
}

func parsePathTokens(path string) ([]pathToken, bool) {
	if !strings.HasPrefix(path, "$") {
		return nil, false
	}
	rest := path[1:]
	var tokens []pathToken
	i := 0
	for i < len(rest) {
		switch rest[i] {
		case '.':
			i++
			start := i
			for i < len(rest) && rest[i] != '.' && rest[i] != '[' {
				i++
			}
			if start == i {
				return nil, false
			}
			tokens = append(tokens, pathToken{key: rest[start:i]})
		case '[':
			i++
			start := i
			for i < len(rest) && rest[i] != ']' {
				i++
			}
			if i >= len(rest) {
				return nil, false
			}
			seg := strings.TrimSpace(rest[start:i])
			i++
			if len(seg) >= 2 && (seg[0] == '\'' || seg[0] == '"') {
				tokens = append(tokens, pathToken{key: seg[1 : len(seg)-1]})
				continue
			}
			n, err := strconv.Atoi(seg)
			if err != nil {
				return nil, false
			}
			tokens = append(tokens, pathToken{index: n, isIndex: true})
		default:
			return nil, false
		}
	}
	if len(tokens) == 0 {
		return nil, false
	}
	return tokens, true
}

func getAtPath(root any, path string) (any, bool) {
	tokens, ok := parsePathTokens(path)
	if !ok {
		return nil, false
	}
	cur := root
	for _, t := range tokens {
		next, ok := descend(cur, t)
		if !ok {
			return nil, false
		}
		cur = next
	}
	return cur, true
}

func setAtPath(root any, path string, value any) bool {
	tokens, ok := parsePathTokens(path)
	if !ok {
		return false
	}
	cur := root
	for _, t := range tokens[:len(tokens)-1] {
		next, ok := descend(cur, t)
		if !ok {
			return false
		}
		cur = next
	}
	last := tokens[len(tokens)-1]
	if last.isIndex {
		arr, ok := cur.([]any)
		if !ok || last.index < 0 || last.index >= len(arr) {
			return false
		}
		arr[last.index] = value
		return true
	}
	m, ok := cur.(map[string]any)
	if !ok {
		return false
	}
	if _, exists := m[last.key]; !exists {
		return false
	}
	m[last.key] = value
	return true
}

func descend(cur any, t pathToken) (any, bool) {
	if t.isIndex {
		arr, ok := cur.([]any)
		if !ok || t.index < 0 || t.index >= len(arr) {
			return nil, false
		}
		return arr[t.index], true
	}
	m, ok := cur.(map[string]any)
	if !ok {
		return nil, false
	}
	v, ok := m[t.key]
	return v, ok
}
