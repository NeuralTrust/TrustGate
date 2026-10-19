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

package registry

import (
	"net/url"
	"strings"
)

// AdminBoundValues reads non-secret placeholder values an admin wrote into
// rowURL. catalogURL is the catalog template those values were substituted
// into (the Registry create form writes them into mcp_target.url and does not
// store a separate map). Secret variables are omitted: a per-user credential
// still belongs to the caller. ok is false when rowURL does not follow
// catalogURL. An exact copy of the template, placeholders and all, returns an
// empty map and ok true.
func AdminBoundValues(catalogURL string, vars []MCPURLVariable, rowURL string) (map[string]string, bool) {
	raw, ok := ConcreteTemplateValues(catalogURL, rowURL)
	if !ok {
		return nil, false
	}
	if len(raw) == 0 {
		return map[string]string{}, true
	}
	secret := make(map[string]struct{}, len(vars))
	for _, variable := range vars {
		if variable.Secret {
			secret[variable.Name] = struct{}{}
		}
	}
	out := make(map[string]string, len(raw))
	for name, value := range raw {
		if _, skip := secret[name]; skip {
			continue
		}
		decoded, err := url.PathUnescape(value)
		if err != nil || strings.TrimSpace(decoded) == "" || strings.ContainsAny(decoded, "{}") {
			return nil, false
		}
		out[name] = decoded
	}
	if len(out) == 0 {
		return map[string]string{}, true
	}
	return out, true
}

// ConcreteTemplateValues returns placeholder values that were written into
// actual in place of template's {name} tokens. A placeholder actual still
// contains is omitted. ok is false when actual does not follow template.
// An exact copy of template, placeholders and all, returns an empty map.
func ConcreteTemplateValues(template, actual string) (map[string]string, bool) {
	template = strings.TrimSpace(template)
	actual = strings.TrimSpace(actual)
	if template == "" || actual == "" {
		return nil, false
	}
	pieces := templatePieces(template)
	values := make(map[string]string)
	rest := actual
	for i, piece := range pieces {
		if piece.name == "" {
			if !strings.HasPrefix(rest, piece.text) {
				return nil, false
			}
			rest = rest[len(piece.text):]
			continue
		}
		litAfter := ""
		if i+1 < len(pieces) && pieces[i+1].name == "" {
			litAfter = pieces[i+1].text
		}
		token := "{" + piece.name + "}"
		if strings.HasPrefix(rest, token) {
			after := rest[len(token):]
			if litAfter == "" || strings.HasPrefix(after, litAfter) {
				rest = after
				continue
			}
		}
		var val string
		switch litAfter {
		case "":
			val = rest
			rest = ""
		default:
			idx := strings.Index(rest, litAfter)
			if idx < 0 {
				return nil, false
			}
			val = rest[:idx]
			rest = rest[idx:]
		}
		if val == "" || strings.ContainsAny(val, "{}") {
			return nil, false
		}
		if prev, seen := values[piece.name]; seen && prev != val {
			return nil, false
		}
		values[piece.name] = val
	}
	if rest != "" {
		return nil, false
	}
	if len(values) == 0 {
		return map[string]string{}, true
	}
	return values, true
}

type templatePiece struct {
	name string
	text string
}

func templatePieces(template string) []templatePiece {
	locs := urlTemplateToken.FindAllStringSubmatchIndex(template, -1)
	if len(locs) == 0 {
		return []templatePiece{{text: template}}
	}
	out := make([]templatePiece, 0, len(locs)*2+1)
	prev := 0
	for _, loc := range locs {
		if loc[0] > prev {
			out = append(out, templatePiece{text: template[prev:loc[0]]})
		}
		out = append(out, templatePiece{name: template[loc[2]:loc[3]]})
		prev = loc[1]
	}
	if prev < len(template) {
		out = append(out, templatePiece{text: template[prev:]})
	}
	return out
}
