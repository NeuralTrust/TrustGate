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
	"net/http"
	"strconv"
	"strings"
)

type modeBResult struct {
	hasReference     bool
	changed          bool
	resolvedTemplate string
}

func applyModeB(cfg *config, rb *requestBody, clientVars map[string]any, ctxVars map[string]string) (modeBResult, error) {
	refs := rb.findReferences()
	if len(refs) == 0 {
		if !cfg.AllowUntemplatedRequests {
			return modeBResult{}, reject(http.StatusBadRequest, typeRequired, "request does not reference a template")
		}
		return modeBResult{}, nil
	}

	ref := refs[0]
	nt, ok := findNamedTemplate(cfg, ref.name)
	if !ok {
		return modeBResult{hasReference: true}, reject(http.StatusBadRequest, typeNotFound, fmt.Sprintf("template %q not found", ref.name))
	}
	version, ok := resolveVersion(*nt, ref.label, cfg.DefaultLabel)
	if !ok {
		return modeBResult{hasReference: true}, reject(http.StatusBadRequest, typeNotFound, fmt.Sprintf("template %q label could not be resolved", ref.name))
	}

	result := modeBResult{hasReference: true, resolvedTemplate: nt.Name}

	if err := validateClientVars(version, clientVars); err != nil {
		return result, err
	}

	escape := cfg.EscapeJSONControlChars == nil || *cfg.EscapeJSONControlChars
	rendered, err := renderTemplateContent(version, clientVars, ctxVars, escape, cfg.OnMissingClientVariable)
	if err != nil {
		return result, err
	}
	if err := rb.replaceMessages(rendered); err != nil {
		return result, reject(http.StatusInternalServerError, typeRenderFailed, "rendered template is not a valid messages array")
	}

	result.changed = true
	return result, nil
}

func findNamedTemplate(cfg *config, name string) (*namedTemplate, bool) {
	for i := range cfg.NamedTemplates {
		if cfg.NamedTemplates[i].Name == name {
			return &cfg.NamedTemplates[i], true
		}
	}
	return nil, false
}

func resolveVersion(nt namedTemplate, label, defaultLabel string) (*templateVersion, bool) {
	effective := label
	if effective == "" {
		effective = defaultLabel
	}
	if effective == "" {
		return nil, false
	}
	for i := range nt.Versions {
		for _, l := range nt.Versions[i].Labels {
			if l == effective {
				return &nt.Versions[i], true
			}
		}
	}
	return nil, false
}

func renderTemplateContent(version *templateVersion, clientVars map[string]any, ctxVars map[string]string, escape bool, onMissing onMissingClient) (string, error) {
	jsonContext := strings.HasPrefix(strings.TrimSpace(version.Content), "[")
	vars := make(map[string]string, len(ctxVars)+len(clientVars))
	for k, v := range ctxVars {
		vars[k] = escapeValue(v, escape, jsonContext)
	}
	for k, v := range clientVars {
		vars[k] = escapeValue(scalarToString(v), escape, jsonContext)
	}
	rendered, missing := renderTemplate(version.Content, vars)
	if len(missing) > 0 && onMissing == onMissingClientError {
		return "", reject(http.StatusBadRequest, typeVariableMissing, fmt.Sprintf("client variable %q is missing", missing[0]))
	}
	return rendered, nil
}

func escapeValue(s string, escape, jsonContext bool) string {
	if escape {
		s = escapeControlChars(s)
	}
	if jsonContext {
		return jsonEscapeString(s)
	}
	return s
}

func jsonEscapeString(s string) string {
	encoded, err := json.Marshal(s)
	if err != nil {
		return s
	}
	return string(encoded[1 : len(encoded)-1])
}

func scalarToString(v any) string {
	switch t := v.(type) {
	case string:
		return t
	case bool:
		return strconv.FormatBool(t)
	case float64:
		return strconv.FormatFloat(t, 'f', -1, 64)
	case json.Number:
		return t.String()
	case nil:
		return ""
	default:
		return fmt.Sprintf("%v", t)
	}
}
