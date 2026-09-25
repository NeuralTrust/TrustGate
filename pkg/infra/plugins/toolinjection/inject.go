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

package toolinjection

import (
	"encoding/json"
	"fmt"
	"net/http"

	appplugins "github.com/NeuralTrust/TrustGate/pkg/app/plugins"
	"github.com/NeuralTrust/TrustGate/pkg/infra/providers/adapter"
)

const (
	outcomeAppended = "appended"
	outcomeReplaced = "replaced"
	outcomeDropped  = "dropped"
	outcomeRejected = "rejected"
)

type injectOutcome struct {
	Name    string
	Outcome string
}

func indexOfTool(tools []adapter.CanonicalTool, name string) int {
	for i := range tools {
		if tools[i].Name == name {
			return i
		}
	}
	return -1
}

func applyInjections(
	tools []adapter.CanonicalTool,
	entries []injectDef,
	conflict string,
) ([]adapter.CanonicalTool, []injectOutcome, error) {
	outcomes := make([]injectOutcome, 0, len(entries))
	for i := range entries {
		ct := adapter.CanonicalTool{
			Name:        entries[i].Function.Name,
			Description: entries[i].Function.Description,
			Schema:      entries[i].Function.Parameters,
		}
		idx := indexOfTool(tools, ct.Name)
		if idx < 0 {
			tools = append(tools, ct)
			outcomes = append(outcomes, injectOutcome{Name: ct.Name, Outcome: outcomeAppended})
			continue
		}
		switch conflict {
		case conflictGatewayWins:
			ct.Cache = tools[idx].Cache
			tools[idx] = ct
			tools = dropLaterCopies(tools, idx)
			outcomes = append(outcomes, injectOutcome{Name: ct.Name, Outcome: outcomeReplaced})
		case conflictClientWins:
			outcomes = append(outcomes, injectOutcome{Name: ct.Name, Outcome: outcomeDropped})
		case conflictReject:
			return nil, nil, rejectError(ct.Name)
		}
	}
	return tools, outcomes, nil
}

// dropLaterCopies removes the tools after idx that share its name, so a
// client that declares a tool twice keeps no copy of its own beside the
// gateway's.
func dropLaterCopies(tools []adapter.CanonicalTool, idx int) []adapter.CanonicalTool {
	name := tools[idx].Name
	out := tools[:idx+1]
	for _, t := range tools[idx+1:] {
		if t.Name != name {
			out = append(out, t)
		}
	}
	return out
}

// resolveLegacyConflicts applies conflict to the injected tools that share a
// name with a legacy Chat function of the client. gateway_wins drops the
// client's function, client_wins skips the injection, and reject refuses
// the request. It returns the entries left to inject and the functions to
// drop.
func resolveLegacyConflicts(entries []injectDef, legacy map[string]bool, conflict string) ([]injectDef, map[string]bool, []injectOutcome, error) {
	if len(legacy) == 0 {
		return entries, nil, nil, nil
	}
	kept := make([]injectDef, 0, len(entries))
	var drop map[string]bool
	var skipped []injectOutcome
	for _, e := range entries {
		name := e.Function.Name
		if !legacy[name] {
			kept = append(kept, e)
			continue
		}
		switch conflict {
		case conflictReject:
			return nil, nil, nil, rejectError(name)
		case conflictClientWins:
			skipped = append(skipped, injectOutcome{Name: name, Outcome: outcomeDropped})
		default:
			if drop == nil {
				drop = map[string]bool{}
			}
			drop[name] = true
			kept = append(kept, e)
		}
	}
	return kept, drop, skipped, nil
}

func rejectError(name string) error {
	body, err := json.Marshal(map[string]any{
		"error": map[string]any{
			"type": "tool_name_reserved",
			"name": name,
		},
	})
	if err != nil {
		body = nil
	}
	return &appplugins.PluginError{
		StatusCode: http.StatusBadRequest,
		Type:       "tool_name_reserved",
		Message:    fmt.Sprintf("tool name %q is reserved by the gateway", name),
		Body:       body,
	}
}
