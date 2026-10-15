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

package mcp

import "encoding/json"

// Tool risk classes, from the MCP tool annotations a server declares.
const (
	ToolRiskReadOnly    = "read_only"
	ToolRiskAdditive    = "additive"
	ToolRiskDestructive = "destructive"
)

// toolHints are the behaviour hints of an MCP tool's annotations. A nil field
// is a hint the server did not declare.
type toolHints struct {
	ReadOnly    *bool `json:"readOnlyHint"`
	Destructive *bool `json:"destructiveHint"`
	Idempotent  *bool `json:"idempotentHint"`
	OpenWorld   *bool `json:"openWorldHint"`
}

func (h toolHints) declared() bool {
	return h.ReadOnly != nil || h.Destructive != nil || h.Idempotent != nil || h.OpenWorld != nil
}

// Risk classifies the tool from the hints its server declared: read_only when
// it says it changes nothing, otherwise destructive unless it says it is not
// (the protocol's default for a tool that writes), otherwise additive.
// openWorld is the openWorldHint, true by default.
//
// A tool that declares no hint at all is unannotated: risk is "" and openWorld
// nil, rather than the defaults, which would label every unannotated tool
// destructive. The hints are the server's own claim, never verified; they
// describe, they do not enforce.
func (t Tool) Risk() (risk string, openWorld *bool) {
	raw, ok := t.payload["annotations"]
	if !ok {
		return "", nil
	}
	var hints toolHints
	if err := json.Unmarshal(raw, &hints); err != nil || !hints.declared() {
		return "", nil
	}
	world := hints.OpenWorld == nil || *hints.OpenWorld
	switch {
	case hints.ReadOnly != nil && *hints.ReadOnly:
		return ToolRiskReadOnly, &world
	case hints.Destructive == nil || *hints.Destructive:
		return ToolRiskDestructive, &world
	default:
		return ToolRiskAdditive, &world
	}
}
