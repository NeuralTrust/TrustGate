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

package tooltransform

import (
	"fmt"
	"path"

	"github.com/NeuralTrust/TrustGate/pkg/infra/plugins/pluginutil"
)

const (
	conflictGatewayWins = "gateway_wins"
	conflictClientWins  = "client_wins"
	conflictReject      = "reject"
)

var validScopes = map[string]struct{}{
	"consumer": {},
	"global":   {},
}

var validConflicts = map[string]struct{}{
	conflictGatewayWins: {},
	conflictClientWins:  {},
	conflictReject:      {},
}

type fnDef struct {
	Name        string                 `mapstructure:"name"`
	Description string                 `mapstructure:"description"`
	Parameters  map[string]interface{} `mapstructure:"parameters"`
}

type injectDef struct {
	Type     string `mapstructure:"type"`
	Function fnDef  `mapstructure:"function"`
}

type transformDef struct {
	Tool                string                 `mapstructure:"tool"`
	SchemaPatch         map[string]interface{} `mapstructure:"schema_patch"`
	DescriptionOverride *string                `mapstructure:"description_override"`
}

type config struct {
	Scope          string         `mapstructure:"scope"`
	TransformTools []transformDef `mapstructure:"transform_tools"`
	InjectTools    []injectDef    `mapstructure:"inject_tools"`
	OnConflict     string         `mapstructure:"on_conflict"`
}

func parseConfig(settings map[string]any) (*config, error) {
	cfg, err := pluginutil.Parse[config](settings)
	if err != nil {
		return nil, err
	}
	if err := cfg.validate(); err != nil {
		return nil, err
	}
	return &cfg, nil
}

func (c *config) validate() error {
	if c.Scope != "" {
		if _, ok := validScopes[c.Scope]; !ok {
			return fmt.Errorf("tool_definition_transformation: scope must be one of consumer, global")
		}
	}
	if c.OnConflict != "" {
		if _, ok := validConflicts[c.OnConflict]; !ok {
			return fmt.Errorf("tool_definition_transformation: on_conflict must be one of gateway_wins, client_wins, reject")
		}
	}
	for i := range c.TransformTools {
		tool := c.TransformTools[i].Tool
		if tool == "" {
			return fmt.Errorf("tool_definition_transformation: transform_tools[%d]: tool must not be empty", i)
		}
		if _, err := path.Match(tool, ""); err != nil {
			return fmt.Errorf("tool_definition_transformation: transform_tools[%d]: invalid tool pattern %q: %w", i, tool, err)
		}
	}
	for i := range c.InjectTools {
		if c.InjectTools[i].Function.Name == "" {
			return fmt.Errorf("tool_definition_transformation: inject_tools[%d]: function.name must not be empty", i)
		}
	}
	if len(c.TransformTools) == 0 && len(c.InjectTools) == 0 {
		return fmt.Errorf("tool_definition_transformation: at least one of transform_tools or inject_tools must be set")
	}
	return nil
}

func (c *config) onConflict() string {
	if c.OnConflict != "" {
		return c.OnConflict
	}
	return conflictGatewayWins
}
