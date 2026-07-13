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

package promptdecorator

import (
	"fmt"
	"strings"

	"github.com/mitchellh/mapstructure"
)

type position string

const (
	positionStart          position = "start"
	positionEnd            position = "end"
	positionAfterSystem    position = "after_system"
	positionBeforeLastUser position = "before_last_user"
	positionSystem         position = "system"
)

type role string

const (
	roleSystem    role = "system"
	roleUser      role = "user"
	roleAssistant role = "assistant"
)

type systemStrategy string

const (
	systemStrategyMerge   systemStrategy = "merge"
	systemStrategyReplace systemStrategy = "replace"
	systemStrategyAppend  systemStrategy = "append"
	systemStrategySkip    systemStrategy = "skip"
)

type decorator struct {
	Position         position        `mapstructure:"position"`
	Role             role            `mapstructure:"role"`
	Content          string          `mapstructure:"content"`
	OnExistingSystem *systemStrategy `mapstructure:"on_existing_system"`
}

type config struct {
	Scope                string      `mapstructure:"scope"`
	Decorators           []decorator `mapstructure:"decorators"`
	RequireSystemMessage bool        `mapstructure:"require_system_message"`
}

func parseConfig(settings map[string]any) (*config, error) {
	if err := validateSettingsTypes(settings); err != nil {
		return nil, err
	}
	var cfg config
	decoder, err := mapstructure.NewDecoder(&mapstructure.DecoderConfig{
		Result:           &cfg,
		TagName:          "mapstructure",
		ErrorUnused:      true,
		WeaklyTypedInput: false,
		MatchName: func(mapKey, fieldName string) bool {
			return mapKey == fieldName
		},
	})
	if err != nil {
		return nil, fmt.Errorf("prompt_decorator: build settings decoder: %w", err)
	}
	if err := decoder.Decode(settings); err != nil {
		return nil, fmt.Errorf("prompt_decorator: invalid settings: %w", err)
	}
	if err := cfg.validate(); err != nil {
		return nil, err
	}
	return &cfg, nil
}

func validateSettingsTypes(settings map[string]any) error {
	if err := validateStringSettings(settings, "", "scope"); err != nil {
		return err
	}
	if value, ok := settings["require_system_message"]; ok {
		if _, valid := value.(bool); !valid {
			return invalidSettingType("require_system_message", "true or false", value)
		}
	}
	value, ok := settings["decorators"]
	if !ok {
		return nil
	}
	decorators, valid := value.([]any)
	if !valid {
		return invalidSettingType("decorators", "a list", value)
	}
	for i, value := range decorators {
		path := fmt.Sprintf("decorators[%d]", i)
		decorator, valid := value.(map[string]any)
		if !valid {
			return invalidSettingType(path, "an object", value)
		}
		if err := validateStringSettings(decorator, path+".", "position", "role", "content", "on_existing_system"); err != nil {
			return err
		}
	}
	return nil
}

func validateStringSettings(settings map[string]any, prefix string, names ...string) error {
	for _, name := range names {
		value, ok := settings[name]
		if !ok {
			continue
		}
		if _, valid := value.(string); !valid {
			return invalidSettingType(prefix+name, "text", value)
		}
	}
	return nil
}

func invalidSettingType(path, expected string, value any) error {
	received := fmt.Sprintf("%T", value)
	if value == nil {
		received = "null"
	}
	return fmt.Errorf(
		"prompt_decorator: invalid settings: field %q must be %s but received %s",
		path,
		expected,
		received,
	)
}

func (c *config) validate() error {
	switch c.Scope {
	case "", "consumer", "global":
	default:
		return fmt.Errorf("prompt_decorator: scope %q must be consumer or global", c.Scope)
	}
	if len(c.Decorators) == 0 && !c.RequireSystemMessage {
		return fmt.Errorf("prompt_decorator: at least one decorator or require_system_message=true is required")
	}
	for i := range c.Decorators {
		if err := c.Decorators[i].validate(i); err != nil {
			return err
		}
	}
	return nil
}

func (d decorator) validate(index int) error {
	if strings.TrimSpace(string(d.Position)) == "" {
		return fmt.Errorf("prompt_decorator: decorators[%d].position must not be blank", index)
	}
	switch d.Position {
	case positionStart, positionEnd, positionAfterSystem, positionBeforeLastUser, positionSystem:
	default:
		return fmt.Errorf("prompt_decorator: decorators[%d].position %q must be start, end, after_system, before_last_user, or system", index, d.Position)
	}
	if strings.TrimSpace(string(d.Role)) == "" {
		return fmt.Errorf("prompt_decorator: decorators[%d].role must not be blank", index)
	}
	switch d.Role {
	case roleSystem, roleUser, roleAssistant:
	default:
		return fmt.Errorf("prompt_decorator: decorators[%d].role %q must be system, user, or assistant", index, d.Role)
	}
	if strings.TrimSpace(d.Content) == "" {
		return fmt.Errorf("prompt_decorator: decorators[%d].content must not be blank", index)
	}
	if d.Position == positionSystem {
		return d.validateSystemPosition(index)
	}
	if d.Role == roleSystem {
		return fmt.Errorf("prompt_decorator: decorators[%d].role system requires position system", index)
	}
	if d.OnExistingSystem != nil {
		return fmt.Errorf("prompt_decorator: decorators[%d].on_existing_system is only allowed with position system", index)
	}
	return nil
}

func (d decorator) validateSystemPosition(index int) error {
	if d.Role != roleSystem {
		return fmt.Errorf("prompt_decorator: decorators[%d].position system requires role system", index)
	}
	if d.OnExistingSystem == nil {
		return fmt.Errorf("prompt_decorator: decorators[%d].on_existing_system is required with position system", index)
	}
	switch *d.OnExistingSystem {
	case systemStrategyMerge, systemStrategyReplace, systemStrategyAppend, systemStrategySkip:
		return nil
	default:
		return fmt.Errorf("prompt_decorator: decorators[%d].on_existing_system %q must be merge, replace, append, or skip", index, *d.OnExistingSystem)
	}
}
