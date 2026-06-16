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

package pluginutil

import (
	"fmt"

	"github.com/mitchellh/mapstructure"
)

func Decode(settings map[string]any, target any) error {
	decoder, err := mapstructure.NewDecoder(&mapstructure.DecoderConfig{
		Result:           target,
		WeaklyTypedInput: true,
		ErrorUnused:      false,
	})
	if err != nil {
		return fmt.Errorf("pluginutil: build decoder: %w", err)
	}
	if err := decoder.Decode(settings); err != nil {
		return fmt.Errorf("pluginutil: decode settings: %w", err)
	}
	return nil
}

func Parse[T any](settings map[string]any) (T, error) {
	var cfg T
	if err := Decode(settings, &cfg); err != nil {
		return cfg, err
	}
	return cfg, nil
}
