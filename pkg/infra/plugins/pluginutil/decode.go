// Package pluginutil holds helpers shared across plugin implementations.
package pluginutil

import (
	"fmt"

	"github.com/mitchellh/mapstructure"
)

// Decode maps a plugin's raw settings into a typed config struct. Weakly typed
// input is enabled so JSON numbers (decoded as float64) populate int/duration
// fields without per-plugin conversion code.
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
