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
