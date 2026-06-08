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
