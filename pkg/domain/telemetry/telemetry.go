package telemetry

import (
	"database/sql/driver"
	"encoding/json"
	"fmt"
)

type Telemetry struct {
	Exporters []ExporterConfig `json:"exporters"`
}

type ExporterConfig struct {
	Name     string                 `json:"name"`
	Settings map[string]interface{} `json:"settings"`
}

func (t Telemetry) Value() (driver.Value, error) {
	return json.Marshal(t)
}

func (t *Telemetry) Scan(value interface{}) error {
	bytes, ok := value.([]byte)
	if !ok {
		return fmt.Errorf("could not convert value %v to []byte", value)
	}
	return json.Unmarshal(bytes, t)
}
