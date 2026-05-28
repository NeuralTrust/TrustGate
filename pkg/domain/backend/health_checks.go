package backend

import (
	"database/sql/driver"
	"encoding/json"
	"fmt"
)

type HealthChecks struct {
	Passive   bool              `json:"passive"`
	Path      string            `json:"path,omitempty"`
	Headers   map[string]string `json:"headers,omitempty"`
	Threshold int               `json:"threshold"`
	Interval  int               `json:"interval"`
}

func (h *HealthChecks) Validate() error {
	if h.Interval <= 0 {
		return fmt.Errorf("%w: health_checks.interval must be positive", ErrInvalidHealthChecks)
	}
	if h.Threshold <= 0 {
		return fmt.Errorf("%w: health_checks.threshold must be positive", ErrInvalidHealthChecks)
	}
	return nil
}

func (h HealthChecks) Value() (driver.Value, error) {
	return json.Marshal(h)
}

func (h *HealthChecks) Scan(value interface{}) error {
	if value == nil {
		return nil
	}
	bytes, ok := value.([]byte)
	if !ok {
		return fmt.Errorf("expected []byte, got %T", value)
	}
	return json.Unmarshal(bytes, h)
}
