package upstream

import (
	"database/sql/driver"
	"encoding/json"
	"fmt"

	"github.com/NeuralTrust/TrustGate/pkg/domain"
)

type HealthCheck struct {
	Passive   bool               `json:"passive"`
	Path      string             `json:"path"`
	Headers   domain.HeadersJSON `json:"headers" gorm:"type:jsonb"`
	Threshold int                `json:"threshold"` // Number of failures before marking as unhealthy
	Interval  int                `json:"interval"`  // Time in seconds before resetting failure count
}

func (h *HealthCheck) Validate() error {
	if h.Interval <= 0 {
		return fmt.Errorf("health check interval must be positive")
	}
	if h.Threshold <= 0 {
		return fmt.Errorf("health check threshold must be positive")
	}
	return nil
}

func (h HealthCheck) Value() (driver.Value, error) {
	return json.Marshal(h)
}

func (h *HealthCheck) Scan(value interface{}) error {
	if value == nil {
		return nil
	}
	bytes, ok := value.([]byte)
	if !ok {
		return fmt.Errorf("expected []byte, got %T", value)
	}
	return json.Unmarshal(bytes, h)
}
