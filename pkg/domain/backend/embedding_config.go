package backend

import (
	"database/sql/driver"
	"encoding/json"
	"fmt"
)

type EmbeddingConfig struct {
	Provider string      `json:"provider"`
	Model    string      `json:"model"`
	Auth     *APIKeyAuth `json:"auth,omitempty"`
}

func (e EmbeddingConfig) Value() (driver.Value, error) {
	return json.Marshal(e)
}

func (e *EmbeddingConfig) Scan(value interface{}) error {
	if value == nil {
		return nil
	}
	bytes, ok := value.([]byte)
	if !ok {
		return fmt.Errorf("expected []byte, got %T", value)
	}
	return json.Unmarshal(bytes, e)
}

func (e *EmbeddingConfig) Validate() error {
	if e.Model == "" {
		return fmt.Errorf("%w: model is required", ErrInvalidEmbeddingConfig)
	}
	if e.Auth == nil {
		return fmt.Errorf("%w: auth is required", ErrInvalidEmbeddingConfig)
	}
	if e.Auth.APIKey == "" {
		if e.Auth.HeaderName == "" {
			return fmt.Errorf("%w: header_name is required when api_key is empty", ErrInvalidEmbeddingConfig)
		}
		if e.Auth.HeaderValue == "" {
			return fmt.Errorf("%w: header_value is required when api_key is empty", ErrInvalidEmbeddingConfig)
		}
	}
	return nil
}
