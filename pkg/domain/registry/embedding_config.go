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

package registry

import (
	"database/sql/driver"
	"encoding/json"
	"fmt"

	"github.com/NeuralTrust/AgentGateway/pkg/common/secret"
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

func (e *EmbeddingConfig) ResolveSecretsFrom(prev *EmbeddingConfig) {
	if e == nil || prev == nil || e.Auth == nil || prev.Auth == nil {
		return
	}
	e.Auth.APIKey = secret.Resolve(e.Auth.APIKey, prev.Auth.APIKey)
	e.Auth.HeaderValue = secret.Resolve(e.Auth.HeaderValue, prev.Auth.HeaderValue)
	e.Auth.ParamValue = secret.Resolve(e.Auth.ParamValue, prev.Auth.ParamValue)
}

func (e *EmbeddingConfig) Validate() error {
	if e.Model == "" {
		return fmt.Errorf("%w: model is required", ErrInvalidEmbeddingConfig)
	}
	if e.Auth == nil {
		return fmt.Errorf("%w: auth is required", ErrInvalidEmbeddingConfig)
	}
	if secret.IsMasked(e.Auth.APIKey) || secret.IsMasked(e.Auth.HeaderValue) || secret.IsMasked(e.Auth.ParamValue) {
		return fmt.Errorf("%w: secret cannot be a masked value; omit it to keep the stored value", ErrInvalidEmbeddingConfig)
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
