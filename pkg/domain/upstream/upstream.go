package upstream

import (
	"database/sql/driver"
	"encoding/json"
	"fmt"
	"slices"
	"time"

	"github.com/NeuralTrust/TrustGate/pkg/domain"
	"github.com/google/uuid"
	"gorm.io/gorm"
)

var ErrUpstreamIsBeingUsed = fmt.Errorf("upstream is being used by a gateway")

type EmbeddingConfig struct {
	Provider    string                 `json:"provider"`
	Model       string                 `json:"model"`
	Credentials domain.CredentialsJSON `json:"credentials,omitempty" gorm:"type:jsonb"`
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

type Target struct {
	ID           string                 `json:"id"`
	Weight       int                    `json:"weight,omitempty"`
	Priority     int                    `json:"priority,omitempty"`
	Tags         domain.TagsJSON        `json:"tags,omitempty" gorm:"type:jsonb"`
	Headers      domain.HeadersJSON     `json:"headers,omitempty" gorm:"type:jsonb"`
	Path         string                 `json:"path,omitempty"`
	Host         string                 `json:"host,omitempty"`
	Port         int                    `json:"port,omitempty"`
	Protocol     string                 `json:"protocol,omitempty"`
	Provider     string                 `json:"provider,omitempty"`
	Models       ModelsJSON             `json:"models,omitempty" gorm:"type:jsonb"`
	DefaultModel string                 `json:"default_model,omitempty"`
	Description  string                 `json:"description,omitempty"`
	Credentials  domain.CredentialsJSON `json:"credentials,omitempty" gorm:"type:jsonb"`
	Stream       bool                   `json:"stream,omitempty"`
	InsecureSSL  bool                   `json:"insecure_ssl,omitempty"`
}

type ModelsJSON []string

func (m ModelsJSON) Value() (driver.Value, error) {
	if m == nil {
		return []byte("[]"), nil
	}
	return json.Marshal(m)
}

func (m *ModelsJSON) Scan(value interface{}) error {
	if value == nil {
		*m = ModelsJSON{}
		return nil
	}
	bytes, ok := value.([]byte)
	if !ok {
		return fmt.Errorf("expected []byte, got %T", value)
	}
	return json.Unmarshal(bytes, m)
}

type Targets []Target

func (t Targets) Value() (driver.Value, error) {
	if t != nil && len(t) == 0 {
		return []byte("[]"), nil
	}
	return json.Marshal(t)
}

func (t *Targets) Scan(value interface{}) error {
	if value == nil {
		*t = make(Targets, 0)
		return nil
	}

	bytes, ok := value.([]byte)
	if !ok {
		return fmt.Errorf("expected []byte, got %T", value)
	}

	// Handle both array and object cases
	var temp interface{}
	if err := json.Unmarshal(bytes, &temp); err != nil {
		return err
	}

	switch v := temp.(type) {
	case []interface{}:
		return json.Unmarshal(bytes, t)
	case map[string]interface{}:
		// If it's a single object, wrap it in an array
		*t = make(Targets, 1)
		return json.Unmarshal(bytes, &(*t)[0])
	default:
		return fmt.Errorf("unexpected JSON type: %T", v)
	}
}

type Proxy struct {
	Host     string `json:"host"`
	Port     string `json:"port"`
	Protocol string `json:"protocol"`
}

func (p Proxy) Value() (driver.Value, error) {
	return json.Marshal(p)
}

func (p *Proxy) Scan(value interface{}) error {
	if value == nil {
		return nil
	}
	bytes, ok := value.([]byte)
	if !ok {
		return fmt.Errorf("expected []byte, got %T", value)
	}
	return json.Unmarshal(bytes, p)
}

type Upstream struct {
	ID              uuid.UUID        `json:"id" gorm:"type:uuid;primaryKey;default:gen_random_uuid()"`
	GatewayID       uuid.UUID        `json:"gateway_id" gorm:"type:uuid; not null"`
	Name            string           `json:"name" gorm:"uniqueIndex:idx_gateway_upstream_name"`
	Algorithm       string           `json:"algorithm" gorm:"default:'round-robin'"`
	Targets         Targets          `json:"targets" gorm:"type:jsonb"`
	EmbeddingConfig *EmbeddingConfig `json:"embedding_config,omitempty" gorm:"type:jsonb"`
	HealthChecks    *HealthCheck     `json:"health_checks,omitempty" gorm:"type:jsonb"`
	Tags            domain.TagsJSON  `json:"tags,omitempty" gorm:"type:jsonb"`
	Websocket       *WebsocketConfig `json:"websocket_config,omitempty" gorm:"type:jsonb"`
	Proxy           *Proxy           `json:"proxy,omitempty" gorm:"type:jsonb"`
	CreatedAt       time.Time        `json:"created_at"`
	UpdatedAt       time.Time        `json:"updated_at"`
}

type WebsocketConfig struct {
	EnableDirectCommunication bool   `json:"enable_direct_communication"`
	ReturnErrorDetails        bool   `json:"return_error_details"`
	PingPeriod                string `json:"ping_period"`
	PongWait                  string `json:"pong_wait"`
	HandshakeTimeout          string `json:"handshake_timeout"`
	ReadBufferSize            int    `json:"read_buffer_size"`
	WriteBufferSize           int    `json:"write_buffer_size"`
}

func (e WebsocketConfig) Value() (driver.Value, error) {
	return json.Marshal(e)
}

func (e *WebsocketConfig) Scan(value interface{}) error {
	if value == nil {
		return nil
	}
	bytes, ok := value.([]byte)
	if !ok {
		return fmt.Errorf("expected []byte, got %T", value)
	}
	return json.Unmarshal(bytes, e)
}

func (t *Target) Validate() error {
	if t.Weight < 0 {
		return fmt.Errorf("weight cannot be negative")
	}

	if t.Provider != "" {
		if t.Host != "" || t.Port != 0 {
			return fmt.Errorf("provider-type target cannot have host/port configuration")
		}
		var emptyCredentials domain.CredentialsJSON
		if t.Credentials == emptyCredentials {
			return fmt.Errorf("provider-type target requires credentials")
		}
		if len(t.Models) == 0 {
			return fmt.Errorf("provider-type target requires at least one model")
		}
		if t.DefaultModel == "" {
			return fmt.Errorf("provider-type target requires a default model")
		}
		if t.DefaultModel != "" && !slices.Contains(t.Models, t.DefaultModel) {
			return fmt.Errorf("default model must be in the models list")
		}
	} else if t.Host != "" {
		if t.Port <= 0 || t.Port > 65535 {
			return fmt.Errorf("invalid port number")
		}
		if t.Protocol != "http" && t.Protocol != "https" {
			return fmt.Errorf("invalid protocol: must be http or https")
		}
	} else {
		return fmt.Errorf("target must specify either provider or host")
	}

	return nil
}

func (u *Upstream) BeforeCreate(tx *gorm.DB) error {
	if u.ID == uuid.Nil {
		u.ID = uuid.New()
	}
	for i := range u.Targets {
		if u.Targets[i].ID == "" {
			u.Targets[i].ID = fmt.Sprintf("%s-%s-%d", u.ID, u.Targets[i].Provider, i)
		}
	}
	return u.Validate()
}

func (u *Upstream) BeforeUpdate(tx *gorm.DB) error {
	u.UpdatedAt = time.Now()
	return u.Validate()
}

func (u *Upstream) Validate() error {
	if u.Name == "" {
		return fmt.Errorf("name is required")
	}

	if len(u.Targets) == 0 {
		return fmt.Errorf("at least one target is required")
	}

	validAlgorithms := map[string]bool{
		"round-robin":          true,
		"weighted-round-robin": true,
		"least-conn":           true,
		"semantic":             true,
	}

	if !validAlgorithms[u.Algorithm] {
		return fmt.Errorf("invalid algorithm: %s", u.Algorithm)
	}

	if u.Algorithm == "semantic" {
		if u.EmbeddingConfig == nil {
			return fmt.Errorf("embedding configuration is required when algorithm is semantic")
		}
		if u.EmbeddingConfig.Model == "" {
			return fmt.Errorf("embedding model is required when algorithm is semantic")
		}
		if u.EmbeddingConfig.Credentials.HeaderName == "" {
			return fmt.Errorf("embedding credentials header_name is required when algorithm is semantic")
		}
		if u.EmbeddingConfig.Credentials.HeaderValue == "" {
			return fmt.Errorf("embedding credentials header_value is required when algorithm is semantic")
		}
	}

	for i, target := range u.Targets {
		if err := target.Validate(); err != nil {
			return fmt.Errorf("invalid target %d: %w", i, err)
		}

		if u.Algorithm == "semantic" {
			if target.Description == "" {
				return fmt.Errorf("target %d: description is required when algorithm is semantic", i)
			}
		}
	}

	if u.HealthChecks != nil {
		if err := u.HealthChecks.Validate(); err != nil {
			return fmt.Errorf("invalid health check configuration: %w", err)
		}
	}

	return nil
}

func (u *Upstream) TableName() string {
	return "public.upstreams"
}
