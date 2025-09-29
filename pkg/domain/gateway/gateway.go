package gateway

import (
	"database/sql/driver"
	"encoding/json"
	"fmt"
	"time"

	"github.com/NeuralTrust/TrustGate/pkg/domain"
	"github.com/NeuralTrust/TrustGate/pkg/domain/telemetry"
	"github.com/google/uuid"
	"gorm.io/gorm"
)

type Gateway struct {
	ID              uuid.UUID                  `json:"id" gorm:"type:uuid;primaryKey;default:gen_random_uuid()"`
	Name            string                     `json:"name"`
	Status          string                     `json:"status"`
	Telemetry       *telemetry.Telemetry       `json:"telemetry,omitempty" gorm:"type:jsonb"`
	RequiredPlugins domain.PluginChainJSON     `json:"required_plugins,omitempty" gorm:"type:jsonb"`
	SecurityConfig  *domain.SecurityConfigJSON `json:"security_config,omitempty" gorm:"type:jsonb"`
	ClientTLSConfig domain.ClientTLSConfig     `json:"client_tls,omitempty" gorm:"type:jsonb"`
	SessionConfig   *SessionConfig             `json:"session_config,omitempty" gorm:"type:jsonb"`
	CreatedAt       time.Time                  `json:"created_at"`
	UpdatedAt       time.Time                  `json:"updated_at"`
}

type SessionConfig struct {
	Enabled       bool   `json:"enabled"`
	HeaderName    string `json:"header_name"`
	BodyParamName string `json:"body_param_name"`
	Mapping       string `json:"mapping_field"`
	TTL           int    `json:"ttl"`
}

func (t SessionConfig) Value() (driver.Value, error) {
	return json.Marshal(t)
}

func (t *SessionConfig) Scan(value interface{}) error {
	bytes, ok := value.([]byte)
	if !ok {
		return fmt.Errorf("could not convert value %v to []byte", value)
	}
	return json.Unmarshal(bytes, t)
}

func (g *Gateway) BeforeCreate(tx *gorm.DB) error {
	if g.ID == uuid.Nil {
		g.ID = uuid.New()
	}
	now := time.Now()
	g.CreatedAt = now
	g.UpdatedAt = now
	if g.RequiredPlugins != nil {
		for i := range g.RequiredPlugins {
			if g.RequiredPlugins[i].ID == "" {
				g.RequiredPlugins[i].ID = uuid.New().String()
			}
		}
	}
	return g.Validate()
}

func (g *Gateway) BeforeUpdate(tx *gorm.DB) error {
	g.UpdatedAt = time.Now()
	return g.Validate()
}

func (g *Gateway) Validate() error {
	if g.Name == "" {
		return fmt.Errorf("name is required")
	}

	if g.Status == "" {
		g.Status = "active"
	}

	if g.RequiredPlugins != nil {
		for _, plugin := range g.RequiredPlugins {
			if plugin.Name == "" {
				return fmt.Errorf("plugin name is required")
			}
		}
	}

	if g.SessionConfig != nil && g.SessionConfig.Enabled {
		if g.SessionConfig.HeaderName == "" {
			g.SessionConfig.HeaderName = "X-TG-SESSION-ID"
		}
		if g.SessionConfig.BodyParamName == "" {
			g.SessionConfig.BodyParamName = "tg_session_id"
		}
		if g.SessionConfig.TTL <= 0 {
			g.SessionConfig.TTL = 3600
		}
	}

	return nil
}

func (g *Gateway) TableName() string {
	return "gateways"
}
