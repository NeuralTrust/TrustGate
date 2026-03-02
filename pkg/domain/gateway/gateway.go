package gateway

import (
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
	ClientTLSConfig domain.ClientTLSConfig `json:"client_tls,omitempty" gorm:"type:jsonb"`
	CreatedAt       time.Time              `json:"created_at"`
	UpdatedAt       time.Time                  `json:"updated_at"`
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

	return nil
}

func (g *Gateway) TableName() string {
	return "gateways"
}
