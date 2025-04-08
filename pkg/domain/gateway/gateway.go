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
	ID              uuid.UUID              `json:"id" gorm:"type:uuid;primaryKey;default:gen_random_uuid()"`
	Name            string                 `json:"name"`
	Subdomain       string                 `json:"subdomain" gorm:"uniqueIndex"`
	Status          string                 `json:"status"`
	Telemetry       *telemetry.Telemetry   `json:"telemetry" gorm:"type:jsonb"`
	RequiredPlugins domain.PluginChainJSON `json:"required_plugins" gorm:"type:jsonb"`
	CreatedAt       time.Time              `json:"created_at"`
	UpdatedAt       time.Time              `json:"updated_at"`
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
				g.RequiredPlugins[i].ID = fmt.Sprintf("%s-gateway-%s-%d", g.ID, g.RequiredPlugins[i].Name, i)
			}
		}
	}

	return g.Validate()
}

func (g *Gateway) BeforeUpdate(tx *gorm.DB) error {
	g.UpdatedAt = time.Now()

	if g.RequiredPlugins != nil {
		for i := range g.RequiredPlugins {
			if g.RequiredPlugins[i].ID == "" {
				g.RequiredPlugins[i].ID = fmt.Sprintf("%s-gateway-%s-%d", g.ID, g.RequiredPlugins[i].Name, i)
			}
		}
	}

	return g.Validate()
}

func (g *Gateway) Validate() error {
	if g.Name == "" {
		return fmt.Errorf("name is required")
	}

	if g.Subdomain == "" {
		return fmt.Errorf("subdomain is required")
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
	return "public.gateways"
}

// Include all Gateway-related methods
