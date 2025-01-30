package models

import (
	"fmt"
	"time"

	"github.com/google/uuid"
	"gorm.io/gorm"
)

type Gateway struct {
	ID              string          `json:"id" gorm:"primaryKey"`
	Name            string          `json:"name"`
	Subdomain       string          `json:"subdomain" gorm:"uniqueIndex"`
	Status          string          `json:"status"`
	RequiredPlugins PluginChainJSON `json:"required_plugins" gorm:"type:jsonb"`
	CreatedAt       time.Time       `json:"created_at"`
	UpdatedAt       time.Time       `json:"updated_at"`
}

func (g *Gateway) BeforeCreate(tx *gorm.DB) error {
	if g.ID == "" {
		g.ID = uuid.New().String()
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
