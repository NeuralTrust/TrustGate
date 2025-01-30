package models

import (
	"database/sql/driver"
	"encoding/json"
	"fmt"
	"slices"
	"time"

	"github.com/google/uuid"
	"gorm.io/gorm"
)

type UpstreamTarget struct {
	ID           string          `json:"id" gorm:"primaryKey"`
	Weight       int             `json:"weight,omitempty"`
	Priority     int             `json:"priority,omitempty"`
	Tags         TagsJSON        `json:"tags,omitempty" gorm:"type:jsonb"`
	Headers      HeadersJSON     `json:"headers,omitempty" gorm:"type:jsonb"`
	Path         string          `json:"path,omitempty"`
	Host         string          `json:"host,omitempty"`
	Port         int             `json:"port,omitempty"`
	Protocol     string          `json:"protocol,omitempty"`
	Provider     string          `json:"provider,omitempty"`
	Models       ModelsJSON      `json:"models,omitempty" gorm:"type:jsonb"`
	DefaultModel string          `json:"default_model,omitempty"`
	Credentials  CredentialsJSON `json:"credentials,omitempty" gorm:"type:jsonb"`
}

// Add this type for Models array
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

// Add Value() method for UpstreamTargets
type UpstreamTargets []UpstreamTarget

func (t UpstreamTargets) Value() (driver.Value, error) {
	if len(t) == 0 {
		return []byte("[]"), nil
	}
	return json.Marshal(t)
}

func (t *UpstreamTargets) Scan(value interface{}) error {
	if value == nil {
		*t = make(UpstreamTargets, 0)
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
		*t = make(UpstreamTargets, 1)
		return json.Unmarshal(bytes, &(*t)[0])
	default:
		return fmt.Errorf("unexpected JSON type: %T", v)
	}
}

type Upstream struct {
	ID           string          `json:"id" gorm:"primaryKey"`
	GatewayID    string          `json:"gateway_id" gorm:"not null"`
	Name         string          `json:"name" gorm:"uniqueIndex:idx_gateway_upstream_name"`
	Algorithm    string          `json:"algorithm" gorm:"default:'round-robin'"`
	Targets      UpstreamTargets `json:"targets" gorm:"type:jsonb"`
	HealthChecks *HealthCheck    `json:"health_checks,omitempty" gorm:"type:jsonb"`
	Tags         TagsJSON        `json:"tags,omitempty" gorm:"type:jsonb"`
	Services     []Service       `json:"-" gorm:"foreignKey:UpstreamID"`
	CreatedAt    time.Time
	UpdatedAt    time.Time
}

func (t *UpstreamTarget) Validate() error {
	if t.Weight < 0 {
		return fmt.Errorf("weight cannot be negative")
	}

	if t.Provider != "" {
		if t.Host != "" || t.Port != 0 {
			return fmt.Errorf("provider-type target cannot have host/port configuration")
		}
		var emptyCredentials CredentialsJSON
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
	if u.ID == "" {
		u.ID = uuid.New().String()
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
	}

	if !validAlgorithms[u.Algorithm] {
		return fmt.Errorf("invalid algorithm: %s", u.Algorithm)
	}

	for i, target := range u.Targets {
		if err := target.Validate(); err != nil {
			return fmt.Errorf("invalid target %d: %w", i, err)
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
