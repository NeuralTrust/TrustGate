package forwarding_rule

import (
	"fmt"
	"time"

	"github.com/NeuralTrust/TrustGate/pkg/domain"
	"github.com/google/uuid"
	"gorm.io/gorm"
)

type ForwardingRule struct {
	ID            string                 `gorm:"primaryKey"`
	GatewayID     string                 `gorm:"not null"`
	ServiceID     string                 `gorm:"not null"`
	Path          string                 `gorm:"not null"`
	Methods       domain.MethodsJSON     `gorm:"type:jsonb"`
	Headers       domain.HeadersJSON     `gorm:"type:jsonb"`
	StripPath     bool                   `gorm:"default:false"`
	PreserveHost  bool                   `gorm:"default:false"`
	PluginChain   domain.PluginChainJSON `gorm:"type:jsonb"`
	Active        bool                   `gorm:"default:true"`
	Public        bool                   `gorm:"default:false"`
	RetryAttempts int                    `gorm:"default:1"`
	CreatedAt     time.Time
	UpdatedAt     time.Time
}

// Validate checks if the rule is valid
func (r *ForwardingRule) Validate() error {
	if r.Path == "" {
		return fmt.Errorf("path is required")
	}

	if r.ServiceID == "" {
		return fmt.Errorf("service_id is required")
	}

	if len(r.Methods) == 0 {
		return fmt.Errorf("at least one HTTP method is required")
	}

	validMethods := map[string]bool{
		"GET": true, "POST": true, "PUT": true, "DELETE": true,
		"PATCH": true, "HEAD": true, "OPTIONS": true,
	}

	for _, method := range r.Methods {
		if !validMethods[method] {
			return fmt.Errorf("invalid HTTP method: %s", method)
		}
	}

	return nil
}

// BeforeCreate is called before inserting a new forwarding rule into the database
func (r *ForwardingRule) BeforeCreate(tx *gorm.DB) error {
	// Generate UUID if not set
	if r.ID == "" {
		r.ID = uuid.New().String()
	}

	// Set timestamps
	now := time.Now()
	r.CreatedAt = now
	r.UpdatedAt = now

	// Generate unique IDs for plugins in the chain
	if r.PluginChain != nil {
		for i := range r.PluginChain {
			if r.PluginChain[i].ID == "" { // Only generate if ID is not already set
				r.PluginChain[i].ID = fmt.Sprintf("%s-%s-%d", r.GatewayID, r.PluginChain[i].Name, i)
			}
		}
	}

	// Validate the rule
	return r.Validate()
}

// BeforeUpdate is called before updating a forwarding rule in the database
func (r *ForwardingRule) BeforeUpdate(tx *gorm.DB) error {
	// Update timestamp
	r.UpdatedAt = time.Now()

	// Generate unique IDs for any new plugins in the chain
	if r.PluginChain != nil {
		for i := range r.PluginChain {
			if r.PluginChain[i].ID == "" { // Only generate if ID is not already set
				r.PluginChain[i].ID = fmt.Sprintf("%s-%s-%d", r.GatewayID, r.PluginChain[i].Name, i)
			}
		}
	}

	// Validate the rule
	return r.Validate()
}

func (r *ForwardingRule) TableName() string {
	return "public.forwarding_rules"
}
