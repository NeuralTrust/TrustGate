package service

import (
	"fmt"
	"time"

	"github.com/NeuralTrust/TrustGate/pkg/domain"
	"github.com/NeuralTrust/TrustGate/pkg/domain/upstream"
	"github.com/google/uuid"
	"gorm.io/gorm"
)

const (
	TypeEndpoint = "endpoint"
	TypeUpstream = "upstream"
)

var ErrServiceIsBeingUsed = fmt.Errorf("service is being used by a forwarding rule")

type Service struct {
	ID          uuid.UUID       `json:"id" gorm:"type:uuid;primaryKey;default:gen_random_uuid()"`
	GatewayID   uuid.UUID       `json:"gateway_id" gorm:"type:uuid;not null"`
	Name        string          `json:"name" gorm:"index:idx_gateway_service_name"`
	Type        string          `json:"type" gorm:"not null"` // "upstream" or "endpoint"
	Description string          `json:"description"`
	Tags        domain.TagsJSON `json:"tags,omitempty" gorm:"type:jsonb"`

	// Upstream configuration (used when type is "upstream")
	UpstreamID uuid.UUID          `json:"upstream_id,omitempty" gorm:"type:uuid"`
	Upstream   *upstream.Upstream `json:"upstream,omitempty" gorm:"foreignKey:UpstreamID;references:ID"`

	// Direct configuration (used when type is "direct")
	Host        string                 `json:"host,omitempty"`
	Port        int                    `json:"port,omitempty"`
	Protocol    string                 `json:"protocol,omitempty"`
	Path        string                 `json:"path,omitempty"`
	Headers     domain.HeadersJSON     `json:"headers,omitempty" gorm:"type:jsonb"`
	Credentials domain.CredentialsJSON `json:"credentials,omitempty" gorm:"type:jsonb"`

	// Common settings
	Stream bool `json:"stream,omitempty"`

	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}

func (s *Service) BeforeCreate(tx *gorm.DB) error {
	if s.ID == uuid.Nil {
		s.ID = uuid.New()
	}
	return s.Validate()
}

func (s *Service) BeforeUpdate(tx *gorm.DB) error {
	s.UpdatedAt = time.Now()
	return s.Validate()
}

func (s *Service) Validate() error {
	if s.Name == "" {
		return fmt.Errorf("name is required")
	}

	validTypes := map[string]bool{
		TypeUpstream: true,
		TypeEndpoint: true,
	}
	if !validTypes[s.Type] {
		return fmt.Errorf("invalid service type: %s", s.Type)
	}

	// Must have either upstream or direct host configuration
	if s.UpstreamID == uuid.Nil {
		if s.Host == "" {
			return fmt.Errorf("either upstream_id or host must be specified")
		}
		if s.Port <= 0 || s.Port > 65535 {
			return fmt.Errorf("invalid port number")
		}
		if s.Protocol != "http" && s.Protocol != "https" {
			return fmt.Errorf("invalid protocol: must be http or https")
		}
	} else {
		// When using upstream, host-specific fields should be empty
		if s.Host != "" || s.Port != 0 {
			return fmt.Errorf("cannot specify host configuration when using upstream")
		}
	}

	return nil
}

func (s *Service) TableName() string {
	return "services"
}
