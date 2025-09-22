package request

import (
	"fmt"
	"strings"
	"time"
)

const gateway = "gateway"

type CreateAPIKeyRequest struct {
	Name        string     `json:"name" binding:"required"`
	Policies    []string   `json:"policies,omitempty"`
	SubjectType string     `json:"subject_type"`
	SubjectID   string     `json:"subject,omitempty"`
	ExpiresAt   *time.Time `json:"expires_at,omitempty"`
}

func (r *CreateAPIKeyRequest) Validate() error {
	if strings.TrimSpace(r.Name) == "" {
		return fmt.Errorf("name is required")
	}

	// Set default value for SubjectType if empty
	if strings.TrimSpace(r.SubjectType) == "" {
		r.SubjectType = gateway
	}

	if r.SubjectType == gateway && strings.TrimSpace(r.SubjectID) == "" {
		return fmt.Errorf("subject_id cannot be empty when subject_type is 'gateway'")
	}

	if r.ExpiresAt != nil && r.ExpiresAt.Before(time.Now()) {
		return fmt.Errorf("expires_at must be greater than current time")
	}

	return nil
}
