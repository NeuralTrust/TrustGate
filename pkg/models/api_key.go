package models

import (
	"time"
)

// APIKey represents an API key in the database
type APIKey struct {
	ID        string    `json:"id" gorm:"type:uuid;primary_key;default:gen_random_uuid()"`
	Key       string    `json:"key" gorm:"index"`
	Name      string    `json:"name"`
	Active    bool      `json:"active"`
	GatewayID string    `json:"gateway_id" gorm:"type:varchar(255);index"` // ID of either Gateway or ConsumerGroup
	ExpiresAt time.Time `json:"expires_at"`
	CreatedAt time.Time `json:"created_at"`
}

func (APIKey) TableName() string {
	return "public.api_keys"
}
