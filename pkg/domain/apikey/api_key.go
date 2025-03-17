package apikey

import (
	"time"
)

type APIKey struct {
	ID        string     `json:"id" gorm:"type:uuid;primary_key;default:gen_random_uuid()"`
	Key       string     `json:"key" gorm:"index"`
	Name      string     `json:"name"`
	Active    bool       `json:"active"`
	GatewayID string     `json:"gateway_id" gorm:"type:varchar(255);index"`
	ExpiresAt time.Time  `json:"expires_at"`
	CreatedAt time.Time  `json:"created_at"`
	DeletedAt *time.Time `json:"deleted_at" gorm:"index"`
}

func (a APIKey) TableName() string {
	return "public.api_keys"
}

func (a APIKey) IsValid() bool {
	if !a.Active {
		return false
	}
	if time.Now().After(a.ExpiresAt) {
		return false
	}
	return true
}
