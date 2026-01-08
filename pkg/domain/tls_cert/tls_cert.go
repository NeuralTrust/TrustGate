package tls_cert

import (
	"time"

	"github.com/google/uuid"
	"gorm.io/gorm"
)

// TLSCert represents a TLS certificate stored in the database
type TLSCert struct {
	ID         uuid.UUID `json:"id" gorm:"type:uuid;primaryKey;default:gen_random_uuid()"`
	GatewayID  uuid.UUID `json:"gateway_id" gorm:"type:uuid;not null;index"`
	Host       string    `json:"host" gorm:"type:text;not null"`
	CACert     string    `json:"ca_cert" gorm:"type:text"`
	ClientCert string    `json:"client_cert" gorm:"type:text"`
	ClientKey  string    `json:"client_key" gorm:"type:text"`
	CreatedAt  time.Time `json:"created_at"`
	UpdatedAt  time.Time `json:"updated_at"`
}

func (c *TLSCert) BeforeCreate(tx *gorm.DB) error {
	if c.ID == uuid.Nil {
		c.ID = uuid.New()
	}
	now := time.Now()
	c.CreatedAt = now
	c.UpdatedAt = now
	return nil
}

func (c *TLSCert) BeforeUpdate(tx *gorm.DB) error {
	c.UpdatedAt = time.Now()
	return nil
}

func (c *TLSCert) TableName() string {
	return "tls_certs"
}


