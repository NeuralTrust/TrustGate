package session

import (
	"time"

	"github.com/google/uuid"
)

type Session struct {
	ID        string    `json:"id"`
	GatewayID uuid.UUID `json:"gateway_id"`
	Content   string    `json:"content"`
	CreatedAt time.Time `json:"created_at"`
	ExpiresAt time.Time `json:"expires_at"`
}

func NewSession(id string, gatewayID uuid.UUID, content string, ttl time.Duration) *Session {
	now := time.Now()
	return &Session{
		ID:        id,
		GatewayID: gatewayID,
		Content:   content,
		CreatedAt: now,
		ExpiresAt: now.Add(ttl),
	}
}
