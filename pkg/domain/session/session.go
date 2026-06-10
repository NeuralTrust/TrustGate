package session

import "time"

type Session struct {
	ID         string    `json:"id"`
	GatewayID  string    `json:"gateway_id"`
	LastTurnID string    `json:"last_turn_id,omitempty"`
	Provider   string    `json:"provider,omitempty"`
	Model      string    `json:"model,omitempty"`
	CreatedAt  time.Time `json:"created_at"`
	UpdatedAt  time.Time `json:"updated_at"`
	ExpiresAt  time.Time `json:"expires_at"`
}
