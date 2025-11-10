package request

import (
	"time"

	"github.com/NeuralTrust/TrustGate/pkg/types"
)

type ServiceRequest struct {
	ID          string   `json:"id"`
	GatewayID   string   `json:"gateway_id"`
	Name        string   `json:"name"`
	Type        string   `json:"type"`
	Description string   `json:"description"`
	Tags        []string `json:"tags,omitempty"`

	UpstreamID string `json:"upstream_id,omitempty"`

	Host        string            `json:"host,omitempty"`
	Port        int               `json:"port,omitempty"`
	Protocol    string            `json:"protocol,omitempty"`
	Path        string            `json:"path,omitempty"`
	Headers     map[string]string `json:"headers,omitempty"`
	Credentials types.Credentials `json:"credentials,omitempty"`

	Retries   int       `json:"retries,omitempty"`
	CreatedAt time.Time `json:"CreatedAt"`
	UpdatedAt time.Time `json:"UpdatedAt"`
}

