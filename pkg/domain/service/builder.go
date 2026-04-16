package service

import (
	"fmt"
	"time"

	"github.com/NeuralTrust/TrustGate/pkg/domain"
	"github.com/google/uuid"
)

type CreateParams struct {
	GatewayID   uuid.UUID
	Name        string
	Type        string
	Description string
	UpstreamID  uuid.UUID
	Tags        domain.TagsJSON
	Host        string
	Protocol    string
	Path        string
	Port        int
	Headers     domain.HeadersJSON
	Credentials domain.CredentialsJSON
}

func New(params CreateParams) (*Service, error) {
	id, err := uuid.NewV7()
	if err != nil {
		return nil, fmt.Errorf("failed to generate UUID: %w", err)
	}
	now := time.Now()
	return &Service{
		ID:          id,
		GatewayID:   params.GatewayID,
		Name:        params.Name,
		Type:        params.Type,
		Description: params.Description,
		Tags:        params.Tags,
		UpstreamID:  params.UpstreamID,
		Host:        params.Host,
		Port:        params.Port,
		Protocol:    params.Protocol,
		Path:        params.Path,
		Headers:     params.Headers,
		Credentials: params.Credentials,
		CreatedAt:   now,
		UpdatedAt:   now,
	}, nil
}
