package gateway

import (
	"time"

	"github.com/NeuralTrust/TrustGate/pkg/models"
	"github.com/NeuralTrust/TrustGate/pkg/types"
)

type OutputTransformer struct {
}

func NewOutputTransformer() *OutputTransformer {
	return &OutputTransformer{}
}

func (ot OutputTransformer) Transform(dbGateway *models.Gateway) (*types.Gateway, error) {
	if dbGateway.RequiredPlugins == nil {
		dbGateway.RequiredPlugins = []types.PluginConfig{}
	}
	return &types.Gateway{
		ID:              dbGateway.ID,
		Name:            dbGateway.Name,
		Subdomain:       dbGateway.Subdomain,
		Status:          dbGateway.Status,
		RequiredPlugins: dbGateway.RequiredPlugins,
		CreatedAt:       dbGateway.CreatedAt.Format(time.RFC3339),
		UpdatedAt:       dbGateway.UpdatedAt.Format(time.RFC3339),
	}, nil
}
