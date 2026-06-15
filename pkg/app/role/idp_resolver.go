package role

import (
	"context"

	"github.com/NeuralTrust/AgentGateway/pkg/domain/ids"
	domain "github.com/NeuralTrust/AgentGateway/pkg/domain/role"
)

type IDPResolver interface {
	ResolveIDPRoles(ctx context.Context, roles []*domain.Role, claims map[string]any) ([]ids.RoleID, error)
}

var _ IDPResolver = (*idpResolver)(nil)

type idpResolver struct{}

func NewIDPResolver() IDPResolver {
	return idpResolver{}
}

func (r idpResolver) ResolveIDPRoles(_ context.Context, roles []*domain.Role, claims map[string]any) ([]ids.RoleID, error) {
	roleIDs := make([]ids.RoleID, 0, len(roles))
	for _, gatewayRole := range roles {
		if gatewayRole == nil || len(gatewayRole.IDPMapping) == 0 {
			continue
		}
		mapping, err := domain.ParseIDPMapping(gatewayRole.IDPMapping)
		if err != nil {
			return nil, err
		}
		if mapping.Matches(claims) {
			roleIDs = append(roleIDs, gatewayRole.ID)
		}
	}
	return roleIDs, nil
}
