package auth

import (
	"context"
	"fmt"

	domain "github.com/NeuralTrust/AgentGateway/pkg/domain/auth"
)

func ensureNoOAuth2Conflict(ctx context.Context, repo domain.Repository, candidate *domain.Auth) error {
	if candidate.Type != domain.TypeOAuth2 || !candidate.Enabled || candidate.Config.OAuth2 == nil {
		return nil
	}
	existing, err := repo.FindEnabledByTypes(ctx, []domain.Type{domain.TypeOAuth2})
	if err != nil {
		return fmt.Errorf("auth: check oauth2 conflicts: %w", err)
	}
	for _, a := range existing {
		if a.ID == candidate.ID || a.Config.OAuth2 == nil {
			continue
		}
		if candidate.Config.OAuth2.ConflictsWith(a.Config.OAuth2) {
			return fmt.Errorf("%w: conflicts with %q (%s); scope it with a distinct audience or disable the other entry",
				domain.ErrDuplicateOAuth2, a.Name, a.ID)
		}
	}
	return nil
}
