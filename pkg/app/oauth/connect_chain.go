package oauth

import (
	"context"
	"errors"
	"net/url"

	appconsumer "github.com/NeuralTrust/AgentGateway/pkg/app/consumer"
	"github.com/NeuralTrust/AgentGateway/pkg/domain/ids"
	vaultdomain "github.com/NeuralTrust/AgentGateway/pkg/domain/vault"
)

func (s *connectService) ChainURL(ctx context.Context, baseURL string, gatewayID ids.GatewayID, resource, principalSub, resumeURL string) (string, error) {
	data, err := s.consumers.FindByGateway(ctx, gatewayID)
	if err != nil {
		return "", err
	}
	rc := s.chainTarget(ctx, data, gatewayID, resource, principalSub)
	if rc == nil {
		return "", nil
	}
	id, err := s.mintTicket(ctx, ConnectTicket{
		GatewayID:    gatewayID.String(),
		PrincipalSub: principalSub,
		ConsumerPath: rc.Consumer.Path,
		ResumeURL:    resumeURL,
	})
	if err != nil {
		return "", err
	}
	return baseURL + rc.Consumer.Path + "/connect?ticket=" + id, nil
}

func (s *connectService) chainTarget(ctx context.Context, data *appconsumer.Data, gatewayID ids.GatewayID, resource, principalSub string) *appconsumer.RoutableConsumer {
	if resource != "" {
		if res, err := url.Parse(resource); err == nil && res.Path != "" {
			if rc, ok := data.MatchPath(res.Path); ok {
				if s.hasUnlinked(ctx, gatewayID, rc, principalSub) {
					return rc
				}
				return nil
			}
		}
	}
	for i := range data.Consumers {
		rc := &data.Consumers[i]
		if rc.Consumer == nil || !rc.Consumer.Active {
			continue
		}
		if s.hasUnlinked(ctx, gatewayID, rc, principalSub) {
			return rc
		}
	}
	return nil
}

// hasUnlinked treats only a definitive ErrNotFound as "needs consent": a
// transient vault failure must not detour the user through a consent page
// for providers they already linked.
func (s *connectService) hasUnlinked(ctx context.Context, gatewayID ids.GatewayID, rc *appconsumer.RoutableConsumer, principalSub string) bool {
	for _, reg := range rc.Registries {
		cfg := forwardedAuth(reg)
		if cfg == nil {
			continue
		}
		if _, err := s.vault.Find(ctx, gatewayID, principalSub, cfg.Provider); errors.Is(err, vaultdomain.ErrNotFound) {
			return true
		}
	}
	return false
}
