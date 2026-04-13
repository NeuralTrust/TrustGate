package helpers

import (
	"context"
	"fmt"
	"strings"

	"github.com/NeuralTrust/TrustGate/pkg/app/service"
	"github.com/NeuralTrust/TrustGate/pkg/app/upstream"
	domainService "github.com/NeuralTrust/TrustGate/pkg/domain/service"
	domainUpstream "github.com/NeuralTrust/TrustGate/pkg/domain/upstream"
	"github.com/NeuralTrust/TrustGate/pkg/types"
)

func GetUpstream(
	ctx context.Context,
	serviceFinder service.Finder,
	upstreamFinder upstream.Finder,
	rule *types.ForwardingRuleDTO,
) (*domainUpstream.Upstream, error) {
	serviceEntity, err := serviceFinder.Find(ctx, rule.GatewayID, rule.ServiceID)
	if err != nil {
		return nil, fmt.Errorf("service not found: %w", err)
	}
	if serviceEntity.Type != domainService.TypeUpstream {
		return nil, fmt.Errorf("service %s is not an upstream type", rule.ServiceID)
	}
	upstreamModel, err := upstreamFinder.Find(ctx, serviceEntity.GatewayID, serviceEntity.UpstreamID)
	if err != nil {
		return nil, fmt.Errorf("upstream not found: %w", err)
	}
	return upstreamModel, nil
}

func BuildUpstreamTargetURL(target *types.UpstreamTargetDTO, pathParams map[string]string) string {
	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("%s://%s", target.Protocol, target.Host))
	if (target.Protocol == "https" && target.Port != 443) || (target.Protocol == "http" && target.Port != 80) {
		sb.WriteString(fmt.Sprintf(":%d", target.Port))
	}

	targetPath := target.Path
	if len(pathParams) > 0 {
		targetPath = ReplacePathParams(targetPath, pathParams)
	}

	sb.WriteString(targetPath)
	return sb.String()
}
