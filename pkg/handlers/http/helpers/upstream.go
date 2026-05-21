package helpers

import (
	"context"
	"fmt"
	"strings"

	"github.com/NeuralTrust/TrustGate/pkg/app/upstream"
	domainUpstream "github.com/NeuralTrust/TrustGate/pkg/domain/upstream"
	"github.com/NeuralTrust/TrustGate/pkg/types"
	"github.com/google/uuid"
)

// GetUpstream resolves the upstream targeted by a forwarding rule. After the
// Service entity deprecation, forwarding rules carry the upstream ID directly
// and the lookup is a single call to upstream.Finder.
func GetUpstream(
	ctx context.Context,
	upstreamFinder upstream.Finder,
	rule *types.ForwardingRuleDTO,
) (*domainUpstream.Upstream, error) {
	gatewayUUID, err := uuid.Parse(rule.GatewayID)
	if err != nil {
		return nil, fmt.Errorf("invalid gateway_id %q: %w", rule.GatewayID, err)
	}
	upstreamUUID, err := uuid.Parse(rule.UpstreamID)
	if err != nil {
		return nil, fmt.Errorf("invalid upstream_id %q: %w", rule.UpstreamID, err)
	}
	upstreamModel, err := upstreamFinder.Find(ctx, gatewayUUID, upstreamUUID)
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
