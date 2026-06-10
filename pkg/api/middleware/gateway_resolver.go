package middleware

import (
	"errors"
	"fmt"
	"net"
	"strconv"
	"strings"

	appauth "github.com/NeuralTrust/AgentGateway/pkg/app/auth"
	appgateway "github.com/NeuralTrust/AgentGateway/pkg/app/gateway"
	commonerrors "github.com/NeuralTrust/AgentGateway/pkg/common/errors"
	gatewaydomain "github.com/NeuralTrust/AgentGateway/pkg/domain/gateway"
	"github.com/gofiber/fiber/v2"
)

const cloudGatewayBaseDomain = "gw.neuraltrust.ai"

type GatewayResolver interface {
	Resolve(c *fiber.Ctx) (*gatewaydomain.Gateway, error)
}

type SubdomainGatewayResolver struct {
	finder     appgateway.Finder
	baseDomain string
}

func NewSubdomainGatewayResolver(finder appgateway.Finder) GatewayResolver {
	return &SubdomainGatewayResolver{
		finder:     finder,
		baseDomain: cloudGatewayBaseDomain,
	}
}

func (r *SubdomainGatewayResolver) Resolve(c *fiber.Ctx) (*gatewaydomain.Gateway, error) {
	slug, err := parseGatewaySlugFromHost(string(c.Request().Host()), r.baseDomain)
	if err != nil {
		return nil, err
	}
	gw, err := r.finder.FindBySlug(c.UserContext(), slug)
	if err != nil {
		if errors.Is(err, commonerrors.ErrNotFound) {
			return nil, fmt.Errorf("%w: gateway host is unknown", appauth.ErrInvalidAuthRequest)
		}
		return nil, fmt.Errorf("resolve gateway by slug: %w", err)
	}
	return gw, nil
}

func parseGatewaySlugFromHost(rawHost, baseDomain string) (string, error) {
	host, err := normalizeHost(rawHost)
	if err != nil {
		return "", err
	}
	baseDomain = strings.Trim(strings.ToLower(strings.TrimSpace(baseDomain)), ".")
	suffix := "." + baseDomain
	if !strings.HasSuffix(host, suffix) {
		return "", fmt.Errorf("%w: host must match {slug}.%s", appauth.ErrInvalidAuthRequest, baseDomain)
	}
	slug := strings.TrimSuffix(host, suffix)
	if slug == "" || strings.Contains(slug, ".") {
		return "", fmt.Errorf("%w: host must contain exactly one gateway slug label", appauth.ErrInvalidAuthRequest)
	}
	slug = gatewaydomain.NormalizeSlug(slug)
	if !gatewaydomain.IsValidSlug(slug) {
		return "", fmt.Errorf("%w: host contains an invalid gateway slug", appauth.ErrInvalidAuthRequest)
	}
	return slug, nil
}

func normalizeHost(rawHost string) (string, error) {
	rawHost = strings.TrimSpace(rawHost)
	if rawHost == "" {
		return "", fmt.Errorf("%w: host is required", appauth.ErrInvalidAuthRequest)
	}
	host := rawHost
	if strings.Contains(rawHost, ":") {
		if strings.Count(rawHost, ":") != 1 {
			return "", fmt.Errorf("%w: host is malformed", appauth.ErrInvalidAuthRequest)
		}
		withoutPort, port, err := net.SplitHostPort(rawHost)
		if err != nil {
			return "", fmt.Errorf("%w: host port is malformed", appauth.ErrInvalidAuthRequest)
		}
		portNumber, err := strconv.Atoi(port)
		if err != nil || portNumber < 1 || portNumber > 65535 {
			return "", fmt.Errorf("%w: host port is malformed", appauth.ErrInvalidAuthRequest)
		}
		host = withoutPort
	}
	host = strings.Trim(strings.ToLower(host), ".")
	if host == "" {
		return "", fmt.Errorf("%w: host is required", appauth.ErrInvalidAuthRequest)
	}
	return host, nil
}
