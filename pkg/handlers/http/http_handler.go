package http

import "github.com/gofiber/fiber/v2"

type Handler interface {
	Handle(ctx *fiber.Ctx) error
}

type HandlerTransport interface {
	GetTransport() HandlerTransport
}

type HandlerTransportDTO struct {
	// ProxyConfig
	ForwardedHandler Handler

	// Gateway
	CreateGatewayHandler Handler
	ListGatewayHandler   Handler
	GetGatewayHandler    Handler
	UpdateGatewayHandler Handler
	DeleteGatewayHandler Handler

	// Upstream
	CreateUpstreamHandler Handler
	ListUpstreamHandler   Handler
	GetUpstreamHandler    Handler
	UpdateUpstreamHandler Handler
	DeleteUpstreamHandler Handler

	// Service
	CreateServiceHandler Handler
	ListServicesHandler  Handler
	GetServiceHandler    Handler
	UpdateServiceHandler Handler
	DeleteServiceHandler Handler

	// Rule
	CreateRuleHandler Handler
	ListRulesHandler  Handler
	UpdateRuleHandler Handler
	DeleteRuleHandler Handler

	// APIKey
	CreateAPIKeyHandler      Handler
	ListAPIKeysHandler       Handler
	ListAPIKeysPublicHandler Handler
	GetAPIKeyHandler         Handler
	DeleteAPIKeyHandler      Handler

	// Version
	GetVersionHandler Handler

	// Plugins
	ListPluginsHandler   Handler
	UpdatePluginsHandler Handler

	// Cache
	InvalidateCacheHandler Handler
}

func (t *HandlerTransportDTO) GetTransport() HandlerTransport {
	return t
}
