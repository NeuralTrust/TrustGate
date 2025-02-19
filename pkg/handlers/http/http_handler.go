package http

import "github.com/gofiber/fiber/v2"

type Handler interface {
	Handle(ctx *fiber.Ctx) error
}

type HandlerTransport struct {
	// Proxy
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
	CreateAPIKeyHandler Handler
	ListAPIKeysHandler  Handler
	GetAPIKeyHandler    Handler
	DeleteAPIKeyHandler Handler
}
