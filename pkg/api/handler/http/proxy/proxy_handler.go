package proxy

import (
	"errors"
	"net/textproto"
	"net/url"

	"github.com/NeuralTrust/AgentGateway/pkg/api/handler/http/helpers"
	appproxy "github.com/NeuralTrust/AgentGateway/pkg/app/proxy"
	commonerrors "github.com/NeuralTrust/AgentGateway/pkg/common/errors"
	infracontext "github.com/NeuralTrust/AgentGateway/pkg/infra/context"
	"github.com/gofiber/fiber/v2"
	"github.com/google/uuid"
)

// Routing headers used to resolve the gateway and backend on the proxy plane.
//
// TODO(B.2/B.8): replace header-based routing with real proxy auth + gateway
// resolution (API key / host based) once those sub-issues land.
const (
	HeaderGatewayID = "X-Gateway-Id"
	HeaderBackendID = "X-Backend-Id"
)

var errInvalidRouting = errors.New("missing or invalid routing headers")

// hopByHopHeaders are connection-scoped headers that must not be relayed from
// the upstream response back to the client.
var hopByHopHeaders = map[string]struct{}{
	"Connection":          {},
	"Keep-Alive":          {},
	"Proxy-Authenticate":  {},
	"Proxy-Authorization": {},
	"Te":                  {},
	"Trailer":             {},
	"Transfer-Encoding":   {},
	"Upgrade":             {},
	"Content-Length":      {},
}

// ProxyHandler is the AI Gateway data-plane entry point. It builds the proxy
// RequestContext from the inbound request, resolves the target gateway and
// backend, and delegates the forward to the application layer.
type ProxyHandler struct {
	forwarder appproxy.Forwarder
}

func NewProxyHandler(forwarder appproxy.Forwarder) *ProxyHandler {
	return &ProxyHandler{forwarder: forwarder}
}

func (h *ProxyHandler) Handle(c *fiber.Ctx) error {
	gatewayID, backendID, err := resolveRouting(c)
	if err != nil {
		return writeProxyError(c, err)
	}

	result, err := h.forwarder.Forward(c.UserContext(), appproxy.ForwardInput{
		GatewayID: gatewayID,
		BackendID: backendID,
		Request:   buildRequestContext(c, gatewayID, backendID),
	})
	if err != nil {
		return writeProxyError(c, err)
	}

	for name, values := range result.Headers {
		if _, skip := hopByHopHeaders[textproto.CanonicalMIMEHeaderKey(name)]; skip {
			continue
		}
		for _, v := range values {
			c.Response().Header.Add(name, v)
		}
	}
	return c.Status(result.StatusCode).Send(result.Body)
}

// resolveRouting extracts the gateway and backend identifiers from the inbound
// request. This is a deliberate seam: real proxy auth/routing arrives with
// B.2/B.8.
func resolveRouting(c *fiber.Ctx) (gatewayID, backendID uuid.UUID, err error) {
	gatewayID, err = uuid.Parse(c.Get(HeaderGatewayID))
	if err != nil {
		return uuid.Nil, uuid.Nil, errInvalidRouting
	}
	backendID, err = uuid.Parse(c.Get(HeaderBackendID))
	if err != nil {
		return uuid.Nil, uuid.Nil, errInvalidRouting
	}
	return gatewayID, backendID, nil
}

func buildRequestContext(c *fiber.Ctx, gatewayID, backendID uuid.UUID) *infracontext.RequestContext {
	headers := make(map[string][]string)
	c.Request().Header.VisitAll(func(key, value []byte) {
		name := string(key)
		headers[name] = append(headers[name], string(value))
	})

	query := url.Values{}
	c.Context().QueryArgs().VisitAll(func(key, value []byte) {
		query.Add(string(key), string(value))
	})

	return &infracontext.RequestContext{
		Context:   c.UserContext(),
		GatewayID: gatewayID.String(),
		BackendID: backendID.String(),
		Headers:   headers,
		Method:    c.Method(),
		Path:      c.Path(),
		Query:     query,
		Body:      c.Body(),
		IP:        c.IP(),
	}
}

func writeProxyError(c *fiber.Ctx, err error) error {
	status, body := mapProxyError(err)
	return c.Status(status).JSON(body)
}

func mapProxyError(err error) (int, helpers.ErrorBody) {
	switch {
	case errors.Is(err, errInvalidRouting):
		return fiber.StatusBadRequest, helpers.ErrorBody{Error: "invalid_routing", Message: err.Error()}
	case errors.Is(err, commonerrors.ErrNotFound),
		errors.Is(err, appproxy.ErrBackendGatewayMismatch):
		return fiber.StatusNotFound, helpers.ErrorBody{Error: "not_found"}
	case errors.Is(err, appproxy.ErrNoTargetAvailable):
		return fiber.StatusServiceUnavailable, helpers.ErrorBody{Error: "no_target_available", Message: err.Error()}
	case errors.Is(err, appproxy.ErrStreamingNotImplemented),
		errors.Is(err, appproxy.ErrProviderNotImplemented):
		return fiber.StatusNotImplemented, helpers.ErrorBody{Error: "not_implemented", Message: err.Error()}
	default:
		return fiber.StatusBadGateway, helpers.ErrorBody{Error: "upstream_error"}
	}
}
