package websocket

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/NeuralTrust/TrustGate/pkg/app/service"
	"github.com/NeuralTrust/TrustGate/pkg/app/upstream"
	"github.com/NeuralTrust/TrustGate/pkg/cache"
	"github.com/NeuralTrust/TrustGate/pkg/common"
	"github.com/NeuralTrust/TrustGate/pkg/config"
	domainService "github.com/NeuralTrust/TrustGate/pkg/domain/service"
	domainUpstream "github.com/NeuralTrust/TrustGate/pkg/domain/upstream"
	"github.com/NeuralTrust/TrustGate/pkg/infra/metrics"
	infraWebsocket "github.com/NeuralTrust/TrustGate/pkg/infra/websocket"
	"github.com/NeuralTrust/TrustGate/pkg/loadbalancer"
	"github.com/NeuralTrust/TrustGate/pkg/plugins"
	"github.com/NeuralTrust/TrustGate/pkg/types"
	"github.com/gofiber/contrib/websocket"
	"github.com/gofiber/fiber/v2"
	gorilla "github.com/gorilla/websocket"
	"github.com/sirupsen/logrus"
)

type forwardedWebsocketHandler struct {
	config                *config.Config
	logger                *logrus.Logger
	upstreamFinder        upstream.Finder
	serviceFinder         service.Finder
	lbFactory             loadbalancer.Factory
	cache                 *cache.Cache
	connections           map[string]*gorilla.Conn
	connectionMutex       sync.RWMutex
	clientChannels        map[string]map[string]chan *infraWebsocket.ResponseMessage
	clientChannelMutex    sync.RWMutex
	clientConnections     map[string]*websocket.Conn
	clientConnMutex       sync.RWMutex
	clientIDMap           map[string]*gorilla.Conn
	clientIDMutex         sync.RWMutex
	clientSessionIDs      map[string]string
	clientSessionIDsMutex sync.RWMutex
	loadBalancers         sync.Map
	pluginManager         plugins.Manager
	// connWriteMutexes is used to synchronize writes to individual websocket connections
	connWriteMutexes      map[*websocket.Conn]*sync.Mutex
	connWriteMutexesMutex sync.RWMutex
}

func NewWebsocketHandler(
	config *config.Config,
	logger *logrus.Logger,
	upstreamFinder upstream.Finder,
	serviceFinder service.Finder,
	lbFactory loadbalancer.Factory,
	cache *cache.Cache,
	pluginManager plugins.Manager,
) Handler {
	return &forwardedWebsocketHandler{
		config:            config,
		logger:            logger,
		upstreamFinder:    upstreamFinder,
		serviceFinder:     serviceFinder,
		lbFactory:         lbFactory,
		cache:             cache,
		connections:       make(map[string]*gorilla.Conn),
		clientChannels:    make(map[string]map[string]chan *infraWebsocket.ResponseMessage),
		clientConnections: make(map[string]*websocket.Conn),
		clientIDMap:       make(map[string]*gorilla.Conn),
		clientSessionIDs:  make(map[string]string),
		pluginManager:     pluginManager,
		connWriteMutexes:  make(map[*websocket.Conn]*sync.Mutex),
	}
}

func (h *forwardedWebsocketHandler) Handle(c *websocket.Conn) {
	semaphoreInterface := c.Locals("ws_semaphore")
	if semaphoreInterface != nil {
		if semaphore, ok := semaphoreInterface.(*infraWebsocket.Semaphore); ok {
			defer semaphore.Release()
		}
	}

	reqCtx, ok := c.Locals(string(common.WsRequestContextContextKey)).(*types.RequestContext)
	if !ok || reqCtx == nil {
		h.logger.Error("missing request context in websocket connection")
		return
	}

	//nolint
	gatewayData, ok := c.Locals(string(common.GatewayDataContextKey)).(*types.GatewayData)
	if !ok || gatewayData == nil {
		h.logger.Error("missing gateway data in websocket connection")
		return
	}

	matchingRule, ok := c.Locals(string(common.MatchedRuleContextKey)).(*types.ForwardingRule)
	if !ok {
		h.logger.Error("failed to get matched rule from context")
		return
	}

	if matchingRule == nil {
		h.logger.WithField("path", reqCtx.Path).Error("no matching rule found for websocket connection")
		return
	}

	reqCtx.RuleID = matchingRule.ID

	metricsCollector, ok := c.Locals(string(metrics.CollectorKey)).(*metrics.Collector)
	if !ok || metricsCollector == nil {
		return
	}

	if err := h.configureRulePlugins(gatewayData.Gateway.ID, matchingRule); err != nil {
		h.logger.WithError(err).Error("failed to configure plugins")
		return
	}

	pongWait, err := time.ParseDuration(h.config.WebSocket.PongWait)
	if err != nil {
		pongWait = 45 * time.Second
	}

	pingPeriod, err := time.ParseDuration(h.config.WebSocket.PingPeriod)
	if err != nil {
		pingPeriod = 30 * time.Second
	}

	if err := c.SetReadDeadline(time.Now().Add(pongWait)); err != nil {
		h.logger.WithError(err).Error("failed to set read deadline")
		return
	}

	c.SetPongHandler(func(string) error {
		h.logger.Debug("pong received, resetting read deadline")
		return c.SetReadDeadline(time.Now().Add(pongWait))
	})

	ticker := time.NewTicker(pingPeriod)
	defer ticker.Stop()

	go func() {
		for range ticker.C {
			if err := c.WriteMessage(websocket.PingMessage, []byte{}); err != nil {
				h.logger.WithError(err).Error("failed to send ping")
				return
			}
		}
	}()

	// Send an initial message to the client to confirm the connection is established
	if err := c.WriteMessage(websocket.TextMessage, []byte("Connection established")); err != nil {
		h.logger.WithError(err).Error("failed to send initial message to client")
		return
	}

	err = h.forwardWebsocketRequest(c, reqCtx, matchingRule, pongWait, gatewayData, metricsCollector)
	if err != nil {
		h.logger.WithError(err).Error("failed to forward websocket request")
		return
	}
}

func (h *forwardedWebsocketHandler) forwardWebsocketRequest(
	clientConn *websocket.Conn,
	reqCtx *types.RequestContext,
	rule *types.ForwardingRule,
	pongWait time.Duration,
	gatewayData *types.GatewayData,
	collector *metrics.Collector,
) error {
	serviceEntity, err := h.serviceFinder.Find(reqCtx.Context, rule.GatewayID, rule.ServiceID)
	if err != nil {
		return fmt.Errorf("service not found: %w", err)
	}

	if serviceEntity.Type != domainService.TypeUpstream {
		return fmt.Errorf("only upstream services are supported for websocket connections")
	}

	upstreamModel, err := h.upstreamFinder.Find(reqCtx.Context, serviceEntity.GatewayID, serviceEntity.UpstreamID)
	if err != nil {
		return fmt.Errorf("upstream not found: %w", err)
	}

	if upstreamModel.Websocket == nil {
		return fmt.Errorf("websocket configuration not found for upstream")
	}

	lb, err := h.getOrCreateLoadBalancer(upstreamModel)
	if err != nil {
		return fmt.Errorf("failed to get load balancer: %w", err)
	}

	target, err := lb.NextTarget(reqCtx)
	if err != nil {
		return fmt.Errorf("failed to get target: %w", err)
	}

	if upstreamModel.Websocket.EnableDirectCommunication {
		return h.handleDirectCommunication(clientConn, gatewayData, reqCtx, target, lb, pongWait, collector)
	} else {
		return h.handleMultiplexing(clientConn, gatewayData, reqCtx, target, lb, collector)
	}
}

func (h *forwardedWebsocketHandler) configureRulePlugins(gatewayID string, rule *types.ForwardingRule) error {
	if rule != nil && len(rule.PluginChain) > 0 {
		if err := h.pluginManager.SetPluginChain(gatewayID, rule.PluginChain); err != nil {
			return fmt.Errorf("failed to configure rule plugins: %w", err)
		}
	}
	return nil
}

func (h *forwardedWebsocketHandler) handleDirectCommunication(
	clientConn *websocket.Conn,
	gatewayData *types.GatewayData,
	reqCtx *types.RequestContext,
	target *types.UpstreamTarget,
	lb *loadbalancer.LoadBalancer,
	pongWait time.Duration,
	collector *metrics.Collector,
) error {

	respCtx := &types.ResponseContext{
		Context:   context.Background(),
		GatewayID: gatewayData.Gateway.ID,
		Headers:   make(map[string][]string),
		Metadata:  make(map[string]interface{}),
		Target:    target,
	}

	targetConn, err := h.connectToTarget(reqCtx, target)
	if err != nil {
		h.logger.WithError(err).Warn("failed to connect to target in direct communication mode")
		lb.ReportFailure(target, err)
		errorMsg := fmt.Sprintf("Failed to connect to target: %v", err)
		if writeErr := clientConn.WriteMessage(websocket.TextMessage, []byte(errorMsg)); writeErr != nil {
			h.logger.WithError(writeErr).Error("failed to send error message to client")
		}
		return err
	}

	defer targetConn.Close()

	if err := clientConn.SetReadDeadline(time.Now().Add(pongWait)); err != nil {
		h.logger.WithError(err).Error("failed to set read deadline")
		return err
	}

	pingPeriod, err := time.ParseDuration(h.config.WebSocket.PingPeriod)
	if err != nil {
		pingPeriod = 30 * time.Second
	}
	targetPingTicker := time.NewTicker(pingPeriod)
	defer targetPingTicker.Stop()

	done := make(chan struct{})
	defer close(done)

	go func() {
		defer func() {
			select {
			case <-done:
			default:
				close(done)
			}
		}()

		for {
			_, message, err := targetConn.ReadMessage()
			if err != nil {
				lb.ReportFailure(target, err)
				h.logger.WithError(err).Error("error reading message from target")
				return
			}
			lb.ReportSuccess(target)
			// Execute PostResponse plugins
			respCtx.Body = message
			if _, err := h.pluginManager.ExecuteStage(
				context.Background(),
				types.PostResponse,
				gatewayData.Gateway.ID,
				reqCtx,
				respCtx,
				collector,
			); err != nil {
				var pluginErr *types.PluginError
				if errors.As(err, &pluginErr) {
					errorPayload := fiber.Map{
						"error":       pluginErr.Message,
						"retry_after": respCtx.Metadata["retry_after"],
					}
					if data, err := json.Marshal(errorPayload); err == nil {
						err = clientConn.WriteMessage(websocket.TextMessage, data)
						if err != nil {
							h.logger.WithError(err).Error("failed to send error message to client")
						}
					} else {
						h.logger.WithError(err).Error("failed to serialize plugin error")
					}
					continue
				}

				if respCtx.StopProcessing {
					err = clientConn.WriteMessage(websocket.TextMessage, respCtx.Body)
					if err != nil {
						h.logger.WithError(err).Error("failed to send error message to client")
					}
					continue
				}

				if !h.config.Plugins.IgnoreErrors {
					errPayload := fiber.Map{"error": "plugin execution failed"}
					if data, err := json.Marshal(errPayload); err == nil {
						err = clientConn.WriteMessage(websocket.TextMessage, data)
						if err != nil {
							h.logger.WithError(err).Error("failed to send error message to client")
						}
					}
					continue
				}
			}

			if err := clientConn.WriteMessage(websocket.TextMessage, respCtx.Body); err != nil {
				h.logger.WithError(err).Error("error writing message to client")
				return
			}
		}
	}()

	for {
		select {
		case <-done:
			return nil
		case <-targetPingTicker.C:
			// Send ping to target
			if err := targetConn.WriteMessage(websocket.PingMessage, []byte{}); err != nil {
				h.logger.WithError(err).Error("failed to send ping to target")
				lb.ReportFailure(target, err)
				return err
			}
		default:
			if err := clientConn.SetReadDeadline(time.Now().Add(pongWait)); err != nil {
				h.logger.WithError(err).Error("failed to set read deadline")
				return err
			}

			mt, message, err := clientConn.ReadMessage()
			if err != nil {
				h.logger.WithError(err).Error("error reading message from client")
				return err
			}

			reqCtx.Body = message

			// Execute PreRequest plugins
			if _, err := h.pluginManager.ExecuteStage(
				context.Background(),
				types.PreRequest,
				gatewayData.Gateway.ID,
				reqCtx,
				respCtx,
				collector,
			); err != nil {
				var pluginErr *types.PluginError
				if errors.As(err, &pluginErr) {
					// Handle plugin error
					errorPayload := fiber.Map{
						"error":       pluginErr.Message,
						"retry_after": respCtx.Metadata["retry_after"],
					}
					if data, err := json.Marshal(errorPayload); err == nil {
						err = clientConn.WriteMessage(websocket.TextMessage, data)
						if err != nil {
							h.logger.WithError(err).Error("failed to send error message to client")
						}
					} else {
						h.logger.WithError(err).Error("failed to serialize plugin error")
					}
					continue
				}

				if respCtx.StopProcessing {
					err = clientConn.WriteMessage(websocket.TextMessage, respCtx.Body)
					if err != nil {
						h.logger.WithError(err).Error("failed to send error message to client")
					}
					continue
				}

				if !h.config.Plugins.IgnoreErrors {
					errPayload := fiber.Map{"error": "plugin execution failed"}
					if data, err := json.Marshal(errPayload); err == nil {
						err = clientConn.WriteMessage(websocket.TextMessage, data)
						if err != nil {
							h.logger.WithError(err).Error("failed to send error message to client")
						}
					}
					continue
				}
			}

			if err := targetConn.WriteMessage(mt, reqCtx.Body); err != nil {
				h.logger.WithError(err).Error("error writing message to target")
				return err
			}
		}
	}
}

func (h *forwardedWebsocketHandler) handleMultiplexing(
	clientConn *websocket.Conn,
	gatewayData *types.GatewayData,
	reqCtx *types.RequestContext,
	target *types.UpstreamTarget,
	lb *loadbalancer.LoadBalancer,
	collector *metrics.Collector,
) error {

	targetKey := fmt.Sprintf("%s://%s:%d%s", target.Protocol, target.Host, target.Port, target.Path)
	clientID := fmt.Sprintf("%p", clientConn)

	done := make(chan struct{})
	defer close(done)

	// Extract session ID from headers
	var sessionID string
	if sessionIDHeaders, ok := reqCtx.Headers["Session-Id"]; ok && len(sessionIDHeaders) > 0 {
		sessionID = sessionIDHeaders[0]
		h.logger.WithField("sessionID", sessionID).Debug("Found session ID in headers")
	}

	// Store session ID if present
	if sessionID != "" {
		h.clientSessionIDsMutex.Lock()
		h.clientSessionIDs[clientID] = sessionID
		h.clientSessionIDsMutex.Unlock()
	}

	h.clientConnMutex.Lock()
	h.clientConnections[clientID] = clientConn
	h.clientConnMutex.Unlock()

	// Create a buffered channel for client messages
	clientChan := make(chan *infraWebsocket.ResponseMessage, 1000)
	defer close(clientChan)

	h.clientChannelMutex.Lock()
	if _, exists := h.clientChannels[targetKey]; !exists {
		h.clientChannels[targetKey] = make(map[string]chan *infraWebsocket.ResponseMessage)
	}
	h.clientChannels[targetKey][clientID] = clientChan
	h.clientChannelMutex.Unlock()

	// Clean up resources when this function exits
	defer func() {
		// Remove client from clientConnections map and clean up its mutex
		h.clientConnMutex.Lock()
		clientConn, exists := h.clientConnections[clientID]
		if exists {
			// Clean up the connection mutex before removing the connection
			h.cleanupConnection(clientConn)
			delete(h.clientConnections, clientID)
		}
		h.clientConnMutex.Unlock()

		// Remove client from clientIDMap
		h.clientIDMutex.Lock()
		delete(h.clientIDMap, clientID)
		h.clientIDMutex.Unlock()

		// Remove client from clientSessionIDs map
		h.clientSessionIDsMutex.Lock()
		delete(h.clientSessionIDs, clientID)
		h.clientSessionIDsMutex.Unlock()

		// Remove client channel from clientChannels map
		h.clientChannelMutex.Lock()
		delete(h.clientChannels[targetKey], clientID)
		// If no more clients for this target, close and remove the target connection
		if len(h.clientChannels[targetKey]) == 0 {
			delete(h.clientChannels, targetKey)
			h.connectionMutex.Lock()
			if conn, exists := h.connections[targetKey]; exists {
				err := conn.Close()
				if err != nil {
					h.logger.WithError(err).Error("failed to close target connection")
				}
				delete(h.connections, targetKey)
			}
			h.connectionMutex.Unlock()
		}
		h.clientChannelMutex.Unlock()
	}()

	h.connectionMutex.RLock()
	targetConn, exists := h.connections[targetKey]
	h.connectionMutex.RUnlock()

	if !exists {
		var err error
		targetConn, err = h.connectToTarget(reqCtx, target)
		if err != nil {
			h.logger.WithError(err).Warn("failed to connect to target, closing connection")
			lb.ReportFailure(target, err)
			errorMsg := fmt.Sprintf("Failed to connect to target: %v", err)
			if writeErr := clientConn.WriteMessage(websocket.TextMessage, []byte(errorMsg)); writeErr != nil {
				h.logger.WithError(writeErr).Error("failed to send error message to client")
			}
			return err
		} else {
			h.connectionMutex.Lock()
			h.connections[targetKey] = targetConn
			h.connectionMutex.Unlock()

			h.clientIDMutex.Lock()
			h.clientIDMap[clientID] = targetConn
			h.clientIDMutex.Unlock()

			go h.readFromTarget(reqCtx, gatewayData, targetConn, targetKey, collector, target, lb)
		}
	}

	go h.forwardToTarget(clientConn, targetConn, reqCtx, gatewayData, collector)

	for {
		select {
		case <-done:
			return nil
		case message, ok := <-clientChan:
			if !ok {
				return nil
			}
			if message.Session != nil {
				if err := h.emitToSession(message); err != nil {
					h.logger.WithError(err).Error("error in emitToSession")
					return err
				}
			} else if message.URL != "" {
				if err := h.emitByUrl(message); err != nil {
					h.logger.WithError(err).Error("error in emitByUrl")
					return err
				}
			} else {
				if err := h.emitToBroadCast(message, targetKey); err != nil {
					h.logger.WithError(err).Error("error in emitToBroadCast")
					return err
				}
			}
		}
	}
}

func (h *forwardedWebsocketHandler) emitByUrl(message *infraWebsocket.ResponseMessage) error {
	h.clientConnMutex.RLock()
	defer h.clientConnMutex.RUnlock()

	targetPath := strings.TrimSuffix(message.URL, "/")
	if targetPath == "" {
		return fmt.Errorf("message has no URL")
	}

	for clientID, clientConn := range h.clientConnections {
		session, ok := h.clientSessionIDs[clientID]
		if session != "" && ok {
			continue
		}
		if err := h.writeMessageSafe(clientConn, websocket.TextMessage, message.Response); err != nil {
			h.logger.WithError(err).Error("error writing message to client")
			return err
		}
	}

	return nil
}

func (h *forwardedWebsocketHandler) emitToBroadCast(message *infraWebsocket.ResponseMessage, targetKey string) error {
	h.clientChannelMutex.RLock()
	defer h.clientChannelMutex.RUnlock()

	// Get all clients for this target
	clientChannels, exists := h.clientChannels[targetKey]
	if !exists {
		return fmt.Errorf("no clients found for target %s", targetKey)
	}

	h.clientConnMutex.RLock()
	defer h.clientConnMutex.RUnlock()

	// Send the message to all clients connected to this target
	for clientID := range clientChannels {
		clientConn, ok := h.clientConnections[clientID]
		if !ok {
			continue
		}

		if err := h.writeMessageSafe(clientConn, websocket.TextMessage, message.Response); err != nil {
			h.logger.WithError(err).Error("error writing message to client")
			return err
		}
	}

	return nil
}

func (h *forwardedWebsocketHandler) emitToSession(message *infraWebsocket.ResponseMessage) error {
	h.clientConnMutex.RLock()
	defer h.clientConnMutex.RUnlock()

	h.clientSessionIDsMutex.RLock()
	defer h.clientSessionIDsMutex.RUnlock()

	var sessionUUID string
	if message.Session != nil && message.Session.UUID != "" {
		sessionUUID = message.Session.UUID
	} else {
		return fmt.Errorf("message has no session UUID")
	}

	for cID, clientConn := range h.clientConnections {
		if headerSessionID, ok := h.clientSessionIDs[cID]; ok && headerSessionID == sessionUUID {
			if err := h.writeMessageSafe(clientConn, websocket.TextMessage, message.Response); err != nil {
				h.logger.WithError(err).Error("error writing message to client")
				return err
			}
			continue
		}
	}

	return nil
}

func (h *forwardedWebsocketHandler) writeMessageSafe(conn *websocket.Conn, messageType int, data []byte) error {
	h.connWriteMutexesMutex.RLock()
	mutex, exists := h.connWriteMutexes[conn]
	h.connWriteMutexesMutex.RUnlock()

	if !exists {
		h.connWriteMutexesMutex.Lock()
		mutex, exists = h.connWriteMutexes[conn]
		if !exists {
			mutex = &sync.Mutex{}
			h.connWriteMutexes[conn] = mutex
		}
		h.connWriteMutexesMutex.Unlock()
	}

	mutex.Lock()
	err := conn.WriteMessage(messageType, data)
	mutex.Unlock()

	return err
}

func (h *forwardedWebsocketHandler) cleanupConnection(conn *websocket.Conn) {
	h.connWriteMutexesMutex.Lock()
	delete(h.connWriteMutexes, conn)
	h.connWriteMutexesMutex.Unlock()
}

func (h *forwardedWebsocketHandler) getOrCreateLoadBalancer(upstream *domainUpstream.Upstream) (*loadbalancer.LoadBalancer, error) {
	if lb, ok := h.loadBalancers.Load(upstream.ID); ok {
		if lb, ok := lb.(*loadbalancer.LoadBalancer); ok {
			return lb, nil
		}
	}
	lb, err := loadbalancer.NewLoadBalancer(h.lbFactory, upstream, h.logger, h.cache)
	if err != nil {
		return nil, err
	}
	h.loadBalancers.Store(upstream.ID, lb)
	return lb, nil
}

func (h *forwardedWebsocketHandler) connectToTarget(
	reqCtx *types.RequestContext,
	target *types.UpstreamTarget,
) (*gorilla.Conn, error) {
	protocol := target.Protocol
	if protocol == "https" {
		protocol = "wss"
	} else {
		protocol = "ws"
	}

	targetURL := fmt.Sprintf("%s://%s:%d%s",
		protocol,
		target.Host,
		target.Port,
		target.Path)

	conn, resp, err := gorilla.DefaultDialer.Dial(targetURL, reqCtx.Headers)
	if err != nil {
		if resp != nil {
			return nil, fmt.Errorf("websocket dial failed: %v (HTTP %d)", err, resp.StatusCode)
		}
		return nil, fmt.Errorf("websocket dial failed: %w", err)
	}

	pongWait, err := time.ParseDuration(h.config.WebSocket.PongWait)
	if err != nil {
		pongWait = 45 * time.Second
	}

	conn.SetPongHandler(func(string) error {
		h.logger.Debug("pong received from target, resetting read deadline")
		return conn.SetReadDeadline(time.Now().Add(pongWait))
	})

	if err := conn.SetReadDeadline(time.Now().Add(pongWait)); err != nil {
		errConn := conn.Close()
		if errConn != nil {
			h.logger.WithError(errConn).Error("failed to close client connection")
		}
		return nil, fmt.Errorf("failed to set read deadline on target connection: %w", err)
	}

	return conn, nil
}

func (h *forwardedWebsocketHandler) readFromTarget(
	reqCtx *types.RequestContext,
	gatewayData *types.GatewayData,
	targetConn *gorilla.Conn,
	targetKey string,
	metricsCollector *metrics.Collector,
	target *types.UpstreamTarget,
	lb *loadbalancer.LoadBalancer,
) {
	defer func() {
		h.connectionMutex.Lock()
		delete(h.connections, targetKey)
		h.connectionMutex.Unlock()
		err := targetConn.Close()
		if err != nil {
			h.logger.WithError(err).Error("failed to close target connection")
		}
	}()

	pingPeriod, err := time.ParseDuration(h.config.WebSocket.PingPeriod)
	if err != nil {
		pingPeriod = 30 * time.Second
	}
	targetPingTicker := time.NewTicker(pingPeriod)
	defer targetPingTicker.Stop()

	done := make(chan struct{})
	defer close(done)

	go func() {
		for {
			select {
			case <-done:
				return
			case <-targetPingTicker.C:
				if err := targetConn.WriteMessage(websocket.PingMessage, []byte{}); err != nil {
					h.logger.WithError(err).Error("failed to send ping to target in multiplexing mode")
					return
				}
			}
		}
	}()

	for {
		_, message, err := targetConn.ReadMessage()
		if err != nil {
			lb.ReportFailure(target, err)
			h.logger.WithError(err).Error("error reading message from target")
			break
		}

		h.clientChannelMutex.RLock()
		clients := make(map[string]chan *infraWebsocket.ResponseMessage, len(h.clientChannels[targetKey]))
		for clientID, ch := range h.clientChannels[targetKey] {
			clients[clientID] = ch
		}
		h.clientChannelMutex.RUnlock()

		if len(clients) == 0 {
			h.logger.Error("no clients found for target")
			return
		}

		lb.ReportSuccess(target)

		respCtx := &types.ResponseContext{
			Context:    context.Background(),
			GatewayID:  gatewayData.Gateway.ID,
			Headers:    make(map[string][]string),
			Metadata:   make(map[string]interface{}),
			Body:       message,
			StatusCode: http.StatusOK,
		}

		if _, err := h.pluginManager.ExecuteStage(
			context.Background(),
			types.PostResponse,
			gatewayData.Gateway.ID,
			reqCtx,
			respCtx,
			metricsCollector,
		); err != nil {
			var pluginErr *types.PluginError
			if errors.As(err, &pluginErr) {
				errorPayload := fiber.Map{
					"error":       pluginErr.Message,
					"retry_after": respCtx.Metadata["retry_after"],
				}
				if data, err := json.Marshal(errorPayload); err == nil {
					for clientID, clientChan := range clients {
						var sess *infraWebsocket.Session
						h.clientSessionIDsMutex.RLock()
						if sessionID, ok := h.clientSessionIDs[clientID]; ok {
							sess = &infraWebsocket.Session{UUID: sessionID}
						}
						h.clientSessionIDsMutex.RUnlock()

						respMessage := &infraWebsocket.ResponseMessage{
							Session:    sess,
							Response:   data,
							URL:        reqCtx.Path,
							OriginPath: reqCtx.Path,
						}

						select {
						case clientChan <- respMessage:
						default:
							h.logger.WithField("clientID", clientID).Warn("client channel full, dropping plugin error message")
						}
					}
				} else {
					h.logger.WithError(err).Error("failed to serialize plugin error")
				}
				continue
			}

			if respCtx.StopProcessing {
				for clientID, clientChan := range clients {
					var sess *infraWebsocket.Session
					h.clientSessionIDsMutex.RLock()
					if sessionID, ok := h.clientSessionIDs[clientID]; ok {
						sess = &infraWebsocket.Session{UUID: sessionID}
					}
					h.clientSessionIDsMutex.RUnlock()

					respMessage := &infraWebsocket.ResponseMessage{
						Session:    sess,
						Response:   respCtx.Body,
						URL:        reqCtx.Path,
						OriginPath: reqCtx.Path,
					}

					select {
					case clientChan <- respMessage:
					default:
						h.logger.WithField("clientID", clientID).Warn("client channel full, dropping stop processing message")
					}
				}
				continue
			}

			if !h.config.Plugins.IgnoreErrors {
				errPayload := fiber.Map{"error": "plugin execution failed"}
				if data, err := json.Marshal(errPayload); err == nil {
					for clientID, clientChan := range clients {
						var sess *infraWebsocket.Session
						h.clientSessionIDsMutex.RLock()
						if sessionID, ok := h.clientSessionIDs[clientID]; ok {
							sess = &infraWebsocket.Session{UUID: sessionID}
						}
						h.clientSessionIDsMutex.RUnlock()

						respMessage := &infraWebsocket.ResponseMessage{
							Session:    sess,
							Response:   data,
							URL:        reqCtx.Path,
							OriginPath: reqCtx.Path,
						}

						select {
						case clientChan <- respMessage:
						default:
							h.logger.WithField("clientID", clientID).Warn("client channel full, dropping plugin error fallback message")
						}
					}
				}
				continue
			}
		}

		// Normal response
		// Try to parse the response body as JSON to check for session ID
		var messageData map[string]interface{}
		var messageSessionID string

		if err := json.Unmarshal(respCtx.Body, &messageData); err == nil {
			// Check if the message contains a session field with a uuid
			if sessionData, ok := messageData["session"].(map[string]interface{}); ok {
				if uuid, ok := sessionData["uuid"].(string); ok && uuid != "" {
					messageSessionID = uuid
				}
			}
		}

		// If the message contains a session ID, only send to clients with matching session IDs
		if messageSessionID != "" {
			h.logger.WithField("sessionID", messageSessionID).Debug("Found session ID in response body, sending only to matching clients")

			for clientID, clientChan := range clients {
				h.clientSessionIDsMutex.RLock()
				clientSessionID, hasSession := h.clientSessionIDs[clientID]
				h.clientSessionIDsMutex.RUnlock()

				// Only send to clients with matching session IDs
				if hasSession && clientSessionID == messageSessionID {
					respMessage := &infraWebsocket.ResponseMessage{
						Session:    &infraWebsocket.Session{UUID: messageSessionID},
						Response:   respCtx.Body,
						URL:        reqCtx.Path,
						OriginPath: reqCtx.Path,
					}

					select {
					case clientChan <- respMessage:
					default:
						h.logger.WithField("clientID", clientID).Warn("client channel full, dropping response message")
					}
				}
			}
		} else {
			// No session ID in the message, send to all clients as before
			for clientID, clientChan := range clients {
				var sess *infraWebsocket.Session
				h.clientSessionIDsMutex.RLock()
				if sessionID, ok := h.clientSessionIDs[clientID]; ok {
					sess = &infraWebsocket.Session{UUID: sessionID}
				}
				h.clientSessionIDsMutex.RUnlock()

				respMessage := &infraWebsocket.ResponseMessage{
					Session:    sess,
					Response:   respCtx.Body,
					URL:        reqCtx.Path,
					OriginPath: reqCtx.Path,
				}

				select {
				case clientChan <- respMessage:
				default:
					h.logger.WithField("clientID", clientID).Warn("client channel full, dropping response message")
				}
			}
		}
	}
}

func (h *forwardedWebsocketHandler) forwardToTarget(
	clientConn *websocket.Conn,
	targetConn *gorilla.Conn,
	reqCtx *types.RequestContext,
	gatewayData *types.GatewayData,
	collector *metrics.Collector,
) {
	respCtx := &types.ResponseContext{
		Context:   context.Background(),
		GatewayID: gatewayData.Gateway.ID,
		Headers:   make(map[string][]string),
		Metadata:  make(map[string]interface{}),
	}

	for {
		mt, message, err := clientConn.ReadMessage()
		if err != nil {
			h.logger.WithError(err).Error("error reading message from client")
			return
		}

		var wsMessage infraWebsocket.Message
		if err := json.Unmarshal(message, &wsMessage); err != nil {
			h.logger.WithError(err).Error("failed to unmarshal message")
			continue
		}

		wsMessage.OriginPath = reqCtx.Path

		clientID := fmt.Sprintf("%p", clientConn)

		h.clientSessionIDsMutex.RLock()
		sessionID, hasSessionID := h.clientSessionIDs[clientID]
		h.clientSessionIDsMutex.RUnlock()

		if hasSessionID && sessionID != "" {
			if wsMessage.Session == nil {
				wsMessage.Session = &infraWebsocket.Session{}
			}
			wsMessage.Session.UUID = sessionID
		}

		reqCtx.Body = message

		if _, err := h.pluginManager.ExecuteStage(
			context.Background(),
			types.PreRequest,
			gatewayData.Gateway.ID,
			reqCtx,
			respCtx,
			collector,
		); err != nil {
			var pluginErr *types.PluginError
			if errors.As(err, &pluginErr) {
				errorPayload := fiber.Map{
					"error":       pluginErr.Message,
					"retry_after": respCtx.Metadata["retry_after"],
				}
				if data, err := json.Marshal(errorPayload); err == nil {
					err = clientConn.WriteMessage(websocket.TextMessage, data)
					if err != nil {
						h.logger.WithError(err).Error("failed to send error message to client")
					}
				} else {
					h.logger.WithError(err).Error("failed to serialize plugin error")
				}
				return
			}

			if respCtx.StopProcessing {
				err = clientConn.WriteMessage(websocket.TextMessage, respCtx.Body)
				if err != nil {
					h.logger.WithError(err).Error("failed to send stop processing message to client")
				}
				return
			}

			if !h.config.Plugins.IgnoreErrors {
				errPayload := fiber.Map{"error": "plugin execution failed"}
				if data, err := json.Marshal(errPayload); err == nil {
					err = clientConn.WriteMessage(websocket.TextMessage, data)
					if err != nil {
						h.logger.WithError(err).Error("failed to send error message to client")
					}
				}
				return
			}
		}

		if targetConn != nil {
			if err := targetConn.WriteMessage(mt, reqCtx.Body); err != nil {
				h.logger.WithError(err).Error("error writing message to target")
				return
			}
		}
	}
}
