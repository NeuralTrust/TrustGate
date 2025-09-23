package middleware

import (
	"fmt"

	"github.com/NeuralTrust/TrustGate/pkg/common"
	"github.com/NeuralTrust/TrustGate/pkg/plugins"
	"github.com/NeuralTrust/TrustGate/pkg/types"
	"github.com/gofiber/fiber/v2"
	"github.com/sirupsen/logrus"
)

type pluginMiddleware struct {
	pluginManager plugins.Manager
	logger        *logrus.Logger
}

func NewPluginChainMiddleware(
	pluginManager plugins.Manager,
	logger *logrus.Logger,
) Middleware {
	return &pluginMiddleware{
		pluginManager: pluginManager,
		logger:        logger,
	}
}

func (m *pluginMiddleware) Middleware() fiber.Handler {
	return func(c *fiber.Ctx) error {
		gatewayData, ok := c.Locals(string(common.GatewayDataContextKey)).(*types.GatewayData)
		if !ok {
			m.logger.Error("gateway data not found in context")
			return c.Status(fiber.StatusInternalServerError).JSON(
				fiber.Map{"error": "failed to get gateway data from context in plugin chain middleware"},
			)
		}

		err := m.configurePlugins(gatewayData)
		if err != nil {
			m.logger.WithError(err).Error("failed to configure gateway plugins")
			return c.Status(fiber.StatusInternalServerError).JSON(
				fiber.Map{"error": "failed to configure gateway plugins"},
			)
		}
		return c.Next()
	}

}

func (m *pluginMiddleware) configurePlugins(gateway *types.GatewayData) error {
	m.pluginManager.ClearPluginChain(gateway.Gateway.ID)
	gatewayChains := m.convertGatewayPlugins(gateway.Gateway)
	if len(gatewayChains) == 0 {
		return nil
	}
	if err := m.pluginManager.SetPluginChain(gateway.Gateway.ID, gatewayChains); err != nil {
		return fmt.Errorf("failed to configure gateway plugins: %w", err)
	}
	return nil
}

func (m *pluginMiddleware) convertGatewayPlugins(gateway *types.Gateway) []types.PluginConfig {
	chains := make([]types.PluginConfig, 0, len(gateway.RequiredPlugins))
	for _, cfg := range gateway.RequiredPlugins {
		if !cfg.Enabled {
			continue
		}
		plugin := m.pluginManager.GetPlugin(cfg.Name)
		if plugin == nil {
			m.logger.WithField("plugin", cfg.Name).Error("Plugin not found")
			continue
		}

		pluginConfig := cfg
		// Level removed

		if len(plugin.Stages()) > 0 || cfg.Stage != "" {
			chains = append(chains, pluginConfig)
		} else {
			m.logger.WithField("plugin", cfg.Name).Error("Stage not configured for plugin")
		}
	}
	return chains
}
