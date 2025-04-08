package dependency_container

import (
	"fmt"
	"net/http"
	"reflect"
	"time"

	"github.com/NeuralTrust/TrustGate/pkg/app/apikey"
	"github.com/NeuralTrust/TrustGate/pkg/app/gateway"
	"github.com/NeuralTrust/TrustGate/pkg/app/plugin"
	"github.com/NeuralTrust/TrustGate/pkg/app/service"
	"github.com/NeuralTrust/TrustGate/pkg/app/telemetry"
	"github.com/NeuralTrust/TrustGate/pkg/app/upstream"
	"github.com/NeuralTrust/TrustGate/pkg/cache"
	"github.com/NeuralTrust/TrustGate/pkg/common"
	"github.com/NeuralTrust/TrustGate/pkg/config"
	"github.com/NeuralTrust/TrustGate/pkg/database"
	domainApikey "github.com/NeuralTrust/TrustGate/pkg/domain/apikey"
	handlers "github.com/NeuralTrust/TrustGate/pkg/handlers/http"
	"github.com/NeuralTrust/TrustGate/pkg/infra/bedrock"
	infraCache "github.com/NeuralTrust/TrustGate/pkg/infra/cache"
	"github.com/NeuralTrust/TrustGate/pkg/infra/cache/event"
	"github.com/NeuralTrust/TrustGate/pkg/infra/cache/subscriber"
	"github.com/NeuralTrust/TrustGate/pkg/infra/fingerprint"
	"github.com/NeuralTrust/TrustGate/pkg/infra/httpx"
	"github.com/NeuralTrust/TrustGate/pkg/infra/repository"
	"github.com/NeuralTrust/TrustGate/pkg/loadbalancer"
	"github.com/NeuralTrust/TrustGate/pkg/middleware"
	"github.com/NeuralTrust/TrustGate/pkg/plugins"
	"github.com/sirupsen/logrus"
)

type Container struct {
	Cache                 *cache.Cache
	BedrockClient         bedrock.Client
	PluginManager         plugins.Manager
	HandlerTransport      handlers.HandlerTransport
	RedisListener         infraCache.EventListener
	Repository            *database.Repository
	AuthMiddleware        middleware.Middleware
	GatewayMiddleware     middleware.Middleware
	MetricsMiddleware     middleware.Middleware
	PluginMiddleware      middleware.Middleware
	FingerPrintMiddleware middleware.Middleware
	ApiKeyRepository      domainApikey.Repository
	FingerprintTracker    fingerprint.Tracker
	PluginChainValidator  plugin.ValidatePluginChain
}

func NewContainer(
	cfg *config.Config,
	logger *logrus.Logger,
	db *database.DB,
	lbFactory loadbalancer.Factory,
	eventsRegistry map[string]reflect.Type,
	initializeMemoryCache func(cacheInstance *cache.Cache),
) (*Container, error) {

	httpClient := &http.Client{}
	breaker := httpx.NewCircuitBreaker("breaker", 10*time.Second, 3)

	cacheConfig := common.CacheConfig{
		Host:     cfg.Redis.Host,
		Port:     cfg.Redis.Port,
		Password: cfg.Redis.Password,
		DB:       cfg.Redis.DB,
	}
	cacheInstance, err := cache.NewCache(cacheConfig, db.DB)
	if err != nil {
		return nil, fmt.Errorf("failed to initialize cache: %v", err)
	}
	initializeMemoryCache(cacheInstance)

	bedrockClient, err := bedrock.NewClient(logger)
	if err != nil {
		return nil, fmt.Errorf("failed to initialize bedrock client: %v", err)
	}

	fingerprintTracker := fingerprint.NewFingerPrintTracker(cacheInstance)
	pluginManager := plugins.NewManager(cfg, cacheInstance, logger, bedrockClient, fingerprintTracker)

	// repository
	repo := database.NewRepository(db.DB, logger, cacheInstance)
	upstreamRepository := repository.NewUpstreamRepository(db.DB)
	serviceRepository := repository.NewServiceRepository(db.DB)
	apiKeyRepository := repository.NewApiKeyRepository(db.DB)
	gatewayRepository := repository.NewGatewayRepository(db.DB)

	// service
	upstreamFinder := upstream.NewFinder(upstreamRepository, cacheInstance, logger)
	serviceFinder := service.NewFinder(serviceRepository, cacheInstance, logger)
	apiKeyFinder := apikey.NewFinder(apiKeyRepository, cacheInstance, logger)
	updateGatewayCache := gateway.NewUpdateGatewayCache(cacheInstance)
	getGatewayCache := gateway.NewGetGatewayCache(cacheInstance)
	validatePlugin := plugin.NewValidatePlugin(pluginManager)
	gatewayDataFinder := gateway.NewDataFinder(repo, cacheInstance, logger)
	pluginChainValidator := plugin.NewValidatePluginChain(pluginManager, gatewayRepository)

	telemetryBuilder := telemetry.NewTelemetryProvidersBuilder(breaker, httpClient)

	// redis publisher
	redisPublisher := infraCache.NewRedisEventPublisher(cacheInstance)
	redisListener := infraCache.NewRedisEventListener(logger, cacheInstance, eventsRegistry)

	// subscribers
	deleteGatewaySubscriber := subscriber.NewDeleteGatewayCacheEventSubscriber(logger, cacheInstance)
	deleteRulesSubscriber := subscriber.NewDeleteRulesEventSubscriber(logger, cacheInstance)
	deleteServiceSubscriber := subscriber.NewDeleteServiceCacheEventSubscriber(logger, cacheInstance)
	deleteUpstreamSubscriber := subscriber.NewDeleteUpstreamCacheEventSubscriber(logger, cacheInstance)
	deleteApiKeySubscriber := subscriber.NewDeleteApiKeyCacheEventSubscriber(logger, cacheInstance)
	updateGatewaySubscriber := subscriber.NewUpdateGatewayCacheEventSubscriber(logger, updateGatewayCache, cacheInstance)
	updateUpstreamSubscriber := subscriber.NewUpdateUpstreamCacheEventSubscriber(logger, cacheInstance, upstreamRepository)
	updateServiceSubscriber := subscriber.NewUpdateServiceCacheEventSubscriber(logger, cacheInstance, serviceRepository)

	infraCache.RegisterEventSubscriber[event.DeleteGatewayCacheEvent](redisListener, deleteGatewaySubscriber)
	infraCache.RegisterEventSubscriber[event.DeleteRulesCacheEvent](redisListener, deleteRulesSubscriber)
	infraCache.RegisterEventSubscriber[event.DeleteServiceCacheEvent](redisListener, deleteServiceSubscriber)
	infraCache.RegisterEventSubscriber[event.DeleteUpstreamCacheEvent](redisListener, deleteUpstreamSubscriber)
	infraCache.RegisterEventSubscriber[event.DeleteKeyCacheEvent](redisListener, deleteApiKeySubscriber)
	infraCache.RegisterEventSubscriber[event.UpdateGatewayCacheEvent](redisListener, updateGatewaySubscriber)
	infraCache.RegisterEventSubscriber[event.UpdateUpstreamCacheEvent](redisListener, updateUpstreamSubscriber)
	infraCache.RegisterEventSubscriber[event.UpdateServiceCacheEvent](redisListener, updateServiceSubscriber)

	// Handler Transport
	handlerTransport := &handlers.HandlerTransportDTO{
		// Proxy
		ForwardedHandler: handlers.NewForwardedHandler(
			logger,
			repo,
			cacheInstance,
			upstreamFinder,
			serviceFinder,
			cfg.Providers.Providers,
			pluginManager,
			lbFactory,
			cfg,
		),
		// Gateway
		CreateGatewayHandler: handlers.NewCreateGatewayHandler(
			logger,
			gatewayRepository,
			updateGatewayCache,
			pluginChainValidator,
			telemetryBuilder,
		),
		ListGatewayHandler:   handlers.NewListGatewayHandler(logger, repo, updateGatewayCache),
		GetGatewayHandler:    handlers.NewGetGatewayHandler(logger, repo, getGatewayCache, updateGatewayCache),
		UpdateGatewayHandler: handlers.NewUpdateGatewayHandler(logger, repo, pluginManager, redisPublisher, telemetryBuilder),
		DeleteGatewayHandler: handlers.NewDeleteGatewayHandler(logger, repo, redisPublisher),
		// Upstream
		CreateUpstreamHandler: handlers.NewCreateUpstreamHandler(logger, repo, cacheInstance),
		ListUpstreamHandler:   handlers.NewListUpstreamHandler(logger, repo, cacheInstance),
		GetUpstreamHandler:    handlers.NewGetUpstreamHandler(logger, repo, cacheInstance, upstreamFinder),
		UpdateUpstreamHandler: handlers.NewUpdateUpstreamHandler(logger, repo, redisPublisher),
		DeleteUpstreamHandler: handlers.NewDeleteUpstreamHandler(logger, repo, redisPublisher),
		// Service
		CreateServiceHandler: handlers.NewCreateServiceHandler(logger, repo, cacheInstance),
		ListServicesHandler:  handlers.NewListServicesHandler(logger, repo),
		GetServiceHandler:    handlers.NewGetServiceHandler(logger, serviceRepository, cacheInstance),
		UpdateServiceHandler: handlers.NewUpdateServiceHandler(logger, repo, redisPublisher),
		DeleteServiceHandler: handlers.NewDeleteServiceHandler(logger, repo, redisPublisher),
		// Rule
		CreateRuleHandler: handlers.NewCreateRuleHandler(logger, repo, pluginChainValidator),
		ListRulesHandler:  handlers.NewListRulesHandler(logger, repo, cacheInstance),
		UpdateRuleHandler: handlers.NewUpdateRuleHandler(logger, repo, cacheInstance, validatePlugin, redisPublisher),
		DeleteRuleHandler: handlers.NewDeleteRuleHandler(logger, repo, cacheInstance, redisPublisher),
		// APIKey
		CreateAPIKeyHandler: handlers.NewCreateAPIKeyHandler(logger, repo, cacheInstance),
		ListAPIKeysHandler:  handlers.NewListAPIKeysHandler(logger, repo),
		GetAPIKeyHandler:    handlers.NewGetAPIKeyHandler(logger, cacheInstance, apiKeyRepository),
		DeleteAPIKeyHandler: handlers.NewDeleteAPIKeyHandler(logger, repo, apiKeyRepository, redisPublisher),
	}

	container := &Container{
		Cache:                 cacheInstance,
		RedisListener:         redisListener,
		HandlerTransport:      handlerTransport,
		Repository:            repo,
		AuthMiddleware:        middleware.NewAuthMiddleware(logger, apiKeyFinder, false),
		GatewayMiddleware:     middleware.NewGatewayMiddleware(logger, cacheInstance, repo, gatewayDataFinder, cfg.Server.BaseDomain),
		MetricsMiddleware:     middleware.NewMetricsMiddleware(logger, telemetryBuilder),
		PluginMiddleware:      middleware.NewPluginChainMiddleware(pluginManager, logger),
		FingerPrintMiddleware: middleware.NewFingerPrintMiddleware(logger, fingerprintTracker),
		ApiKeyRepository:      apiKeyRepository,
		PluginManager:         pluginManager,
		BedrockClient:         bedrockClient,
		FingerprintTracker:    fingerprintTracker,
		PluginChainValidator:  pluginChainValidator,
	}

	return container, nil
}
