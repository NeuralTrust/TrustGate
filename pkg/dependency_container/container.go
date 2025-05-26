package dependency_container

import (
	"fmt"
	"reflect"
	"time"

	providersFactory "github.com/NeuralTrust/TrustGate/pkg/infra/providers/factory"
	"github.com/NeuralTrust/TrustGate/pkg/infra/telemetry/trustlens"
	"github.com/valyala/fasthttp"

	"github.com/NeuralTrust/TrustGate/pkg/app/apikey"
	"github.com/NeuralTrust/TrustGate/pkg/app/gateway"
	"github.com/NeuralTrust/TrustGate/pkg/app/plugin"
	"github.com/NeuralTrust/TrustGate/pkg/app/service"
	"github.com/NeuralTrust/TrustGate/pkg/app/telemetry"
	appUpstream "github.com/NeuralTrust/TrustGate/pkg/app/upstream"
	"github.com/NeuralTrust/TrustGate/pkg/cache"
	"github.com/NeuralTrust/TrustGate/pkg/common"
	"github.com/NeuralTrust/TrustGate/pkg/config"
	"github.com/NeuralTrust/TrustGate/pkg/database"
	domainApikey "github.com/NeuralTrust/TrustGate/pkg/domain/apikey"
	domainEmbedding "github.com/NeuralTrust/TrustGate/pkg/domain/embedding"
	domainSession "github.com/NeuralTrust/TrustGate/pkg/domain/session"
	domain "github.com/NeuralTrust/TrustGate/pkg/domain/telemetry"
	handlers "github.com/NeuralTrust/TrustGate/pkg/handlers/http"
	wsHandlers "github.com/NeuralTrust/TrustGate/pkg/handlers/websocket"
	"github.com/NeuralTrust/TrustGate/pkg/infra/bedrock"
	infraCache "github.com/NeuralTrust/TrustGate/pkg/infra/cache"
	"github.com/NeuralTrust/TrustGate/pkg/infra/cache/event"
	"github.com/NeuralTrust/TrustGate/pkg/infra/cache/subscriber"
	"github.com/NeuralTrust/TrustGate/pkg/infra/embedding/factory"
	"github.com/NeuralTrust/TrustGate/pkg/infra/fingerprint"
	"github.com/NeuralTrust/TrustGate/pkg/infra/jwt"
	"github.com/NeuralTrust/TrustGate/pkg/infra/metrics"
	"github.com/NeuralTrust/TrustGate/pkg/infra/repository"
	infraTelemetry "github.com/NeuralTrust/TrustGate/pkg/infra/telemetry"
	"github.com/NeuralTrust/TrustGate/pkg/infra/telemetry/kafka"
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
	WSHandlerTransport    wsHandlers.HandlerTransport
	RedisListener         infraCache.EventListener
	Repository            *database.Repository
	AuthMiddleware        middleware.Middleware
	AdminAuthMiddleware   middleware.Middleware
	MetricsMiddleware     middleware.Middleware
	PluginMiddleware      middleware.Middleware
	FingerPrintMiddleware middleware.Middleware
	SecurityMiddleware    middleware.Middleware
	WebSocketMiddleware   middleware.Middleware
	SessionMiddleware     middleware.Middleware
	ApiKeyRepository      domainApikey.Repository
	EmbeddingRepository   domainEmbedding.EmbeddingRepository
	SessionRepository     domainSession.Repository
	FingerprintTracker    fingerprint.Tracker
	PluginChainValidator  plugin.ValidatePluginChain
	MetricsWorker         metrics.Worker
	RedisIndexCreator     infraCache.RedisIndexCreator
	JWTManager            jwt.Manager
}

func NewContainer(
	cfg *config.Config,
	logger *logrus.Logger,
	db *database.DB,
	eventsRegistry map[string]reflect.Type,
	initializeMemoryCache func(cacheInstance *cache.Cache),
	initializeLoadBalancerFactory loadbalancer.FactoryInitializer,
) (*Container, error) {

	httpClient := &fasthttp.Client{
		ReadTimeout:                   10 * time.Second,
		WriteTimeout:                  10 * time.Second,
		MaxConnsPerHost:               16384,
		MaxIdleConnDuration:           120 * time.Second,
		ReadBufferSize:                32768,
		WriteBufferSize:               32768,
		NoDefaultUserAgentHeader:      true,
		DisableHeaderNamesNormalizing: true,
		DisablePathNormalizing:        true,
	}
	// breaker := httpx.NewCircuitBreaker("breaker", 10*time.Second, 3)

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

	redisIndexCreator := infraCache.NewRedisIndexCreator(cacheInstance.Client(), logger)

	bedrockClient, err := bedrock.NewClient(logger)
	if err != nil {
		return nil, fmt.Errorf("failed to initialize bedrock client: %v", err)
	}

	// embedding services
	embeddingServiceLocator := factory.NewServiceLocator(logger, httpClient)
	embeddingRepository := repository.NewRedisEmbeddingRepository(cacheInstance)
	descriptionEmbeddingCreator := appUpstream.NewDescriptionEmbeddingCreator(embeddingServiceLocator, embeddingRepository, logger)

	providerFactory := providersFactory.NewProviderLocator(httpClient)

	fingerprintTracker := fingerprint.NewFingerPrintTracker(cacheInstance)
	pluginManager := plugins.NewManager(
		cfg,
		cacheInstance,
		logger,
		bedrockClient,
		fingerprintTracker,
		embeddingRepository,
		embeddingServiceLocator,
		providerFactory,
	)

	// repository
	repo := database.NewRepository(db.DB, logger, cacheInstance)
	upstreamRepository := repository.NewUpstreamRepository(db.DB)
	serviceRepository := repository.NewServiceRepository(db.DB)
	apiKeyRepository := repository.NewApiKeyRepository(db.DB)
	gatewayRepository := repository.NewGatewayRepository(db.DB)
	ruleRepository := repository.NewForwardedRuleRepository(db.DB, logger, cacheInstance)

	// service
	upstreamFinder := appUpstream.NewFinder(upstreamRepository, cacheInstance, logger)
	serviceFinder := service.NewFinder(serviceRepository, cacheInstance, logger)
	apiKeyFinder := apikey.NewFinder(apiKeyRepository, cacheInstance, logger)
	updateGatewayCache := gateway.NewUpdateGatewayCache(cacheInstance)
	getGatewayCache := gateway.NewGetGatewayCache(cacheInstance)
	validatePlugin := plugin.NewValidatePlugin(pluginManager)
	gatewayDataFinder := gateway.NewDataFinder(repo, ruleRepository, cacheInstance, logger)
	pluginChainValidator := plugin.NewValidatePluginChain(pluginManager, gatewayRepository)

	// telemetry
	providerLocator := infraTelemetry.NewProviderLocator(map[string]domain.Exporter{
		kafka.ExporterName:     kafka.NewKafkaExporter(),
		trustlens.ExporterName: trustlens.NewTrustLensExporter(),
	})
	telemetryBuilder := telemetry.NewTelemetryExportersBuilder(providerLocator)
	telemetryValidator := telemetry.NewTelemetryExportersValidator(providerLocator)

	// redis publisher
	redisPublisher := infraCache.NewRedisEventPublisher(cacheInstance)
	redisListener := infraCache.NewRedisEventListener(logger, cacheInstance, eventsRegistry)

	// subscribers
	deleteGatewaySubscriber := subscriber.NewDeleteGatewayCacheEventSubscriber(logger, cacheInstance)
	deleteRulesSubscriber := subscriber.NewDeleteRulesEventSubscriber(logger, cacheInstance)
	deleteServiceSubscriber := subscriber.NewDeleteServiceCacheEventSubscriber(logger, cacheInstance)
	deleteUpstreamSubscriber := subscriber.NewDeleteUpstreamCacheEventSubscriber(logger, cacheInstance)
	deleteApiKeySubscriber := subscriber.NewDeleteApiKeyCacheEventSubscriber(logger, cacheInstance)
	updateGatewaySubscriber := subscriber.NewUpdateGatewayCacheEventSubscriber(logger, updateGatewayCache, cacheInstance, repo)
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

	lbFactory := initializeLoadBalancerFactory(embeddingRepository, embeddingServiceLocator)

	metricsWorker := metrics.NewWorker(logger, telemetryBuilder)

	jwtManager := jwt.NewJwtManager(&cfg.Server)

	// WebSocket handler transport
	wsHandlerTransport := &wsHandlers.HandlerTransportDTO{
		ForwardedHandler: wsHandlers.NewWebsocketHandler(
			cfg,
			logger,
			upstreamFinder,
			serviceFinder,
			lbFactory,
			cacheInstance,
			pluginManager,
		),
	}

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
			telemetryValidator,
		),
		ListGatewayHandler:   handlers.NewListGatewayHandler(logger, repo, updateGatewayCache),
		GetGatewayHandler:    handlers.NewGetGatewayHandler(logger, repo, getGatewayCache, updateGatewayCache),
		UpdateGatewayHandler: handlers.NewUpdateGatewayHandler(logger, repo, pluginManager, redisPublisher, telemetryValidator),
		DeleteGatewayHandler: handlers.NewDeleteGatewayHandler(logger, repo, redisPublisher),
		// Upstream
		CreateUpstreamHandler: handlers.NewCreateUpstreamHandler(logger, repo, cacheInstance, descriptionEmbeddingCreator, cfg),
		ListUpstreamHandler:   handlers.NewListUpstreamHandler(logger, repo, cacheInstance),
		GetUpstreamHandler:    handlers.NewGetUpstreamHandler(logger, repo, cacheInstance, upstreamFinder),
		UpdateUpstreamHandler: handlers.NewUpdateUpstreamHandler(logger, repo, redisPublisher, cacheInstance, descriptionEmbeddingCreator, cfg),
		DeleteUpstreamHandler: handlers.NewDeleteUpstreamHandler(logger, repo, redisPublisher),
		// Service
		CreateServiceHandler: handlers.NewCreateServiceHandler(logger, repo, cacheInstance),
		ListServicesHandler:  handlers.NewListServicesHandler(logger, repo),
		GetServiceHandler:    handlers.NewGetServiceHandler(logger, serviceRepository, cacheInstance),
		UpdateServiceHandler: handlers.NewUpdateServiceHandler(logger, repo, redisPublisher),
		DeleteServiceHandler: handlers.NewDeleteServiceHandler(logger, repo, redisPublisher),
		// Rule
		CreateRuleHandler: handlers.NewCreateRuleHandler(logger, repo, pluginChainValidator),
		ListRulesHandler: handlers.NewListRulesHandler(
			logger,
			ruleRepository,
			gatewayRepository,
			serviceRepository,
			cacheInstance,
		),
		UpdateRuleHandler: handlers.NewUpdateRuleHandler(logger, repo, cacheInstance, validatePlugin, redisPublisher),
		DeleteRuleHandler: handlers.NewDeleteRuleHandler(logger, repo, cacheInstance, redisPublisher),
		// APIKey
		CreateAPIKeyHandler: handlers.NewCreateAPIKeyHandler(logger, repo, cacheInstance),
		ListAPIKeysHandler:  handlers.NewListAPIKeysHandler(logger, repo),
		GetAPIKeyHandler:    handlers.NewGetAPIKeyHandler(logger, cacheInstance, apiKeyRepository),
		DeleteAPIKeyHandler: handlers.NewDeleteAPIKeyHandler(logger, repo, apiKeyRepository, redisPublisher),
		// Version
		GetVersionHandler:  handlers.NewGetVersionHandler(logger),
		ListPluginsHandler: handlers.NewListPluginsHandler(logger),
	}

	// Initialize session repository
	sessionRepository := repository.NewSessionRepository(cacheInstance)

	container := &Container{
		Cache:                 cacheInstance,
		RedisListener:         redisListener,
		HandlerTransport:      handlerTransport,
		WSHandlerTransport:    wsHandlerTransport,
		Repository:            repo,
		AuthMiddleware:        middleware.NewAuthMiddleware(logger, apiKeyFinder, gatewayDataFinder),
		AdminAuthMiddleware:   middleware.NewAdminAuthMiddleware(logger, jwtManager),
		MetricsMiddleware:     middleware.NewMetricsMiddleware(logger, metricsWorker),
		PluginMiddleware:      middleware.NewPluginChainMiddleware(pluginManager, logger),
		FingerPrintMiddleware: middleware.NewFingerPrintMiddleware(logger, fingerprintTracker),
		SecurityMiddleware:    middleware.NewSecurityMiddleware(logger),
		WebSocketMiddleware:   middleware.NewWebsocketMiddleware(cfg, logger),
		SessionMiddleware:     middleware.NewSessionMiddleware(logger, sessionRepository),
		ApiKeyRepository:      apiKeyRepository,
		EmbeddingRepository:   embeddingRepository,
		SessionRepository:     sessionRepository,
		PluginManager:         pluginManager,
		BedrockClient:         bedrockClient,
		FingerprintTracker:    fingerprintTracker,
		PluginChainValidator:  pluginChainValidator,
		MetricsWorker:         metricsWorker,
		RedisIndexCreator:     redisIndexCreator,
		JWTManager:            jwtManager,
	}

	return container, nil
}
