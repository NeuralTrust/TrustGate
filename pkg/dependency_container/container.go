package dependency_container

import (
	"crypto/tls"
	"fmt"
	"net/http"
	"reflect"
	"time"

	ruledomain "github.com/NeuralTrust/TrustGate/pkg/domain/forwarding_rule"
	"github.com/NeuralTrust/TrustGate/pkg/infra/auth/jwt"
	"github.com/NeuralTrust/TrustGate/pkg/infra/database"
	"github.com/NeuralTrust/TrustGate/pkg/infra/firewall"
	"github.com/NeuralTrust/TrustGate/pkg/infra/httpx"
	"github.com/NeuralTrust/TrustGate/pkg/infra/policy"
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

	"github.com/NeuralTrust/TrustGate/pkg/config"
	domainEmbedding "github.com/NeuralTrust/TrustGate/pkg/domain/embedding"
	domainGateway "github.com/NeuralTrust/TrustGate/pkg/domain/gateway"
	domainApikey "github.com/NeuralTrust/TrustGate/pkg/domain/iam/apikey"
	domainSession "github.com/NeuralTrust/TrustGate/pkg/domain/session"
	domain "github.com/NeuralTrust/TrustGate/pkg/domain/telemetry"
	handlers "github.com/NeuralTrust/TrustGate/pkg/handlers/http"
	wsHandlers "github.com/NeuralTrust/TrustGate/pkg/handlers/websocket"
	"github.com/NeuralTrust/TrustGate/pkg/infra/auth/oauth"
	"github.com/NeuralTrust/TrustGate/pkg/infra/bedrock"
	infraCache "github.com/NeuralTrust/TrustGate/pkg/infra/cache"
	"github.com/NeuralTrust/TrustGate/pkg/infra/cache/event"
	"github.com/NeuralTrust/TrustGate/pkg/infra/cache/subscriber"
	"github.com/NeuralTrust/TrustGate/pkg/infra/embedding/factory"
	"github.com/NeuralTrust/TrustGate/pkg/infra/fingerprint"
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
	Cache                 cache.Cache
	BedrockClient         bedrock.Client
	PluginManager         plugins.Manager
	HandlerTransport      handlers.HandlerTransport
	WSHandlerTransport    wsHandlers.HandlerTransport
	RedisListener         infraCache.EventListener
	AuthMiddleware        middleware.Middleware
	CORSGlobalMiddleware  middleware.Middleware
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
	RuleRepository        ruledomain.Repository
	GatewayRepository     domainGateway.Repository
	FirewallClient        firewall.Client
}

func NewContainer(
	cfg *config.Config,
	logger *logrus.Logger,
	db *database.DB,
	eventsRegistry map[string]reflect.Type,
	initializeMemoryCache func(cacheInstance cache.Cache),
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

	cacheConfig := cache.Config{
		Host:     cfg.Redis.Host,
		Port:     cfg.Redis.Port,
		Password: cfg.Redis.Password,
		DB:       cfg.Redis.DB,
		TLS:      cfg.Redis.TLS,
	}
	cacheInstance, err := cache.NewCache(cacheConfig)
	if err != nil {
		return nil, fmt.Errorf("failed to initialize cache: %v", err)
	}
	initializeMemoryCache(cacheInstance)

	redisIndexCreator := infraCache.NewRedisIndexCreator(cacheInstance.Client(), logger)

	bedrockClient := bedrock.NewClient()

	// embedding services
	embeddingServiceLocator := factory.NewServiceLocator(logger, httpClient)
	embeddingRepository := repository.NewRedisEmbeddingRepository(cacheInstance)
	descriptionEmbeddingCreator := appUpstream.NewDescriptionEmbeddingCreator(embeddingServiceLocator, embeddingRepository, logger)

	providerFactory := providersFactory.NewProviderLocator(httpClient)

	stdHTTPClient := &http.Client{Timeout: 10 * time.Second}
	oauthTokenClient := oauth.NewTokenClient(stdHTTPClient)

	fingerprintTracker := fingerprint.NewFingerPrintTracker(cacheInstance)

	circuitBreaker := httpx.NewCircuitBreaker("neuraltrust-firewall", 30*time.Second, 3)

	firewallHTTPClient := &http.Client{
		Timeout: 10 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig:       &tls.Config{InsecureSkipVerify: true}, // #nosec G402
			MaxIdleConns:          100,
			MaxIdleConnsPerHost:   10,
			IdleConnTimeout:       90 * time.Second,
			DisableKeepAlives:     false,
			ResponseHeaderTimeout: 10 * time.Second,
		},
	}
	firewallClient := firewall.NewNeuralTrustFirewallClient(
		firewallHTTPClient,
		logger,
		circuitBreaker,
	)

	pluginManager := plugins.NewManager(
		cfg,
		cacheInstance,
		logger,
		bedrockClient,
		fingerprintTracker,
		embeddingRepository,
		embeddingServiceLocator,
		providerFactory,
		firewallClient,
	)

	// repository
	upstreamRepository := repository.NewUpstreamRepository(db.DB)
	serviceRepository := repository.NewServiceRepository(db.DB)
	apiKeyRepository := repository.NewApiKeyRepository(db.DB)
	gatewayRepository := repository.NewGatewayRepository(db.DB)
	ruleRepository := repository.NewForwardedRuleRepository(db.DB, logger, cacheInstance)
	sessionRepository := repository.NewSessionRepository(cacheInstance)

	// service
	upstreamFinder := appUpstream.NewFinder(upstreamRepository, cacheInstance, logger)
	serviceFinder := service.NewFinder(serviceRepository, cacheInstance, logger)
	apiKeyFinder := apikey.NewFinder(apiKeyRepository, cacheInstance, logger)
	updateGatewayCache := gateway.NewUpdateGatewayCache(cacheInstance)
	getGatewayCache := gateway.NewGetGatewayCache(cacheInstance)
	validatePlugin := plugin.NewValidatePlugin(pluginManager)
	gatewayDataFinder := gateway.NewDataFinder(gatewayRepository, ruleRepository, cacheInstance, logger)
	pluginChainValidator := plugin.NewValidatePluginChain(pluginManager, gatewayRepository)

	//policy
	policyValidator := policy.NewApiKeyPolicyValidator(ruleRepository, logger)

	// telemetry
	providerLocator := infraTelemetry.NewProviderLocator(map[string]domain.Exporter{
		kafka.ExporterName:     kafka.NewKafkaExporter(logger),
		trustlens.ExporterName: trustlens.NewTrustLensExporter(logger),
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
	updateGatewaySubscriber := subscriber.NewUpdateGatewayCacheEventSubscriber(logger, updateGatewayCache, cacheInstance, gatewayRepository)
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
		// ProxyConfig
		ForwardedHandler: handlers.NewForwardedHandler(
			logger,
			cacheInstance,
			upstreamFinder,
			serviceFinder,
			pluginManager,
			lbFactory,
			cfg,
			providerFactory,
			oauthTokenClient,
		),
		// Gateway
		CreateGatewayHandler: handlers.NewCreateGatewayHandler(
			logger,
			gatewayRepository,
			updateGatewayCache,
			pluginChainValidator,
			telemetryValidator,
		),
		ListGatewayHandler:   handlers.NewListGatewayHandler(logger, gatewayRepository, updateGatewayCache),
		GetGatewayHandler:    handlers.NewGetGatewayHandler(logger, gatewayRepository, getGatewayCache, updateGatewayCache),
		UpdateGatewayHandler: handlers.NewUpdateGatewayHandler(logger, gatewayRepository, pluginManager, redisPublisher, telemetryValidator),
		DeleteGatewayHandler: handlers.NewDeleteGatewayHandler(logger, gatewayRepository, redisPublisher),
		// Upstream
		CreateUpstreamHandler: handlers.NewCreateUpstreamHandler(logger, upstreamRepository, gatewayRepository, cacheInstance, descriptionEmbeddingCreator, cfg),
		ListUpstreamHandler:   handlers.NewListUpstreamHandler(logger, upstreamRepository, cacheInstance),
		GetUpstreamHandler:    handlers.NewGetUpstreamHandler(logger, upstreamRepository, cacheInstance, upstreamFinder),
		UpdateUpstreamHandler: handlers.NewUpdateUpstreamHandler(logger, upstreamRepository, redisPublisher, cacheInstance, descriptionEmbeddingCreator, cfg),
		DeleteUpstreamHandler: handlers.NewDeleteUpstreamHandler(logger, upstreamRepository, redisPublisher),
		// Service
		CreateServiceHandler: handlers.NewCreateServiceHandler(logger, serviceRepository, cacheInstance),
		ListServicesHandler:  handlers.NewListServicesHandler(logger, serviceRepository),
		GetServiceHandler:    handlers.NewGetServiceHandler(logger, serviceRepository, cacheInstance),
		UpdateServiceHandler: handlers.NewUpdateServiceHandler(logger, serviceRepository, redisPublisher),
		DeleteServiceHandler: handlers.NewDeleteServiceHandler(logger, serviceRepository, redisPublisher),
		// Rule
		CreateRuleHandler: handlers.NewCreateRuleHandler(logger, ruleRepository, gatewayRepository, serviceRepository, pluginChainValidator, redisPublisher),
		ListRulesHandler: handlers.NewListRulesHandler(
			logger,
			ruleRepository,
			gatewayRepository,
			serviceRepository,
			cacheInstance,
		),
		UpdateRuleHandler: handlers.NewUpdateRuleHandler(logger, ruleRepository, cacheInstance, validatePlugin, redisPublisher),
		DeleteRuleHandler: handlers.NewDeleteRuleHandler(logger, ruleRepository, cacheInstance, redisPublisher),
		// APIKey
		CreateAPIKeyHandler: handlers.NewCreateAPIKeyHandler(
			logger,
			cacheInstance,
			apiKeyRepository,
			ruleRepository,
			policyValidator,
			gatewayRepository,
		),
		ListAPIKeysPublicHandler:    handlers.NewListAPIKeysPublicHandler(logger, gatewayRepository, apiKeyRepository),
		GetAPIKeyHandler:            handlers.NewGetAPIKeyHandler(logger, cacheInstance, apiKeyRepository),
		DeleteAPIKeyHandler:         handlers.NewDeleteAPIKeyHandler(logger, apiKeyRepository, redisPublisher),
		UpdateAPIKeyPoliciesHandler: handlers.NewUpdateAPIKeyPoliciesHandler(logger, cacheInstance, apiKeyRepository, ruleRepository, policyValidator),
		// Version
		GetVersionHandler: handlers.NewGetVersionHandler(logger),
		UpdatePluginsHandler: handlers.NewUpdatePluginsHandler(
			logger,
			gatewayRepository,
			ruleRepository,
			pluginChainValidator,
			redisPublisher,
		),
		DeletePluginsHandler: handlers.NewDeletePluginsHandler(
			logger,
			gatewayRepository,
			ruleRepository,
			pluginChainValidator,
			redisPublisher,
		),
		AddPluginsHandler: handlers.NewAddPluginsHandler(
			logger,
			gatewayRepository,
			ruleRepository,
			pluginChainValidator,
			redisPublisher,
		),
		// Cache
		InvalidateCacheHandler: handlers.NewInvalidateCacheHandler(logger, cacheInstance),
	}

	container := &Container{
		Cache:              cacheInstance,
		RedisListener:      redisListener,
		HandlerTransport:   handlerTransport,
		WSHandlerTransport: wsHandlerTransport,
		CORSGlobalMiddleware: middleware.NewCORSGlobalMiddleware(
			[]string{"*"},
			[]string{"GET", "POST", "PUT", "DELETE", "OPTIONS"},
			false,
			[]string{"Content-Length", "X-Response-Time"},
			"12h",
		),
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
		RuleRepository:        ruleRepository,
		GatewayRepository:     gatewayRepository,
		FirewallClient:        firewallClient,
	}

	return container, nil
}
