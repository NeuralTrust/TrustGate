package dependency_container

import (
	"crypto/tls"
	"fmt"
	"net/http"
	"reflect"
	"time"

	ruledomain "github.com/NeuralTrust/TrustGate/pkg/domain/forwarding_rule"
	"github.com/NeuralTrust/TrustGate/pkg/infra/auditlogs"
	"github.com/NeuralTrust/TrustGate/pkg/infra/auth/jwt"
	"github.com/NeuralTrust/TrustGate/pkg/infra/cache/channel"
	"github.com/NeuralTrust/TrustGate/pkg/infra/database"
	"github.com/NeuralTrust/TrustGate/pkg/infra/firewall"
	"github.com/NeuralTrust/TrustGate/pkg/infra/policy"
	providersFactory "github.com/NeuralTrust/TrustGate/pkg/infra/providers/factory"
	"github.com/NeuralTrust/TrustGate/pkg/infra/telemetry/trustlens"
	middleware "github.com/NeuralTrust/TrustGate/pkg/server/middleware"
	audit "github.com/NeuralTrust/audit-sdk-go"
	"github.com/valyala/fasthttp"

	"github.com/NeuralTrust/TrustGate/pkg/app/apikey"
	"github.com/NeuralTrust/TrustGate/pkg/app/gateway"
	"github.com/NeuralTrust/TrustGate/pkg/app/plugin"
	"github.com/NeuralTrust/TrustGate/pkg/app/routing"
	"github.com/NeuralTrust/TrustGate/pkg/app/service"
	"github.com/NeuralTrust/TrustGate/pkg/app/telemetry"
	appUpstream "github.com/NeuralTrust/TrustGate/pkg/app/upstream"
	"github.com/NeuralTrust/TrustGate/pkg/infra/cache"

	"github.com/NeuralTrust/TrustGate/pkg/config"
	domainEmbedding "github.com/NeuralTrust/TrustGate/pkg/domain/embedding"
	domainGateway "github.com/NeuralTrust/TrustGate/pkg/domain/gateway"
	domainApikey "github.com/NeuralTrust/TrustGate/pkg/domain/iam/apikey"
	domainService "github.com/NeuralTrust/TrustGate/pkg/domain/service"
	domainSession "github.com/NeuralTrust/TrustGate/pkg/domain/session"
	domainUpstream "github.com/NeuralTrust/TrustGate/pkg/domain/upstream"
	handlers "github.com/NeuralTrust/TrustGate/pkg/handlers/http"
	wsHandlers "github.com/NeuralTrust/TrustGate/pkg/handlers/websocket"
	"github.com/NeuralTrust/TrustGate/pkg/infra/auth/oauth"
	"github.com/NeuralTrust/TrustGate/pkg/infra/bedrock"
	"github.com/NeuralTrust/TrustGate/pkg/infra/cache/event"
	"github.com/NeuralTrust/TrustGate/pkg/infra/cache/subscriber"
	"github.com/NeuralTrust/TrustGate/pkg/infra/embedding/factory"
	"github.com/NeuralTrust/TrustGate/pkg/infra/fingerprint"
	"github.com/NeuralTrust/TrustGate/pkg/infra/loadbalancer"
	"github.com/NeuralTrust/TrustGate/pkg/infra/metrics"
	"github.com/NeuralTrust/TrustGate/pkg/infra/plugins"
	"github.com/NeuralTrust/TrustGate/pkg/infra/repository"
	infraTelemetry "github.com/NeuralTrust/TrustGate/pkg/infra/telemetry"
	"github.com/NeuralTrust/TrustGate/pkg/infra/telemetry/kafka"
	infraTLS "github.com/NeuralTrust/TrustGate/pkg/infra/tls"
	"github.com/sirupsen/logrus"
)

type Container struct {
	Cache                       cache.Client
	BedrockClient               bedrock.Client
	PluginManager               plugins.Manager
	HandlerTransport            handlers.HandlerTransport
	WSHandlerTransport          wsHandlers.HandlerTransport
	RedisListener               cache.EventListener
	RedisPublisher              cache.EventPublisher
	PanicRecoverMiddleware      middleware.Middleware
	AuthMiddleware              middleware.Middleware
	CORSGlobalMiddleware        middleware.Middleware
	AdminAuthMiddleware         middleware.Middleware
	MetricsMiddleware           middleware.Middleware
	PluginMiddleware            middleware.Middleware
	FingerPrintMiddleware       middleware.Middleware
	SecurityMiddleware          middleware.Middleware
	WebSocketMiddleware         middleware.Middleware
	SessionMiddleware           middleware.Middleware
	ApiKeyRepository            domainApikey.Repository
	EmbeddingRepository         domainEmbedding.Repository
	SessionRepository           domainSession.Repository
	FingerprintTracker          fingerprint.Tracker
	PluginChainValidator        plugin.ValidatePluginChain
	MetricsWorker               metrics.Worker
	RedisIndexCreator           cache.RedisIndexCreator
	JWTManager                  jwt.Manager
	RuleRepository              ruledomain.Repository
	GatewayRepository           domainGateway.Repository
	UpstreamRepository          domainUpstream.Repository
	ServiceRepository           domainService.Repository
	FirewallFactory             firewall.ClientFactory
	TelemetryExporterLocator    *infraTelemetry.ExporterLocator
	TelemetryExporterValidator  telemetry.ExportersValidator
	GatewayCreator              gateway.Creator
	GatewayDeleter              gateway.Deleter
	DescriptionEmbeddingCreator appUpstream.DescriptionEmbeddingCreator
	AuditLogsService            auditlogs.Service
}

type ContainerDI struct {
	Cfg                           *config.Config
	Logger                        *logrus.Logger
	DB                            *database.DB
	EventsRegistry                map[string]reflect.Type
	InitializeMemoryCache         func(cacheInstance cache.Client)
	InitializeLoadBalancerFactory loadbalancer.FactoryInitializer
	InitializeCachePublisher      cache.RedisPublisherInitializer
	EventsChannel                 channel.Channel
}

func NewContainer(di ContainerDI) (*Container, error) {
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
		Host:     di.Cfg.Redis.Host,
		Port:     di.Cfg.Redis.Port,
		Password: di.Cfg.Redis.Password,
		DB:       di.Cfg.Redis.DB,
		TLS:      di.Cfg.Redis.TLS,
	}
	cacheInstance, err := cache.NewClient(cacheConfig, di.Logger)
	if err != nil {
		return nil, fmt.Errorf("failed to initialize cache: %v", err)
	}

	di.InitializeMemoryCache(cacheInstance)
	redisPublisher := di.InitializeCachePublisher(cacheInstance, di.EventsChannel)

	redisListener := cache.NewRedisEventListener(di.Logger, cacheInstance, di.EventsRegistry)

	redisIndexCreator := cache.NewRedisIndexCreator(cacheInstance.RedisClient(), di.Logger)

	bedrockClient := bedrock.NewClient()

	// embedding services
	embeddingServiceLocator := factory.NewServiceLocator(di.Logger, httpClient)
	embeddingRepository := repository.NewRedisEmbeddingRepository(cacheInstance)
	descriptionEmbeddingCreator := appUpstream.NewDescriptionEmbeddingCreator(embeddingServiceLocator, embeddingRepository, di.Logger)

	providerFactory := providersFactory.NewProviderLocator(httpClient)

	oauthTokenClient := oauth.NewTokenClient()

	fingerprintTracker := fingerprint.NewFingerPrintTracker(cacheInstance)

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
	neuralTrustFirewallClient := firewall.NewNeuralTrustFirewallClient(
		di.Logger,
		firewall.WithHTTPClient(firewallHTTPClient),
	)
	openAIFirewallClient := firewall.NewOpenAIFirewallClient(di.Logger)
	firewallFactory := firewall.NewClientFactory(neuralTrustFirewallClient, openAIFirewallClient)

	pluginManager := plugins.NewManager(
		di.Logger,
		cacheInstance,
		plugins.WithBedrockClient(bedrockClient),
		plugins.WithFingerprintTracker(fingerprintTracker),
		plugins.WithEmbeddingRepo(embeddingRepository),
		plugins.WithServiceLocator(embeddingServiceLocator),
		plugins.WithProviderLocator(providerFactory),
		plugins.WithFirewallFactory(firewallFactory),
	)

	// repository
	upstreamRepository := repository.NewUpstreamRepository(di.DB.DB)
	serviceRepository := repository.NewServiceRepository(di.DB.DB)
	apiKeyRepository := repository.NewApiKeyRepository(di.DB.DB)
	gatewayRepository := repository.NewGatewayRepository(di.DB.DB)
	ruleRepository := repository.NewForwardedRuleRepository(di.DB.DB, di.Logger, cacheInstance)
	sessionRepository := repository.NewSessionRepository(cacheInstance)

	// service
	upstreamFinder := appUpstream.NewFinder(upstreamRepository, cacheInstance, di.Logger)
	serviceFinder := service.NewFinder(serviceRepository, cacheInstance, di.Logger)
	apiKeyFinder := apikey.NewFinder(apiKeyRepository, cacheInstance, di.Logger)
	updateGatewayCache := gateway.NewUpdateGatewayCache(cacheInstance)
	getGatewayCache := gateway.NewGetGatewayCache(cacheInstance)
	validatePlugin := plugin.NewValidatePlugin(pluginManager)
	gatewayDataFinder := gateway.NewDataFinder(gatewayRepository, ruleRepository, cacheInstance, di.Logger)
	ruleMatcher := routing.NewRuleMatcher()
	pluginChainValidator := plugin.NewValidatePluginChain(pluginManager, gatewayRepository)

	//policy
	policyValidator := policy.NewApiKeyPolicyValidator(ruleRepository, di.Logger)

	// telemetry
	providerLocator := infraTelemetry.NewProviderLocator(
		infraTelemetry.WithExporter(kafka.ExporterName, kafka.NewKafkaExporter(di.Logger)),
		infraTelemetry.WithExporter(trustlens.ExporterName, trustlens.NewTrustLensExporter(di.Logger)),
	)
	telemetryBuilder := telemetry.NewTelemetryExportersBuilder(providerLocator)
	telemetryValidator := telemetry.NewTelemetryExportersValidator(providerLocator)

	// TLS cert repository and writer
	tlsCertRepository := repository.NewTLSCertRepository(di.DB.DB)
	tlsCertWriter := infraTLS.NewCertWriter(
		di.Logger,
		tlsCertRepository,
		infraTLS.WithBasePath(di.Cfg.TLS.CertsBasePath),
	)

	// gateway creator
	gatewayCreator := gateway.NewCreator(
		di.Logger,
		gatewayRepository,
		updateGatewayCache,
		pluginChainValidator,
		telemetryValidator,
		tlsCertWriter,
	)

	// gateway deleter
	gatewayDeleter := gateway.NewDeleter(
		di.Logger,
		gatewayRepository,
		redisPublisher,
		tlsCertWriter,
	)

	// subscribers
	deleteGatewaySubscriber := subscriber.NewDeleteGatewayCacheEventSubscriber(di.Logger, cacheInstance)
	deleteRulesSubscriber := subscriber.NewDeleteRulesEventSubscriber(di.Logger, cacheInstance)
	deleteServiceSubscriber := subscriber.NewDeleteServiceCacheEventSubscriber(di.Logger, cacheInstance)
	deleteUpstreamSubscriber := subscriber.NewDeleteUpstreamCacheEventSubscriber(di.Logger, cacheInstance)
	deleteApiKeySubscriber := subscriber.NewDeleteApiKeyCacheEventSubscriber(di.Logger, cacheInstance)
	updateGatewaySubscriber := subscriber.NewUpdateGatewayCacheEventSubscriber(di.Logger, updateGatewayCache, cacheInstance, gatewayRepository)
	updateUpstreamSubscriber := subscriber.NewUpdateUpstreamCacheEventSubscriber(di.Logger, cacheInstance, upstreamRepository)
	updateServiceSubscriber := subscriber.NewUpdateServiceCacheEventSubscriber(di.Logger, cacheInstance, serviceRepository)

	cache.RegisterEventSubscriber[event.DeleteGatewayCacheEvent](redisListener, deleteGatewaySubscriber)
	cache.RegisterEventSubscriber[event.DeleteRulesCacheEvent](redisListener, deleteRulesSubscriber)
	cache.RegisterEventSubscriber[event.DeleteServiceCacheEvent](redisListener, deleteServiceSubscriber)
	cache.RegisterEventSubscriber[event.DeleteUpstreamCacheEvent](redisListener, deleteUpstreamSubscriber)
	cache.RegisterEventSubscriber[event.DeleteKeyCacheEvent](redisListener, deleteApiKeySubscriber)
	cache.RegisterEventSubscriber[event.UpdateGatewayCacheEvent](redisListener, updateGatewaySubscriber)
	cache.RegisterEventSubscriber[event.UpdateUpstreamCacheEvent](redisListener, updateUpstreamSubscriber)
	cache.RegisterEventSubscriber[event.UpdateServiceCacheEvent](redisListener, updateServiceSubscriber)

	lbFactory := di.InitializeLoadBalancerFactory(embeddingRepository, embeddingServiceLocator)

	metricsWorker := metrics.NewWorker(di.Logger, telemetryBuilder)

	jwtManager := jwt.NewJwtManager(&di.Cfg.Server)

	// Audit logs service
	var auditClient audit.Client
	if di.Cfg.AuditLogs.Enabled {
		var err error
		auditClient, err = audit.New(&audit.Config{
			Brokers:              di.Cfg.AuditLogs.KafkaBrokers,
			AuditEventsTopic:     di.Cfg.AuditLogs.AuditEventsTopic,
			AuditLogsIngestTopic: di.Cfg.AuditLogs.AuditLogsIngestTopic,
			TopicAutoCreate:      di.Cfg.AuditLogs.TopicAutoCreate,
		})
		if err != nil {
			di.Logger.WithError(err).Warn("failed to initialize audit client, audit logs will be disabled")
			auditClient = nil
		}
	}
	auditLogsService := auditlogs.NewService(auditClient, di.Logger, di.Cfg.AuditLogs.Enabled && auditClient != nil)

	// WebSocket handler transport
	wsHandlerTransport := &wsHandlers.HandlerTransportDTO{
		ForwardedHandler: wsHandlers.NewWebsocketHandler(
			di.Cfg,
			di.Logger,
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
		ForwardedHandler: handlers.NewForwardedHandler(handlers.ForwardedHandlerDeps{
			Logger:              di.Logger,
			Cache:               cacheInstance,
			UpstreamFinder:      upstreamFinder,
			ServiceFinder:       serviceFinder,
			PluginManager:       pluginManager,
			LoadBalancerFactory: lbFactory,
			Cfg:                 di.Cfg,
			ProviderLocator:     providerFactory,
			TokenClient:         oauthTokenClient,
			RuleMatcher:         ruleMatcher,
			TLSCertWriter:       tlsCertWriter,
		}),
		// Gateway
		CreateGatewayHandler: handlers.NewCreateGatewayHandler(
			di.Logger,
			gatewayCreator,
			auditLogsService,
		),
		ListGatewayHandler: handlers.NewListGatewayHandler(di.Logger, gatewayRepository, updateGatewayCache),
		GetGatewayHandler:  handlers.NewGetGatewayHandler(di.Logger, gatewayRepository, getGatewayCache, updateGatewayCache),
		UpdateGatewayHandler: handlers.NewUpdateGatewayHandler(handlers.UpdateGatewayHandlerDeps{
			Logger:                      di.Logger,
			Repo:                        gatewayRepository,
			PluginManager:               pluginManager,
			Publisher:                   redisPublisher,
			TelemetryProvidersValidator: telemetryValidator,
			TLSCertWriter:               tlsCertWriter,
			AuditService:                auditLogsService,
		}),
		DeleteGatewayHandler: handlers.NewDeleteGatewayHandler(di.Logger, gatewayDeleter, auditLogsService),
		// Upstream
		CreateUpstreamHandler: handlers.NewCreateUpstreamHandler(handlers.CreateUpstreamHandlerDeps{
			Logger:                      di.Logger,
			Repo:                        upstreamRepository,
			GatewayRepo:                 gatewayRepository,
			Cache:                       cacheInstance,
			DescriptionEmbeddingCreator: descriptionEmbeddingCreator,
			Cfg:                         di.Cfg,
			AuditService:                auditLogsService,
		}),
		ListUpstreamHandler: handlers.NewListUpstreamHandler(di.Logger, upstreamRepository, cacheInstance),
		GetUpstreamHandler:  handlers.NewGetUpstreamHandler(di.Logger, upstreamRepository, cacheInstance, upstreamFinder),
		UpdateUpstreamHandler: handlers.NewUpdateUpstreamHandler(handlers.UpdateUpstreamHandlerDeps{
			Logger:                      di.Logger,
			Repo:                        upstreamRepository,
			Publisher:                   redisPublisher,
			Cache:                       cacheInstance,
			DescriptionEmbeddingCreator: descriptionEmbeddingCreator,
			Cfg:                         di.Cfg,
			AuditService:                auditLogsService,
		}),
		DeleteUpstreamHandler: handlers.NewDeleteUpstreamHandler(di.Logger, upstreamRepository, redisPublisher, auditLogsService),
		// Service
		CreateServiceHandler: handlers.NewCreateServiceHandler(di.Logger, serviceRepository, cacheInstance, auditLogsService),
		ListServicesHandler:  handlers.NewListServicesHandler(di.Logger, serviceRepository),
		GetServiceHandler:    handlers.NewGetServiceHandler(di.Logger, serviceRepository, cacheInstance),
		UpdateServiceHandler: handlers.NewUpdateServiceHandler(di.Logger, serviceRepository, redisPublisher, auditLogsService),
		DeleteServiceHandler: handlers.NewDeleteServiceHandler(di.Logger, serviceRepository, redisPublisher, auditLogsService),
		// Rule
		CreateRuleHandler: handlers.NewCreateRuleHandler(handlers.CreateRuleHandlerDeps{
			Logger:               di.Logger,
			Repo:                 ruleRepository,
			GatewayRepo:          gatewayRepository,
			ServiceRepo:          serviceRepository,
			PluginChainValidator: pluginChainValidator,
			Publisher:            redisPublisher,
			RuleMatcher:          ruleMatcher,
			AuditService:         auditLogsService,
		}),
		ListRulesHandler: handlers.NewListRulesHandler(handlers.ListRulesHandlerDeps{
			Logger:      di.Logger,
			RuleRepo:    ruleRepository,
			GatewayRepo: gatewayRepository,
			ServiceRepo: serviceRepository,
			Cache:       cacheInstance,
		}),
		UpdateRuleHandler: handlers.NewUpdateRuleHandler(handlers.UpdateRuleHandlerDeps{
			Logger:                di.Logger,
			Repo:                  ruleRepository,
			Cache:                 cacheInstance,
			ValidatePlugin:        validatePlugin,
			InvalidationPublisher: redisPublisher,
			RuleMatcher:           ruleMatcher,
			AuditService:          auditLogsService,
		}),
		DeleteRuleHandler: handlers.NewDeleteRuleHandler(handlers.DeleteRuleHandlerDeps{
			Logger:       di.Logger,
			Repo:         ruleRepository,
			Cache:        cacheInstance,
			Publisher:    redisPublisher,
			AuditService: auditLogsService,
		}),
		// APIKey
		CreateAPIKeyHandler: handlers.NewCreateAPIKeyHandler(handlers.CreateAPIKeyHandlerDeps{
			Logger:          di.Logger,
			Cache:           cacheInstance,
			ApiKeyRepo:      apiKeyRepository,
			RuleRepo:        ruleRepository,
			PolicyValidator: policyValidator,
			GatewayRepo:     gatewayRepository,
			AuditService:    auditLogsService,
		}),
		ListAPIKeysPublicHandler: handlers.NewListAPIKeysPublicHandler(di.Logger, gatewayRepository, apiKeyRepository),
		GetAPIKeyHandler:         handlers.NewGetAPIKeyHandler(di.Logger, cacheInstance, apiKeyRepository),
		DeleteAPIKeyHandler:      handlers.NewDeleteAPIKeyHandler(di.Logger, apiKeyRepository, redisPublisher, auditLogsService),
		UpdateAPIKeyPoliciesHandler: handlers.NewUpdateAPIKeyPoliciesHandler(handlers.UpdateAPIKeyPoliciesHandlerDeps{
			Logger:          di.Logger,
			Cache:           cacheInstance,
			ApiKeyRepo:      apiKeyRepository,
			RuleRepo:        ruleRepository,
			PolicyValidator: policyValidator,
			AuditService:    auditLogsService,
		}),
		// Version
		GetVersionHandler: handlers.NewGetVersionHandler(di.Logger),
		UpdatePluginsHandler: handlers.NewUpdatePluginsHandler(handlers.UpdatePluginsHandlerDeps{
			Logger:               di.Logger,
			GatewayRepo:          gatewayRepository,
			RuleRepo:             ruleRepository,
			PluginChainValidator: pluginChainValidator,
			Publisher:            redisPublisher,
			AuditService:         auditLogsService,
		}),
		DeletePluginsHandler: handlers.NewDeletePluginsHandler(handlers.DeletePluginsHandlerDeps{
			Logger:               di.Logger,
			GatewayRepo:          gatewayRepository,
			RuleRepo:             ruleRepository,
			PluginChainValidator: pluginChainValidator,
			Publisher:            redisPublisher,
			AuditService:         auditLogsService,
		}),
		AddPluginsHandler: handlers.NewAddPluginsHandler(handlers.AddPluginsHandlerDeps{
			Logger:               di.Logger,
			GatewayRepo:          gatewayRepository,
			RuleRepo:             ruleRepository,
			PluginChainValidator: pluginChainValidator,
			Publisher:            redisPublisher,
			AuditService:         auditLogsService,
		}),
		// Cache
		InvalidateCacheHandler: handlers.NewInvalidateCacheHandler(di.Logger, cacheInstance),
	}

	container := &Container{
		Cache:                  cacheInstance,
		RedisListener:          redisListener,
		RedisPublisher:         redisPublisher,
		HandlerTransport:       handlerTransport,
		WSHandlerTransport:     wsHandlerTransport,
		PanicRecoverMiddleware: middleware.NewPanicRecoverMiddleware(di.Logger),
		CORSGlobalMiddleware: middleware.NewCORSGlobalMiddleware(
			[]string{"*"},
			[]string{"GET", "POST", "PUT", "DELETE", "OPTIONS"},
			false,
			[]string{"Content-Length", "X-Response-Time"},
			"12h",
		),
		AuthMiddleware:              middleware.NewAuthMiddleware(di.Logger, apiKeyFinder, gatewayDataFinder, ruleMatcher),
		AdminAuthMiddleware:         middleware.NewAdminAuthMiddleware(di.Logger, jwtManager),
		MetricsMiddleware:           middleware.NewMetricsMiddleware(di.Logger, metricsWorker),
		PluginMiddleware:            middleware.NewPluginChainMiddleware(pluginManager, di.Logger),
		FingerPrintMiddleware:       middleware.NewFingerPrintMiddleware(di.Logger, fingerprintTracker),
		SecurityMiddleware:          middleware.NewSecurityMiddleware(di.Logger),
		WebSocketMiddleware:         middleware.NewWebsocketMiddleware(di.Cfg, di.Logger),
		SessionMiddleware:           middleware.NewSessionMiddleware(di.Logger, sessionRepository),
		ApiKeyRepository:            apiKeyRepository,
		EmbeddingRepository:         embeddingRepository,
		SessionRepository:           sessionRepository,
		PluginManager:               pluginManager,
		BedrockClient:               bedrockClient,
		FingerprintTracker:          fingerprintTracker,
		PluginChainValidator:        pluginChainValidator,
		MetricsWorker:               metricsWorker,
		RedisIndexCreator:           redisIndexCreator,
		JWTManager:                  jwtManager,
		RuleRepository:              ruleRepository,
		GatewayRepository:           gatewayRepository,
		UpstreamRepository:          upstreamRepository,
		ServiceRepository:           serviceRepository,
		FirewallFactory:             firewallFactory,
		TelemetryExporterLocator:    providerLocator,
		TelemetryExporterValidator:  telemetryValidator,
		GatewayCreator:              gatewayCreator,
		GatewayDeleter:              gatewayDeleter,
		DescriptionEmbeddingCreator: descriptionEmbeddingCreator,
		AuditLogsService:            auditLogsService,
	}

	return container, nil
}
