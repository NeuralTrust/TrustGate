package prometheus

import (
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/collectors"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

var registry = prometheus.NewRegistry()

var registerer = prometheus.WrapRegistererWith(nil, registry)

var (
	// Common labels for all metrics
	commonLabels = []string{"gateway_id"}

	// Additional labels for detailed metrics
	routeLabels = []string{"service", "route"}

	// Latency buckets in milliseconds (similar to Kong's approach)
	latencyBuckets = []float64{
		5, 10, 25, // Fast responses (5-25ms)
		50, 100, 250, // Normal responses (50-250ms)
		500, 1000, 2500, // Slower responses (500ms-2.5s)
		5000, 10000, 30000, // Very slow/timeout (5s-30s)
	}

	GatewayRequestTotal = promauto.With(registerer).NewCounterVec(
		prometheus.CounterOpts{
			Name: "trustgate_requests_total",
			Help: "Total number of requests processed",
		},
		append(commonLabels, "method", "status"),
	)

	GatewayRequestLatency = promauto.With(registerer).NewHistogramVec(
		prometheus.HistogramOpts{
			Name:    "trustgate_latency_ms",
			Help:    "Request latency in milliseconds",
			Buckets: latencyBuckets,
		},
		append(commonLabels, "type"), // type can be "total" or "upstream"
	)

	GatewayDetailedLatency = promauto.With(registerer).NewHistogramVec(
		prometheus.HistogramOpts{
			Name:    "trustgate_detailed_latency_ms",
			Help:    "Detailed request latency by service and route",
			Buckets: latencyBuckets,
		},
		append(commonLabels, routeLabels...),
	)

	GatewayConnections = promauto.With(registerer).NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "trustgate_connections",
			Help: "Number of active connections",
		},
		append(commonLabels, "state"),
	)

	GatewayUpstreamLatency = promauto.With(registerer).NewHistogramVec(
		prometheus.HistogramOpts{
			Name:    "trustgate_upstream_latency_ms",
			Help:    "Upstream service latency in milliseconds",
			Buckets: latencyBuckets,
		},
		append(commonLabels, routeLabels...), // Use existing label definitions
	)
)

type MetricsConfig struct {
	EnableLatency         bool // Basic latency metrics
	EnableUpstreamLatency bool // Detailed upstream latency (higher cardinality)
	EnableBandwidth       bool // Bandwidth metrics (can be high volume)
	EnableConnections     bool // Connection tracking (can impact performance)
	EnablePerRoute        bool // Per-route metrics (high cardinality)
}

func DefaultMetricsConfig() MetricsConfig {
	return MetricsConfig{
		EnableLatency:         true,  // Basic latency is usually safe
		EnableUpstreamLatency: false, // Disabled by default (high cardinality)
		EnableBandwidth:       false, // Disabled by default (high volume)
		EnableConnections:     false, // Disabled by default (performance impact)
		EnablePerRoute:        false, // Disabled by default (high cardinality)
	}
}

var Config MetricsConfig

func Initialize(cfg MetricsConfig) {
	Config = cfg
	registry.MustRegister(
		collectors.NewProcessCollector(collectors.ProcessCollectorOpts{}),
	)

	prometheus.DefaultRegisterer = registry
	prometheus.DefaultGatherer = registry
}
