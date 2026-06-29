package bootlog

const (
	MigrationsRunning          = "🗄️  running database migrations"
	MigrationsApplied          = "✅ database migrations applied"
	RedisConnected             = "📡 redis connected successfully"
	CacheListenerStarted       = "📻 cache event listener started"
	RedisPubSubConnected       = "📡 redis pubsub connected"
	RedisPubSubShuttingDown    = "📴 redis pubsub listener shutting down"
	CatalogSyncCompleted       = "📚 catalog sync completed"
	MetricsWorkerStarted       = "📊 metrics worker started"
	MetricsWorkersShuttingDown = "📉 shutting down metrics workers"
	MetricsWorkersStopped      = "✅ metrics workers stopped"
)

func rolePrefix(name string) string {
	switch name {
	case "admin":
		return "🎛️  "
	case "proxy":
		return "⚡ "
	case "mcp":
		return "🔌 "
	default:
		return "🌐 "
	}
}

func HTTPStart(name string) string {
	return rolePrefix(name) + "HTTP server starting"
}

func HTTPShutdown(name string) string {
	return rolePrefix(name) + "shutting down HTTP server"
}

func HTTPStopped(name string) string {
	return rolePrefix(name) + "HTTP server stopped"
}

func ServerShutdown(name string) string {
	return rolePrefix(name) + "shutting down server"
}

func ServerStoppedGracefully(name string) string {
	return rolePrefix(name) + "server stopped gracefully"
}
