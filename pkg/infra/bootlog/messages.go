// Copyright 2026 NeuralTrust
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package bootlog

const (
	MigrationsRunning          = "🗄️  running database migrations"
	MigrationsApplied          = "✅ database migrations applied"
	DatabaseClosing            = "🗄️  closing database connection"
	RedisConnected             = "📡 redis connected successfully"
	CacheListenerStarted       = "📻 cache event listener started"
	RedisPubSubConnected       = "📡 redis pubsub connected"
	RedisPubSubShuttingDown    = "📴 redis pubsub listener shutting down"
	CatalogSyncCompleted       = "📚 catalog sync completed"
	ConfigSyncWorkerStarted    = "🔄 config sync worker started"
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
