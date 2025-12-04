package common

import "time"

const (
	ServiceCacheTTL      = 5 * time.Minute
	ApiKeyCacheTTL       = 5 * time.Minute
	UpstreamCacheTTL     = 5 * time.Minute
	GatewayCacheTTL      = 1 * time.Hour
	RulesCacheTTL        = 5 * time.Minute
	PluginCacheTTL       = 30 * time.Minute
	LoadBalancerCacheTTL = 5 * time.Minute

	ConversationIDHeader = "X-Conversation-Id"
	InteractionIDHeader  = "X-Interaction-Id"
	TrustgateAuthHeader  = "X-TG-API-Key"

	SemanticStrategyName = "semantic"

	NeuralTrustJailbreakIndexName = "neuraltrust_jailbreak"
)
