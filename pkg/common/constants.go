package common

const (
	ConversationIDHeader = "X-Conversation-Id"
	InteractionIDHeader  = "X-Interaction-Id"
	TrustgateAuthHeader  = "X-TG-API-Key"

	SemanticStrategyName = "semantic"
)

var FallbackAPIKeyHeaders = []string{
	"x-goog-api-key",
	"x-api-key",
	"Authorization",
}
