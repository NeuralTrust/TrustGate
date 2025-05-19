package plugins

import (
	"github.com/NeuralTrust/TrustGate/pkg/types"
	"github.com/go-redis/redis/v8"
	"github.com/google/uuid"
	"github.com/sirupsen/logrus"
)

var PluginList = []PluginDefinition{
	{
		UUID:          GeneratePluginUUID("bedrock_guardrail"),
		Name:          "bedrock_guardrail",
		Description:   "Integrates with AWS Bedrock Guardrails to filter content based on guardrail policies",
		AllowedStages: []types.Stage{types.PreRequest},
	},
	{
		UUID:          GeneratePluginUUID("code_sanitation"),
		Name:          "code_sanitation",
		Description:   "Detects and sanitizes potentially malicious code in requests",
		AllowedStages: []types.Stage{types.PreRequest},
	},
	{
		UUID:          GeneratePluginUUID("contextual_security"),
		Name:          "contextual_security",
		Description:   "Analyzes request context for security threats",
		AllowedStages: []types.Stage{types.PreRequest},
	},
	{
		UUID:          GeneratePluginUUID("cors"),
		Name:          "cors",
		Description:   "Handles Cross-Origin Resource Sharing (CORS) requests",
		AllowedStages: []types.Stage{types.PreRequest, types.PostResponse},
	},
	{
		UUID:          GeneratePluginUUID("data_masking"),
		Name:          "data_masking",
		Description:   "Masks sensitive data in requests and responses",
		AllowedStages: []types.Stage{types.PreRequest, types.PostResponse},
	},
	{
		UUID:          GeneratePluginUUID("external_api"),
		Name:          "external_api",
		Description:   "Integrates with external APIs for additional processing",
		AllowedStages: []types.Stage{types.PreRequest, types.PostResponse},
	},
	{
		UUID:          GeneratePluginUUID("injection_protection"),
		Name:          "injection_protection",
		Description:   "Protects against various injection attacks",
		AllowedStages: []types.Stage{types.PreRequest},
	},
	{
		UUID:          GeneratePluginUUID("neuraltrust_guardrail"),
		Name:          "neuraltrust_guardrail",
		Description:   "Applies NeuralTrust's guardrails to filter content",
		AllowedStages: []types.Stage{types.PreRequest},
	},
	{
		UUID:          GeneratePluginUUID("neuraltrust_moderation"),
		Name:          "neuraltrust_moderation",
		Description:   "Applies NeuralTrust's moderation to filter content",
		AllowedStages: []types.Stage{types.PreRequest},
	},
	{
		UUID:          GeneratePluginUUID("toxicity_neuraltrust"),
		Name:          "toxicity_neuraltrust",
		Description:   "Applies NeuralTrust's toxicity to filter content",
		AllowedStages: []types.Stage{types.PreRequest},
	},
	{
		UUID:          GeneratePluginUUID("rate_limiter"),
		Name:          "rate_limiter",
		Description:   "Limits request rates to prevent abuse",
		AllowedStages: []types.Stage{types.PreRequest},
	},
	{
		UUID:          GeneratePluginUUID("request_size_limiter"),
		Name:          "request_size_limiter",
		Description:   "Limits the size of incoming requests",
		AllowedStages: []types.Stage{types.PreRequest},
	},
	{
		UUID:          GeneratePluginUUID("token_rate_limiter"),
		Name:          "token_rate_limiter",
		Description:   "Limits token usage rates",
		AllowedStages: []types.Stage{types.PreRequest},
	},
	{
		UUID:          GeneratePluginUUID("toxicity_azure"),
		Name:          "toxicity_azure",
		Description:   "Detects toxic content using Azure services",
		AllowedStages: []types.Stage{types.PreRequest, types.PostResponse},
	},
	{
		UUID:          GeneratePluginUUID("toxicity_openai"),
		Name:          "toxicity_openai",
		Description:   "Detects toxic content using OpenAI services",
		AllowedStages: []types.Stage{types.PreRequest, types.PostResponse},
	},
}

// GeneratePluginUUID creates a deterministic UUID from a plugin ID
func GeneratePluginUUID(pluginID string) string {
	// Create a namespace UUID (using a fixed UUID for consistency)
	namespace := uuid.MustParse("6ba7b810-9dad-11d1-80b4-00c04fd430c8")
	// Generate a UUID based on the plugin ID
	id := uuid.NewSHA1(namespace, []byte(pluginID))
	return id.String()
}

type PluginDefinition struct {
	UUID          string        `json:"id"`
	Name          string        `json:"name"`
	Description   string        `json:"description"`
	AllowedStages []types.Stage `json:"allowed_stages"`
}

// PluginContext holds the context for plugin execution
type PluginContext struct {
	Config   types.PluginConfig
	Redis    *redis.Client
	Logger   *logrus.Logger
	Metadata map[string]interface{}
}

// BasePlugin provides common functionality for all plugins
type BasePlugin struct {
	name string
}

func (p *BasePlugin) GetName() string {
	return p.name
}
