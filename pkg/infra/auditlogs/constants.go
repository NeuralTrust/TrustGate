package auditlogs

const (
	EventTypeGatewayCreated = "gateway.created"
	EventTypeGatewayUpdated = "gateway.updated"
	EventTypeGatewayDeleted = "gateway.deleted"

	EventTypeUpstreamCreated = "upstream.created"
	EventTypeUpstreamUpdated = "upstream.updated"
	EventTypeUpstreamDeleted = "upstream.deleted"

	EventTypeRuleCreated = "rule.created"
	EventTypeRuleUpdated = "rule.updated"
	EventTypeRuleDeleted = "rule.deleted"

	EventTypeAPIKeyCreated         = "apikey.created"
	EventTypeAPIKeyDeleted         = "apikey.deleted"
	EventTypeAPIKeyPoliciesUpdated = "apikey.policies_updated"

	EventTypePluginsAdded   = "plugins.added"
	EventTypePluginsUpdated = "plugins.updated"
	EventTypePluginsDeleted = "plugins.deleted"
)

const (
	CategoryRunTimeSecurity = "runtime_security"
)

const (
	StatusSuccess = "success"
)

const (
	TargetTypeGateway  = "gateway"
	TargetTypeUpstream = "upstream"
	TargetTypeRule     = "rule"
	TargetTypeAPIKey   = "apikey"
)
