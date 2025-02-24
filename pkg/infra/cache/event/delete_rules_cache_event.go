package event

type DeleteRulesCacheEvent struct {
	GatewayID string `json:"gateway_id"`
	RuleID    string `json:"rule_id"`
}

func (e DeleteRulesCacheEvent) Type() string {
	return DeleteRulesCacheEventType
}
