package event

import "reflect"

type Event interface {
	Type() string
}

var (
	DeleteRulesCacheEventType   = "DeleteRulesCacheEvent"
	DeleteGatewayCacheEventType = "DeleteGatewayCacheEvent"
)

var EventRegistry = map[string]reflect.Type{
	DeleteRulesCacheEventType:   reflect.TypeOf(DeleteRulesCacheEvent{}),
	DeleteGatewayCacheEventType: reflect.TypeOf(DeleteGatewayCacheEvent{}),
}
