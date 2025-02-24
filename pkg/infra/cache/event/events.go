package event

import "reflect"

type Event interface {
	Type() string
}

var (
	DeleteRulesCacheEventType    = "DeleteRulesCacheEvent"
	DeleteGatewayCacheEventType  = "DeleteGatewayCacheEvent"
	DeleteServiceCacheEventType  = "DeleteServiceCacheEvent"
	DeleteUpstreamCacheEventType = "DeleteUpstreamCacheEvent"
	DeleteApiKeyCacheEventType   = "DeleteApiKeyCacheEvent"
)

var Registry = map[string]reflect.Type{
	DeleteRulesCacheEventType:    reflect.TypeOf(DeleteRulesCacheEvent{}),
	DeleteGatewayCacheEventType:  reflect.TypeOf(DeleteGatewayCacheEvent{}),
	DeleteServiceCacheEventType:  reflect.TypeOf(DeleteServiceCacheEvent{}),
	DeleteUpstreamCacheEventType: reflect.TypeOf(DeleteUpstreamCacheEvent{}),
	DeleteApiKeyCacheEventType:   reflect.TypeOf(DeleteApiKeyCacheEvent{}),
}
