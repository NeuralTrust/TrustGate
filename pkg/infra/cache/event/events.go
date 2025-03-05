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
	DeleteKeyCacheEventType      = "DeleteKeyCacheEvent"
	UpdateUpstreamCacheEventType = "UpdateUpstreamCacheEvent"
	UpdateServiceCacheEventType  = "UpdateServiceCacheEvent"
	UpdateGatewayCacheEventType  = "UpdateGatewayCacheEvent"
)

var Registry = map[string]reflect.Type{
	DeleteRulesCacheEventType:    reflect.TypeOf(DeleteRulesCacheEvent{}),
	DeleteGatewayCacheEventType:  reflect.TypeOf(DeleteGatewayCacheEvent{}),
	DeleteServiceCacheEventType:  reflect.TypeOf(DeleteServiceCacheEvent{}),
	DeleteUpstreamCacheEventType: reflect.TypeOf(DeleteUpstreamCacheEvent{}),
	DeleteKeyCacheEventType:      reflect.TypeOf(DeleteKeyCacheEvent{}),
	UpdateUpstreamCacheEventType: reflect.TypeOf(UpdateUpstreamCacheEvent{}),
	UpdateServiceCacheEventType:  reflect.TypeOf(UpdateServiceCacheEvent{}),
	UpdateGatewayCacheEventType:  reflect.TypeOf(UpdateGatewayCacheEvent{}),
}
