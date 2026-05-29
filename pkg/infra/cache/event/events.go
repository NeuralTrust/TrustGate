package event

import "reflect"

type Event interface {
	Type() string
}

var (
	DeleteGatewayCacheEventType     = "DeleteGatewayCacheEvent"
	InvalidateGatewayDataEventType  = "InvalidateGatewayDataEvent"
	InvalidateBackendCacheEventType = "InvalidateBackendCacheEvent"
)

var Registry = map[string]reflect.Type{
	DeleteGatewayCacheEventType:     reflect.TypeOf(DeleteGatewayCacheEvent{}),
	InvalidateGatewayDataEventType:  reflect.TypeOf(InvalidateGatewayDataEvent{}),
	InvalidateBackendCacheEventType: reflect.TypeOf(InvalidateBackendCacheEvent{}),
}

func GetEventsRegistry() map[string]reflect.Type {
	return Registry
}
