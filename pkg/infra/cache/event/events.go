package event

import "reflect"

type Event interface {
	Type() string
}

var (
	DeleteGatewayCacheEventType      = "DeleteGatewayCacheEvent"
	InvalidateGatewayDataEventType   = "InvalidateGatewayDataEvent"
	InvalidateRegistryCacheEventType = "InvalidateRegistryCacheEvent"
)

var Registry = map[string]reflect.Type{
	DeleteGatewayCacheEventType:      reflect.TypeOf(DeleteGatewayCacheEvent{}),
	InvalidateGatewayDataEventType:   reflect.TypeOf(InvalidateGatewayDataEvent{}),
	InvalidateRegistryCacheEventType: reflect.TypeOf(InvalidateRegistryCacheEvent{}),
}

func GetEventsRegistry() map[string]reflect.Type {
	return Registry
}
