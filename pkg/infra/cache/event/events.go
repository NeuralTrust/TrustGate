package event

import "reflect"

type Event interface {
	Type() string
}

var (
	DeleteGatewayCacheEventType = "DeleteGatewayCacheEvent"
)

var Registry = map[string]reflect.Type{
	DeleteGatewayCacheEventType: reflect.TypeOf(DeleteGatewayCacheEvent{}),
}

func GetEventsRegistry() map[string]reflect.Type {
	return Registry
}
