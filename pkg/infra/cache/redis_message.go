package cache

import (
	"encoding/json"
)

type RedisMessage struct {
	Type  string          `json:"type"`
	Event json.RawMessage `json:"event"`
}
