package backend

import (
	"database/sql/driver"
	"encoding/json"
	"fmt"
)

type Targets []Target

func (t Targets) Value() (driver.Value, error) {
	if len(t) == 0 {
		return []byte("[]"), nil
	}
	return json.Marshal(t)
}

func (t *Targets) Scan(value interface{}) error {
	if value == nil {
		*t = make(Targets, 0)
		return nil
	}
	bytes, ok := value.([]byte)
	if !ok {
		return fmt.Errorf("expected []byte, got %T", value)
	}
	var temp interface{}
	if err := json.Unmarshal(bytes, &temp); err != nil {
		return err
	}
	switch v := temp.(type) {
	case []interface{}:
		return json.Unmarshal(bytes, t)
	case map[string]interface{}:
		*t = make(Targets, 1)
		return json.Unmarshal(bytes, &(*t)[0])
	default:
		return fmt.Errorf("unexpected JSON type: %T", v)
	}
}
