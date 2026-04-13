package types

import (
	"encoding/json"
	"fmt"
)

type FlexiblePath struct {
	Primary string
	All     []string
}

func (f FlexiblePath) IsMultiPath() bool {
	return len(f.All) > 0
}

func (f FlexiblePath) MarshalJSON() ([]byte, error) {
	if f.IsMultiPath() {
		return json.Marshal(f.All)
	}
	return json.Marshal(f.Primary)
}

func (f *FlexiblePath) UnmarshalJSON(data []byte) error {
	var s string
	if err := json.Unmarshal(data, &s); err == nil {
		f.Primary = s
		f.All = nil
		return nil
	}

	var arr []string
	if err := json.Unmarshal(data, &arr); err == nil {
		if len(arr) == 0 {
			return fmt.Errorf("path array must contain at least one element")
		}
		f.Primary = arr[0]
		f.All = arr
		return nil
	}

	return fmt.Errorf("path must be a string or an array of strings")
}
