package events

import (
	"encoding/json"
	"strconv"
)

// DecimalFloat is a float64 that JSON-encodes as a decimal number, never in scientific notation.
type DecimalFloat float64

func (f DecimalFloat) MarshalJSON() ([]byte, error) {
	return []byte(strconv.FormatFloat(float64(f), 'f', -1, 64)), nil
}

func (f *DecimalFloat) UnmarshalJSON(data []byte) error {
	var v float64
	if err := json.Unmarshal(data, &v); err != nil {
		return err
	}
	*f = DecimalFloat(v)
	return nil
}
