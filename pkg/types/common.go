package types

// ResponseCondition represents a condition for response validation
type ResponseCondition struct {
	Field          string      `json:"field"`
	Operator       string      `json:"operator"`
	Value          interface{} `json:"value"`
	StopProcessing bool        `json:"stop_flow"`
	Message        string      `json:"message"`
}
