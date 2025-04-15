package data_masking

type DataMaskingData struct {
	Masked bool           `json:"masked"`
	Events []MaskingEvent `json:"events"`
}

type MaskingEvent struct {
	Entity        string `json:"entity"`
	OriginalValue string `json:"original_value"`
	MaskedWith    string `json:"masked_with"`
}
