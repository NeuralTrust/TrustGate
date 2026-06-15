package request

type AttachRegistryRequest struct {
	// Weight is the relative weighted-round-robin share on a 1..100 scale.
	Weight *int `json:"weight,omitempty" example:"1" minimum:"1" maximum:"100"`
}
