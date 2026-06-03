package response

type ListRegistryResponse struct {
	Items []RegistryResponse `json:"items"`
	Page  int                `json:"page"`
	Size  int                `json:"size"`
	Total int                `json:"total"`
}
