package response

type ListBackendResponse struct {
	Items []BackendResponse `json:"items"`
	Page  int               `json:"page"`
	Size  int               `json:"size"`
	Total int               `json:"total"`
}
