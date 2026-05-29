package response

type ListAuthResponse struct {
	Items []AuthResponse `json:"items"`
	Page  int            `json:"page"`
	Size  int            `json:"size"`
	Total int            `json:"total"`
}
