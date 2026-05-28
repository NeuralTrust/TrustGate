package response

type ListGatewayResponse struct {
	Items []GatewayResponse `json:"items"`
	Page  int               `json:"page"`
	Size  int               `json:"size"`
	Total int               `json:"total"`
}
