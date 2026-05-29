package response

type ListPolicyResponse struct {
	Items []PolicyResponse `json:"items"`
	Page  int              `json:"page"`
	Size  int              `json:"size"`
	Total int              `json:"total"`
}
