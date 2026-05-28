package response

type ListConsumerResponse struct {
	Items []ConsumerResponse `json:"items"`
	Page  int                `json:"page"`
	Size  int                `json:"size"`
	Total int                `json:"total"`
}
