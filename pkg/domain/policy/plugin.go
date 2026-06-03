package policy

type Stage string

const (
	StagePreRequest   Stage = "pre_request"
	StagePostRequest  Stage = "post_request"
	StagePreResponse  Stage = "pre_response"
	StagePostResponse Stage = "post_response"
)

func (s Stage) IsValid() bool {
	switch s {
	case StagePreRequest, StagePostRequest, StagePreResponse, StagePostResponse:
		return true
	default:
		return false
	}
}

type PluginConfig struct {
	ID       string
	Slug     string
	Name     string
	Settings map[string]any
}
