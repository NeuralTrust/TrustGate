// Copyright 2026 NeuralTrust
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

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
