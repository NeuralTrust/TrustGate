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

package request

// UserHeaderLinkRequest asks for the connect page one person walks to enter
// their own header values.
type UserHeaderLinkRequest struct {
	// PrincipalSub is the person: the subject their token carries, or
	// app:<consumer_id>:<end_user> for an end user an application names.
	PrincipalSub string `json:"principal_sub"`
	// ConsumerPath is the virtual MCP the person reaches the server through.
	// Empty uses the MCP Store.
	ConsumerPath string `json:"consumer_path,omitempty"`
	// ResumeURL is where the page sends the person once they are done.
	ResumeURL string `json:"resume_url,omitempty"`
}

// UserHeaderImportRequest loads values for many people at once.
type UserHeaderImportRequest struct {
	Values []UserHeaderImportValue `json:"values"`
}

// UserHeaderImportValue is one person's value for one header.
type UserHeaderImportValue struct {
	PrincipalSub string `json:"principal_sub"`
	Header       string `json:"header"`
	// Value is the person's own value, stored encrypted and never returned.
	Value string `json:"value"`
}
