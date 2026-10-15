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

// SharedAccountConnectLink is the optional body of a shared-account connect
// link. An empty body asks for the page alone, as before.
type SharedAccountConnectLink struct {
	// ResumeURL is where the connect page sends the admin once the account is
	// connected: the console screen they started from. An absolute https URL;
	// empty leaves them on the page.
	ResumeURL string `json:"resume_url"`
}
