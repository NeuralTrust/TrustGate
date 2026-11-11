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

package a2a

import (
	"net/http"

	appa2a "github.com/NeuralTrust/TrustGate/pkg/app/a2a"
	"github.com/NeuralTrust/TrustGate/pkg/infra/netguard"
)

var _ appa2a.Upstream = (*upstreamClient)(nil)

type upstreamClient struct {
	client *http.Client
}

// NewUpstreamClient posts to agents through the shared network guard. The
// caller's context bounds each call: an agent answers a buffered call only
// once the task is done, so there is no response header timeout.
func NewUpstreamClient() appa2a.Upstream {
	transport := netguard.NewTransport()
	transport.ResponseHeaderTimeout = 0
	return &upstreamClient{client: &http.Client{Transport: transport, CheckRedirect: netguard.CheckRedirect}}
}

func (u *upstreamClient) Do(req *http.Request) (*http.Response, error) {
	return u.client.Do(req)
}
