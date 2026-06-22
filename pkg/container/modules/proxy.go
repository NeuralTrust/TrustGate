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

package modules

import (
	proxyhttp "github.com/NeuralTrust/TrustGate/pkg/api/handler/http/proxy"
	appproxy "github.com/NeuralTrust/TrustGate/pkg/app/proxy"
	approuting "github.com/NeuralTrust/TrustGate/pkg/app/routing"
	"github.com/NeuralTrust/TrustGate/pkg/container"
)

func Proxy(c *container.Container) error {
	if err := c.Provide(approuting.NewResolver); err != nil {
		return err
	}
	if err := c.Provide(appproxy.NewProviderInvoker); err != nil {
		return err
	}
	if err := c.Provide(appproxy.NewForwarder); err != nil {
		return err
	}
	return c.Provide(proxyhttp.NewForwardedHandler)
}
