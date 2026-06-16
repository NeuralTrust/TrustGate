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

import "github.com/NeuralTrust/AgentGateway/pkg/container"

func All() []container.Option {
	return []container.Option{
		container.WithModule(Core),
		container.WithModule(API),
		container.WithModule(Cache),
		container.WithModule(CacheEvents),
		container.WithModule(Session),
		container.WithModule(Telemetry),
		container.WithModule(Auth),
		container.WithModule(Policy),
		container.WithModule(Plugins),
		container.WithModule(LoadBalancer),
		container.WithModule(Gateway),
		container.WithModule(Registry),
		container.WithModule(Role),
		container.WithModule(Consumer),
		container.WithModule(Catalog),
		container.WithModule(Providers),
		container.WithModule(Proxy),
		container.WithModule(MCP),
		container.WithModule(ServerAdmin),
		container.WithModule(ServerProxy),
		container.WithModule(ServerMCP),
	}
}
