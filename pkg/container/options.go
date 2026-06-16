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

package container

// Option configures a Container during New.
type Option func(c *Container) error

func WithModule(m Module) Option {
	return func(c *Container) error { return m(c) }
}

func WithOverride(decorator any) Option {
	return func(c *Container) error { return c.Decorate(decorator) }
}
