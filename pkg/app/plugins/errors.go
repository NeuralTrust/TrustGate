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

package plugins

import "errors"

// PluginError is returned by a plugin to reject a request and short-circuit the
// chain with a specific HTTP status (e.g. rate limit 429, CORS preflight 204).
type PluginError struct {
	StatusCode int
	Type       string
	Message    string
	Headers    map[string][]string
	Body       []byte
}

func (e *PluginError) Error() string {
	return e.Message
}

// AsPluginError reports whether err is (or wraps) a *PluginError and returns it.
func AsPluginError(err error) (*PluginError, bool) {
	var pe *PluginError
	if errors.As(err, &pe) {
		return pe, true
	}
	return nil, false
}
