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

package pluginutil

import "fmt"

// The values a third-party guardrail's on_error setting takes. They name what
// happens to a request when the guardrail cannot give a verdict on it.
const (
	OnErrorFailOpen   = StreamOnErrorFailOpen
	OnErrorFailClosed = StreamOnErrorFailClosed
)

// DefaultOnError returns on_error with its default filled in. A guardrail that
// cannot be consulted lets the request through unless the policy asks
// otherwise (RUN-1792).
func DefaultOnError(onError string) string {
	if onError == "" {
		return OnErrorFailOpen
	}
	return onError
}

// ValidateOnError checks a guardrail's on_error setting.
func ValidateOnError(plugin, onError string) error {
	switch onError {
	case OnErrorFailOpen, OnErrorFailClosed:
		return nil
	}
	return fmt.Errorf("%s: on_error must be one of fail_open, fail_closed", plugin)
}
