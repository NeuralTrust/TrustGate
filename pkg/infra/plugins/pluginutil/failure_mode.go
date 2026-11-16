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

import (
	"fmt"
	"strings"
)

// failure_mode is the setting of a guardrail whose policy decides what an
// availability failure costs: open lets the request through (failed_open),
// closed refuses it in a mode that blocks and records it in observe. An input
// failure is refused in a mode that blocks either way.
const (
	SettingFailureMode = "failure_mode"
	FailureModeOpen    = "open"
	FailureModeClosed  = "closed"
	// DefaultFailureMode is the mode of a policy that leaves the setting empty.
	DefaultFailureMode = FailureModeOpen
)

// ValidateFailureMode rejects a failure_mode other than open or closed, naming
// the plugin in the error.
func ValidateFailureMode(plugin, mode string) error {
	switch mode {
	case FailureModeOpen, FailureModeClosed:
		return nil
	}
	return fmt.Errorf("%s: failure_mode must be one of open, closed", plugin)
}

// FailClosedFromRaw reads failure_mode straight from a settings map that may
// not parse: it is closed only when the key (any case, as mapstructure matches
// it) is a string equal-fold to "closed". It decides only what a failure
// costs, so a policy that asked for closed does not fail open because some
// other key made its settings invalid. It never validates: the plugin's own
// parse is still what rejects a bad value.
func FailClosedFromRaw(settings map[string]any) bool {
	for key, v := range settings {
		if !strings.EqualFold(key, SettingFailureMode) {
			continue
		}
		if mode, ok := v.(string); ok && strings.EqualFold(strings.TrimSpace(mode), FailureModeClosed) {
			return true
		}
	}
	return false
}

// FailureModeStamp is the failure_mode a failure's record carries: "closed"
// under a policy that fails closed, and empty otherwise, so the events of an
// open policy are unchanged.
func FailureModeStamp(failClosed bool) string {
	if failClosed {
		return FailureModeClosed
	}
	return ""
}
