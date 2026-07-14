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

package event

// SnapshotDirtyEvent signals that config feeding the runtime snapshot changed on
// one admin replica, so every admin replica must recompile and push a new
// snapshot version to its connected data planes. Version broadcast is in-process
// per admin pod, so without this cross-pod nudge a replica that did not handle
// the write would only converge on its periodic backstop timer.
type SnapshotDirtyEvent struct{}

func (e SnapshotDirtyEvent) Type() string {
	return SnapshotDirtyEventType
}
