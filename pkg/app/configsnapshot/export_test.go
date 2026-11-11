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

package configsnapshot

import "context"

// WithCompileWhileDirty exposes the compile-while-dirty loop on its own to tests.
var WithCompileWhileDirty = withCompileWhileDirty

// DispatchBackstop runs one dispatch cycle as the backstop ticker would.
func (d *Dispatcher) DispatchBackstop(ctx context.Context) error {
	return d.dispatch(ctx, compileReasonBackstop)
}

// FlushPendingLKG runs the dispatch loop's pending-persist flush.
func (d *Dispatcher) FlushPendingLKG(ctx context.Context) {
	d.flushPendingLKG(ctx)
}
