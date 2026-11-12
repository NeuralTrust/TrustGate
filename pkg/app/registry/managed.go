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

package registry

import (
	"context"

	domain "github.com/NeuralTrust/TrustGate/pkg/domain/registry"
)

type platformCallerKey struct{}

// AsPlatform marks ctx as a change the platform (NeuralTrust itself) asks for.
// Only such a change may create, edit or delete a managed registry; a context
// without the mark is a tenant's.
func AsPlatform(ctx context.Context) context.Context {
	return context.WithValue(ctx, platformCallerKey{}, true)
}

func isPlatform(ctx context.Context) bool {
	marked, _ := ctx.Value(platformCallerKey{}).(bool)
	return marked
}

// refuseManagedChange is the check every create, update and delete makes: a
// managed registry belongs to the platform.
func refuseManagedChange(ctx context.Context, managed bool) error {
	if managed && !isPlatform(ctx) {
		return domain.ErrManaged
	}
	return nil
}
