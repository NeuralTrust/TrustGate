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

package auth

import (
	appsecretref "github.com/NeuralTrust/TrustGate/pkg/app/secretref"
)

// SaveOption configures the auth creator and updater.
type SaveOption func(*saveOptions)

type saveOptions struct {
	secretRefs appsecretref.EntityValidator
}

// WithSecretRefValidator checks the secret references an auth write adds,
// changes or retargets in its identity provider before it is saved.
func WithSecretRefValidator(v appsecretref.EntityValidator) SaveOption {
	return func(o *saveOptions) { o.secretRefs = v }
}

func applySaveOptions(opts []SaveOption) saveOptions {
	var o saveOptions
	for _, opt := range opts {
		opt(&o)
	}
	return o
}
