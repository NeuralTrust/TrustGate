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

package policy

import (
	appplugins "github.com/NeuralTrust/TrustGate/pkg/app/plugins"
	appsecretref "github.com/NeuralTrust/TrustGate/pkg/app/secretref"
	domain "github.com/NeuralTrust/TrustGate/pkg/domain/policy"
)

// SaveOption configures the policy creator and updater.
type SaveOption func(*saveOptions)

type saveOptions struct {
	secretRefs appsecretref.EntityValidator
}

// WithSecretRefValidator checks the secret references a policy write adds,
// changes or retargets at its plugin's credential paths before it is saved.
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

// policyRefs is appsecretref.PolicyRefs with p's plugin's declared paths.
func policyRefs(reg appplugins.Registry, p *domain.Policy) appsecretref.EntityRefs {
	paths, _ := appplugins.PluginCredentialPaths(reg, p.Slug)
	return appsecretref.PolicyRefs(p, paths, appplugins.PluginCredentialDestinations(reg, p.Slug))
}
