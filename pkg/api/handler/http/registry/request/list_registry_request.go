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

package request

import (
	"fmt"

	domain "github.com/NeuralTrust/TrustGate/pkg/domain/registry"
)

const GroupedView = "grouped"

type ListRegistryRequest struct {
	Name        string
	Page        int
	Size        int
	View        string
	Type        string
	TypePresent bool
	NamePresent bool
	PagePresent bool
	SizePresent bool
}

func (r ListRegistryRequest) Validate() error {
	switch r.View {
	case "":
		if r.TypePresent {
			return fmt.Errorf("type is only supported when view is %q", GroupedView)
		}
		return nil
	case GroupedView:
		if r.Type != string(domain.TypeLLM) {
			return fmt.Errorf("type must be %q when view is %q", domain.TypeLLM, GroupedView)
		}
		if r.NamePresent || r.PagePresent || r.SizePresent {
			return fmt.Errorf("name, page, and size are not supported when view is %q", GroupedView)
		}
		return nil
	default:
		return fmt.Errorf("view must be empty or %q", GroupedView)
	}
}
