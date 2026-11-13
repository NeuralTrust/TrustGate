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

package secretstore

import "github.com/NeuralTrust/TrustGate/pkg/domain/ids"

// MaxRefOutcomes caps the outcomes a plane reports, failing ones first.
const MaxRefOutcomes = 200

// RefOutcome is the last outcome of one reference a plane resolved for a
// gateway's runtime data: where it is (entity, id, field), what it names
// (store, path) and the error class that left it empty, "" when it resolved.
// It never holds a value.
type RefOutcome struct {
	GatewayID ids.GatewayID
	Entity    string
	ID        string
	Field     string
	Store     string
	Path      string
	Class     Class
}

// RefHealth is what a plane observed about the references it resolved.
// Total and Unresolved count every one; Outcomes lists them, failing ones
// first, up to MaxRefOutcomes. A reference the plane has not resolved yet is
// in none of them.
type RefHealth struct {
	Total      int
	Unresolved int
	Outcomes   []RefOutcome
}

// Find returns the outcome of the reference raw-named by store and path at
// field of entity id in gw, if h holds it.
func (h RefHealth) Find(gw ids.GatewayID, entity, id, field, store, path string) (RefOutcome, bool) {
	for _, o := range h.Outcomes {
		if o.GatewayID == gw && o.Entity == entity && o.ID == id && o.Field == field && o.Store == store && o.Path == path {
			return o, true
		}
	}
	return RefOutcome{}, false
}
