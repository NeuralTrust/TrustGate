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

import (
	"time"

	"github.com/NeuralTrust/TrustGate/pkg/domain/ids"
)

// State is the health of a store as a plane reports it.
type State string

// Store states.
const (
	StateOK          State = "ok"
	StateAuthFailed  State = "auth_failed"
	StateUnavailable State = "unavailable"
	StateConfigError State = "config_error"
	StateNotAllowed  State = "not_allowed"
)

// Status is what a plane reports about one store: metadata and health,
// never its address, credentials or values.
type Status struct {
	Name         string
	Type         Type
	AllowedPaths []string
	// AllowedDestinations is the store's host allowlist; nil allows any host.
	AllowedDestinations []string
	Gateways            []ids.GatewayID
	State               State
	ErrorClass          Class
	CheckedAt           time.Time
}

//go:generate mockery --name=Catalog --dir=. --output=./mocks --filename=secretstore_catalog_mock.go --case=underscore --with-expecter

// Catalog holds the stores a plane loaded and their backends. Health is not
// its concern: the plane probes the stores and records fetch outcomes.
type Catalog interface {
	// Get returns the store named name (case-insensitive) and its backend.
	Get(name string) (*Store, Backend, bool)
	// Stores returns every loaded store, sorted by name.
	Stores() []*Store
	// LoadError is the error of the last reload of the store file, nil when
	// it loaded. A failed reload keeps the previous stores.
	LoadError() error
}
