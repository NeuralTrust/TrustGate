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

package dataplane

import (
	"strings"
	"time"

	"github.com/NeuralTrust/TrustGate/pkg/domain/secretstore"

	"golang.org/x/mod/semver"
)

// MinStoreVersion is the first data-plane build that serves the LLM Store on a
// gateway whose data plane is its own (hybrid).
const MinStoreVersion = "v0.83.0"

// InstanceFreshness is how long an instance counts as live after its stream
// last refreshed last_seen. It matches the console's Unreachable threshold.
const InstanceFreshness = 5 * time.Minute

// StoreReason says why the LLM Store is, or is not, served on a gateway.
type StoreReason string

// Store reasons, from the gateway's live data-plane instances.
const (
	StoreAvailable         StoreReason = "available"
	StoreNoDataPlane       StoreReason = "no_data_plane"
	StoreVersionUnknown    StoreReason = "version_unknown"
	StoreDataPlaneOutdated StoreReason = "data_plane_outdated"
)

const connectedInstanceState = "connected"

// Instance is one data-plane stream of a gateway, as the control plane
// recorded it. Version is empty when the data plane never sent a heartbeat.
type Instance struct {
	ID       string
	State    string
	LastSeen time.Time
	Version  string
	// AcceptsSecretRefs and SecretStores are what the instance last reported
	// about secret references.
	AcceptsSecretRefs bool
	SecretStores      []secretstore.Status
}

// Live reports whether the instance is connected and was seen within
// InstanceFreshness of now.
func (in Instance) Live(now time.Time) bool {
	return in.State == connectedInstanceState && now.Sub(in.LastSeen) <= InstanceFreshness
}

// StoreAvailability is whether the data planes of one gateway serve the LLM
// Store. LowestVersion is the oldest version seen, set only when outdated.
type StoreAvailability struct {
	Available     bool
	Reason        StoreReason
	MinVersion    string
	LowestVersion string
}

// HostedStoreAvailability is the answer for a gateway the hosted planes serve:
// they run the control plane's own release.
func HostedStoreAvailability() StoreAvailability {
	return StoreAvailability{Available: true, Reason: StoreAvailable, MinVersion: MinStoreVersion}
}

// ResolveStoreAvailability classifies the instances of a gateway served by its
// own data plane. Only connected instances seen within InstanceFreshness count:
// a data plane that predates heartbeats still refreshes last_seen, so it counts
// and reads as version_unknown rather than as absent. Every live instance must
// be recent enough, since the load balancer may send a user to any of them.
func ResolveStoreAvailability(instances []Instance, now time.Time) StoreAvailability {
	out := StoreAvailability{MinVersion: MinStoreVersion}
	live, unknown := 0, false
	for _, in := range instances {
		if in.State != connectedInstanceState || now.Sub(in.LastSeen) > InstanceFreshness {
			continue
		}
		live++
		version, ok := canonicalVersion(in.Version)
		if !ok {
			unknown = true
			continue
		}
		if semver.Compare(version, MinStoreVersion) < 0 && (out.LowestVersion == "" || semver.Compare(version, out.LowestVersion) < 0) {
			out.LowestVersion = version
		}
	}
	switch {
	case live == 0:
		out.Reason = StoreNoDataPlane
		out.LowestVersion = ""
	case unknown:
		out.Reason = StoreVersionUnknown
		out.LowestVersion = ""
	case out.LowestVersion != "":
		out.Reason = StoreDataPlaneOutdated
	default:
		out.Available = true
		out.Reason = StoreAvailable
	}
	return out
}

// canonicalVersion accepts a release version with or without its leading v.
// Anything that is not semver, such as a commit sha or "dev", is refused.
func canonicalVersion(raw string) (string, bool) {
	v := strings.TrimSpace(raw)
	if v == "" {
		return "", false
	}
	if !strings.HasPrefix(v, "v") {
		v = "v" + v
	}
	if !semver.IsValid(v) {
		return "", false
	}
	return semver.Canonical(v), true
}
