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

package grpc

import (
	"bytes"
	"context"
	"log/slog"
	"sync"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/metric"
	"google.golang.org/genproto/googleapis/rpc/errdetails"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/NeuralTrust/TrustGate/pkg/app/configsyncport"
)

// ReasonSecretRefsUnsupported is the ErrorInfo reason of the FailedPrecondition
// a data plane gets when the snapshot it asked for holds secret references
// and the request did not advertise accepts_secret_refs.
const ReasonSecretRefsUnsupported = "secret_refs_unsupported" // #nosec G101 -- an error reason, not a credential

const (
	secretRefsErrorDomain = "trustgate.configsync" // #nosec G101 -- an error domain, not a credential
	oldPlaneMetric        = "trustgate.configsync.secret_refs_on_old_data_plane"
	// maxRefGateEntries bounds the fragment memo and the log dedup set; both
	// are cleared when they reach it.
	maxRefGateEntries = 1 << 16
)

var (
	refScheme = []byte("secret")
	refSep    = []byte("://")
)

// containsSecretRef reports whether b holds "secret://" in any letter case.
// Any field counts, not only credential fields: a plane that predates
// secret references would forward a reference-shaped value from wherever it
// appears.
func containsSecretRef(b []byte) bool {
	for {
		i := bytes.Index(b, refSep)
		if i < 0 {
			return false
		}
		if i >= len(refScheme) && bytes.EqualFold(b[i-len(refScheme):i], refScheme) {
			return true
		}
		b = b[i+len(refSep):]
	}
}

// partsHaveRef scans every part and the joins between consecutive parts, so
// a reference split across two parts is found too.
func partsHaveRef(parts [][]byte) bool {
	window := len(refScheme) + len(refSep) - 1
	for i, part := range parts {
		if containsSecretRef(part) {
			return true
		}
		if i == 0 {
			continue
		}
		prev := parts[i-1]
		join := make([]byte, 0, 2*window)
		join = append(join, prev[max(0, len(prev)-window):]...)
		join = append(join, part[:min(window, len(part))]...)
		if containsSecretRef(join) {
			return true
		}
	}
	return false
}

type scannedVersion struct {
	version string
	has     bool
}

// refGate remembers which served content holds secret references. Blobs are
// remembered per scope for their latest version only; fragments per digest,
// which never changes meaning. Scans run only for requests and streams that
// lack accepts_secret_refs.
type refGate struct {
	logger *slog.Logger

	mu        sync.Mutex
	blobs     map[string]scannedVersion
	manifests map[string]scannedVersion
	fragments map[[32]byte]bool
	logged    map[string]struct{}

	counterOnce sync.Once
	counter     metric.Int64Counter
}

func newRefGate(logger *slog.Logger) *refGate {
	return &refGate{
		logger:    logger,
		blobs:     map[string]scannedVersion{},
		manifests: map[string]scannedVersion{},
		fragments: map[[32]byte]bool{},
		logged:    map[string]struct{}{},
	}
}

// blobHasRefs reports whether the blob parts served to scope at version hold
// a reference.
func (g *refGate) blobHasRefs(scope, version string, parts [][]byte) bool {
	g.mu.Lock()
	if s, ok := g.blobs[scope]; ok && s.version == version {
		g.mu.Unlock()
		return s.has
	}
	g.mu.Unlock()
	has := partsHaveRef(parts)
	g.mu.Lock()
	g.blobs[scope] = scannedVersion{version: version, has: has}
	g.mu.Unlock()
	return has
}

// manifestHasRefs reports whether any fragment of manifest holds a reference.
// A fragment the source no longer serves counts as holding one, so the gate
// fails closed.
func (g *refGate) manifestHasRefs(scope string, manifest configsyncport.Manifest, source LayeredSource) bool {
	g.mu.Lock()
	if s, ok := g.manifests[scope]; ok && s.version == manifest.Version {
		g.mu.Unlock()
		return s.has
	}
	g.mu.Unlock()
	has := false
	for _, ref := range manifest.Fragments {
		if g.fragmentHasRefs(scope, ref.Digest, source) {
			has = true
			break
		}
	}
	g.mu.Lock()
	g.manifests[scope] = scannedVersion{version: manifest.Version, has: has}
	g.mu.Unlock()
	return has
}

func (g *refGate) fragmentHasRefs(scope string, digest [32]byte, source LayeredSource) bool {
	g.mu.Lock()
	has, ok := g.fragments[digest]
	g.mu.Unlock()
	if ok {
		return has
	}
	raw, ok := source.FragmentFor(scope, digest)
	if !ok {
		return true
	}
	has = containsSecretRef(raw)
	g.mu.Lock()
	if len(g.fragments) >= maxRefGateEntries {
		clear(g.fragments)
	}
	g.fragments[digest] = has
	g.mu.Unlock()
	return has
}

// refused records that a plane without accepts_secret_refs was refused or
// not notified of version: a log once per scope, instance and version, and a
// counter labeled only by where it happened.
func (g *refGate) refused(ctx context.Context, op, scope, instanceID, version string) {
	g.counterOnce.Do(func() {
		c, err := otel.Meter("trustgate/configsync").Int64Counter(oldPlaneMetric,
			metric.WithDescription("Snapshot versions withheld from data planes that do not understand secret references"))
		if err != nil {
			g.logger.Warn("failed to create config-sync metric", slog.String("metric", oldPlaneMetric), slog.String("error", err.Error()))
			return
		}
		g.counter = c
	})
	if g.counter != nil {
		g.counter.Add(ctx, 1, metric.WithAttributes(attribute.String("op", op)))
	}
	key := scope + "\x00" + instanceID + "\x00" + version
	g.mu.Lock()
	_, seen := g.logged[key]
	if !seen {
		if len(g.logged) >= maxRefGateEntries {
			clear(g.logged)
		}
		g.logged[key] = struct{}{}
	}
	g.mu.Unlock()
	if seen {
		return
	}
	g.logger.Warn("secret_refs_on_old_data_plane",
		slog.String("component", "configsync"),
		slog.String("op", op),
		slog.String("scope", scope),
		slog.String("instance_id", instanceID),
		slog.String("version", version))
}

func errSecretRefsUnsupported() error {
	st := status.New(codes.FailedPrecondition, "the snapshot holds secret references and this data plane does not advertise accepts_secret_refs; upgrade it")
	if detailed, err := st.WithDetails(&errdetails.ErrorInfo{Reason: ReasonSecretRefsUnsupported, Domain: secretRefsErrorDomain}); err == nil {
		st = detailed
	}
	return st.Err()
}

// withheld reports whether the notice n for scope must not reach a
// connection without accepts_secret_refs, because the content it would pull
// holds references.
func (s *Service) withheld(scope string, n notice) bool {
	if n.layered {
		source := s.layeredSource()
		if manifest, ok := source.ManifestFor(scope); ok {
			return s.refs.manifestHasRefs(scope, manifest, source)
		}
	}
	parts, version, ok := s.source.SnapshotPartsFor(scope)
	if !ok {
		return false
	}
	return s.refs.blobHasRefs(scope, version, parts)
}
