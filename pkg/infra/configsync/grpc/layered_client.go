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
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"strings"
	"sync"

	snapshotpb "github.com/NeuralTrust/TrustGate/pkg/infra/configsnapshot/proto"
	configsync "github.com/NeuralTrust/TrustGate/pkg/runtimeconfig/sync"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// layeredVersionPrefix starts every manifest version the control plane
// publishes; a version without it is a single-blob version.
const layeredVersionPrefix = "m1:"

var (
	errLayeredUnavailable = errors.New("configsync: control plane serves no layered snapshot")
	errFragmentGone       = errors.New("configsync: a fragment of the manifest is no longer served")
)

// fragmentCache holds the fragments of the last manifest the data plane
// assembled, keyed by digest, so the next pull fetches only what changed. It
// never holds more than one manifest's fragments.
type fragmentCache struct {
	mu        sync.Mutex
	fragments map[[32]byte][]byte
}

func (f *fragmentCache) get(digest [32]byte) ([]byte, bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	raw, ok := f.fragments[digest]
	return raw, ok
}

func (f *fragmentCache) replace(fragments map[[32]byte][]byte) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.fragments = fragments
}

// Verifies reports whether Fetch already verified a body returned under
// version: layered versions are checked fragment by fragment, so the worker
// cannot and need not recompute them from the assembled bytes.
func (c *Client) Verifies(version string) bool {
	return c.layered && strings.HasPrefix(version, layeredVersionPrefix)
}

// fetchLayeredOrSnapshot pulls a layered snapshot, retrying once from a fresh
// manifest when a fragment aged out mid-pull, and falls back to the single
// blob for this call when the control plane serves no layered snapshot or the
// retry fails the same way.
func (c *Client) fetchLayeredOrSnapshot(ctx context.Context, etag string) ([]byte, string, bool, error) {
	for attempt := 0; attempt < 2; attempt++ {
		raw, version, notModified, err := c.fetchLayered(ctx, etag)
		switch {
		case err == nil:
			return raw, version, notModified, nil
		case errors.Is(err, errLayeredUnavailable):
			return c.fetchSnapshot(ctx, etag)
		case errors.Is(err, errFragmentGone):
			continue
		default:
			return nil, "", false, err
		}
	}
	return c.fetchSnapshot(ctx, etag)
}

// fetchLayered reads the manifest, fetches the fragments the cache does not
// hold, verifies each against its digest and the manifest against its
// version, and returns the fragments concatenated in manifest order. Nothing
// is returned unless every fragment arrived and verified.
func (c *Client) fetchLayered(ctx context.Context, etag string) ([]byte, string, bool, error) {
	manifest, err := c.cli.GetManifest(ctx, &snapshotpb.GetManifestRequest{AppliedVersion: etag, InstanceId: c.instanceID})
	if err != nil {
		if status.Code(err) == codes.Unimplemented {
			return nil, "", false, fmt.Errorf("%w: %w", errLayeredUnavailable, err)
		}
		return nil, "", false, fmt.Errorf("configsync: get manifest: %w", err)
	}
	if manifest.GetNotModified() {
		return nil, manifest.GetVersion(), true, nil
	}
	refs, total, err := verifyManifest(manifest)
	if err != nil {
		return nil, "", false, err
	}

	held := make(map[[32]byte][]byte, len(refs))
	var missing [][32]byte
	for _, ref := range refs {
		if _, seen := held[ref.digest]; seen {
			continue
		}
		if raw, ok := c.fragments.get(ref.digest); ok {
			held[ref.digest] = raw
			continue
		}
		held[ref.digest] = nil
		missing = append(missing, ref.digest)
	}
	for start := 0; start < len(missing); start += maxFragmentsPerRequest {
		batch := missing[start:min(start+maxFragmentsPerRequest, len(missing))]
		if err := c.fetchFragments(ctx, batch, held); err != nil {
			return nil, "", false, err
		}
	}

	buf := make([]byte, 0, total)
	for _, ref := range refs {
		raw := held[ref.digest]
		if raw == nil && ref.size > 0 {
			return nil, "", false, fmt.Errorf("%w: fragment %x was not received", configsync.ErrIntegrity, ref.digest[:8])
		}
		if len(raw) != ref.size {
			return nil, "", false, fmt.Errorf("%w: fragment %x is %d bytes, manifest says %d", configsync.ErrIntegrity, ref.digest[:8], len(raw), ref.size)
		}
		buf = append(buf, raw...)
	}
	c.fragments.replace(held)
	return buf, manifest.GetVersion(), false, nil
}

type manifestRef struct {
	digest [32]byte
	size   int
}

// verifyManifest checks the manifest's shape and that its version is the hash
// of its digests, and returns the references and the assembled size.
func verifyManifest(manifest *snapshotpb.Manifest) ([]manifestRef, int64, error) {
	version := manifest.GetVersion()
	if !strings.HasPrefix(version, layeredVersionPrefix) {
		return nil, 0, fmt.Errorf("%w: manifest version %q is not a layered version", configsync.ErrIntegrity, version)
	}
	refs := make([]manifestRef, 0, len(manifest.GetFragments()))
	h := sha256.New()
	var total int64
	for _, ref := range manifest.GetFragments() {
		var digest [32]byte
		if len(ref.GetDigest()) != len(digest) {
			return nil, 0, fmt.Errorf("%w: manifest digest must be 32 bytes", configsync.ErrIntegrity)
		}
		size := ref.GetSize()
		if size < 0 || size > maxSnapshotBytes {
			return nil, 0, fmt.Errorf("%w: manifest fragment size %d out of bounds", configsync.ErrIntegrity, size)
		}
		total += size
		if total > maxSnapshotBytes {
			return nil, 0, fmt.Errorf("configsync: layered snapshot exceeds %d bytes", int64(maxSnapshotBytes))
		}
		copy(digest[:], ref.GetDigest())
		_, _ = h.Write(digest[:])
		refs = append(refs, manifestRef{digest: digest, size: int(size)})
	}
	if computed := layeredVersionPrefix + hex.EncodeToString(h.Sum(nil)); computed != version {
		return nil, 0, fmt.Errorf("%w: manifest version %q != digest hash %q", configsync.ErrIntegrity, version, computed)
	}
	return refs, total, nil
}

// fetchFragments streams the fragments named by digests into held, verifying
// each against its digest once its last chunk arrives.
func (c *Client) fetchFragments(ctx context.Context, digests [][32]byte, held map[[32]byte][]byte) error {
	req := &snapshotpb.GetFragmentsRequest{Digests: make([][]byte, len(digests))}
	wanted := make(map[[32]byte]bool, len(digests))
	for i := range digests {
		req.Digests[i] = digests[i][:]
		wanted[digests[i]] = true
	}
	stream, err := c.cli.GetFragments(ctx, req)
	if err != nil {
		return fragmentsErr(err)
	}
	var (
		current [32]byte
		buf     []byte
		open    bool
		total   int64
	)
	for {
		chunk, err := stream.Recv()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return fragmentsErr(err)
		}
		var digest [32]byte
		if len(chunk.GetDigest()) != len(digest) {
			return fmt.Errorf("%w: fragment chunk digest must be 32 bytes", configsync.ErrIntegrity)
		}
		copy(digest[:], chunk.GetDigest())
		if !wanted[digest] {
			return fmt.Errorf("%w: received fragment %x that was not requested", configsync.ErrIntegrity, digest[:8])
		}
		if open && digest != current {
			return fmt.Errorf("%w: fragment %x ended without its last chunk", configsync.ErrIntegrity, current[:8])
		}
		current, open = digest, true
		buf = append(buf, chunk.GetData()...)
		total += int64(len(chunk.GetData()))
		if total > maxSnapshotBytes {
			return fmt.Errorf("configsync: fragments exceed %d bytes", int64(maxSnapshotBytes))
		}
		if !chunk.GetLast() {
			continue
		}
		if sha256.Sum256(buf) != digest {
			return fmt.Errorf("%w: fragment %x does not match its digest", configsync.ErrIntegrity, digest[:8])
		}
		held[digest] = buf
		delete(wanted, digest)
		buf, open = nil, false
	}
	if open || len(wanted) > 0 {
		return fmt.Errorf("%w: %d requested fragments were not received", configsync.ErrIntegrity, len(wanted))
	}
	return nil
}

func fragmentsErr(err error) error {
	switch status.Code(err) {
	case codes.NotFound:
		return fmt.Errorf("%w: %w", errFragmentGone, err)
	case codes.Unimplemented:
		return fmt.Errorf("%w: %w", errLayeredUnavailable, err)
	default:
		return fmt.Errorf("configsync: get fragments: %w", err)
	}
}
