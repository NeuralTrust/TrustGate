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

	"github.com/NeuralTrust/TrustGate/pkg/app/configsyncport"
	snapshotpb "github.com/NeuralTrust/TrustGate/pkg/infra/configsnapshot/proto"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// maxFragmentsPerRequest bounds one GetFragments call. A data plane missing
// more fragments than this asks again for the rest.
const maxFragmentsPerRequest = 4096

// LayeredSource serves layered snapshots: the manifest of a scope and the
// bytes of a fragment by digest. A SnapshotSource that also implements it
// lets data planes that advertise accepts_layered pull only what they miss.
type LayeredSource interface {
	ManifestFor(scope string) (configsyncport.Manifest, bool)
	Fragment(digest [32]byte) ([]byte, bool)
}

func (s *Service) layeredSource() LayeredSource {
	layered, _ := s.source.(LayeredSource)
	return layered
}

// currentNotice is the version a newly connected data plane is compared
// against: the manifest version when it pulls layered snapshots and one is
// published, the single-blob version otherwise.
func (s *Service) currentNotice(scope string, layered bool) (notice, bool) {
	if layered {
		if manifest, ok := s.layeredSource().ManifestFor(scope); ok {
			return notice{version: manifest.Version, layered: true}, true
		}
	}
	_, version, ok := s.source.SnapshotPartsFor(scope)
	return notice{version: version}, ok
}

// GetManifest returns the caller's layered manifest, or not_modified when its
// applied version is current. It answers Unimplemented while no layered
// snapshot is published, which a data plane treats as "pull the single blob".
func (s *Service) GetManifest(ctx context.Context, req *snapshotpb.GetManifestRequest) (*snapshotpb.Manifest, error) {
	identity, _ := IdentityFromContext(ctx)
	if s.revoked(identity) {
		return nil, errInvalidToken
	}
	source := s.layeredSource()
	if source == nil {
		return nil, status.Error(codes.Unimplemented, "layered snapshots are not served")
	}
	manifest, ok := source.ManifestFor(ScopeFromContext(ctx))
	if !ok {
		return nil, status.Error(codes.Unimplemented, "no layered snapshot is published")
	}
	if applied := req.GetAppliedVersion(); applied != "" && applied == manifest.Version {
		return &snapshotpb.Manifest{Version: manifest.Version, NotModified: true}, nil
	}
	s.compressSnapshot(ctx)
	refs := make([]*snapshotpb.FragmentRef, len(manifest.Fragments))
	for i, ref := range manifest.Fragments {
		refs[i] = &snapshotpb.FragmentRef{Digest: ref.Digest[:], Size: int64(ref.Size)}
	}
	return &snapshotpb.Manifest{Version: manifest.Version, Fragments: refs}, nil
}

// GetFragments streams the requested fragments in request order, each in
// chunks of at most snapshotChunkSize bytes. Every digest is resolved before
// anything is sent, so an unknown one fails the call with NotFound and the
// data plane restarts from GetManifest without a partial transfer.
func (s *Service) GetFragments(req *snapshotpb.GetFragmentsRequest, stream snapshotpb.ConfigSync_GetFragmentsServer) error {
	identity, _ := IdentityFromContext(stream.Context())
	if s.revoked(identity) {
		return errInvalidToken
	}
	source := s.layeredSource()
	if source == nil {
		return status.Error(codes.Unimplemented, "layered snapshots are not served")
	}
	digests := req.GetDigests()
	if len(digests) > maxFragmentsPerRequest {
		return status.Errorf(codes.InvalidArgument, "at most %d fragments per request", maxFragmentsPerRequest)
	}
	fragments := make([][]byte, len(digests))
	var total int64
	for i, raw := range digests {
		var digest [32]byte
		if len(raw) != len(digest) {
			return status.Error(codes.InvalidArgument, "fragment digest must be 32 bytes")
		}
		copy(digest[:], raw)
		fragment, ok := source.Fragment(digest)
		if !ok {
			return status.Error(codes.NotFound, "fragment is no longer served")
		}
		fragments[i] = fragment
		total += int64(len(fragment))
	}
	if total > maxSnapshotBytes {
		return status.Errorf(codes.ResourceExhausted, "fragments exceed %d bytes", maxSnapshotBytes)
	}
	s.compressSnapshot(stream.Context())
	for i, fragment := range fragments {
		for offset := 0; ; offset += snapshotChunkSize {
			// GetFragments streams are not registered in the hub, so a
			// revocation loaded mid-transfer is enforced before each chunk.
			if s.revoked(identity) {
				return errInvalidToken
			}
			end := min(offset+snapshotChunkSize, len(fragment))
			chunk := &snapshotpb.FragmentChunk{Digest: digests[i], Data: fragment[offset:end], Last: end == len(fragment)}
			if err := stream.Send(chunk); err != nil {
				return err
			}
			if end == len(fragment) {
				break
			}
		}
	}
	return nil
}
