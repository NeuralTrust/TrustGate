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

package configsync

import "context"

type Versioned[T any] struct {
	Version  string
	Snapshot T
	Raw      []byte
}

type ConfigFetcher interface {
	Fetch(ctx context.Context, etag string) (raw []byte, version string, notModified bool, err error)
}

type ConfigStore[T any] interface {
	Load() (*Versioned[T], bool)
	Swap(v *Versioned[T])
	Version() string
}

// StreamTransport is the DP-side control channel: block for the next change
// notice, and report the version the data plane has applied. Implementations
// (the gRPC client) reconnect internally with backoff.
type StreamTransport interface {
	Watch(ctx context.Context) (version string, err error)
	Ack(ctx context.Context, appliedVersion string) error
}

type Crypto interface {
	Encrypt(plaintext []byte) ([]byte, error)
	Decrypt(ciphertext []byte) ([]byte, error)
}

type SnapshotCodec[T any] interface {
	Encode(snapshot T) (raw []byte, err error)
	Decode(raw []byte) (T, error)
	Version(raw []byte) string
}
