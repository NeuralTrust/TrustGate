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

type ChangeNotifier interface {
	Tail(ctx context.Context) (lastID string, err error)
	Watch(ctx context.Context, lastID string) (id, version string, err error)
	Publish(ctx context.Context, version string) (id string, err error)
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
