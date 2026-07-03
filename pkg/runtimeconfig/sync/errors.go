package configsync

import "errors"

var ErrLKGCorrupt = errors.New("configsync: last-known-good snapshot is corrupt")

var ErrReadOnly = errors.New("configsync: store is read-only")

var ErrNotReady = errors.New("configsync: snapshot not ready")

var ErrIntegrity = errors.New("configsync: snapshot integrity mismatch")
