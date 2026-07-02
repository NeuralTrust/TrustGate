# Delta for Data-Plane Config Sync (proxy/mcp convergence)

This change adds the data-plane side of pull-based config sync: a converge loop
that restores an encrypted last-known-good (LKG) snapshot on cold start, pulls
the current snapshot from the control plane over HTTP+ETag, subscribes to Redis
Stream notifications to re-pull, swaps the in-memory snapshot atomically, and
persists the encrypted LKG. Readiness is gated on having a valid snapshot loaded.
Maps to ENG-950 QA: "DP converges over Redis Streams + HTTP+ETag and hot-swaps
(atomic.Pointer)"; "cold start restores the encrypted LKG when the admin plane is
unreachable; readiness is gated on first converge or LKG restore".

## ADDED Requirements

### Requirement: Cold-start convergence sequence

On start the data-plane worker MUST attempt to restore the encrypted LKG into the
in-memory snapshot first, then capture the current Redis Stream last-id, then
perform an HTTP pull with `If-None-Match` set to the loaded version, then read
subsequent notifications from the captured last-id. When the control plane is
unreachable on cold start but a valid LKG exists, the data plane MUST serve from
the restored LKG and continue retrying the pull in the background.

#### Scenario: Restore then pull then subscribe
- GIVEN a valid encrypted LKG on disk and a reachable control plane
- WHEN the worker starts
- THEN it MUST restore the LKG, capture the stream last-id, pull with `If-None-Match`, and begin reading from the captured last-id

#### Scenario: Control plane unreachable but LKG present
- GIVEN a valid LKG and an unreachable control plane at start
- WHEN the worker starts
- THEN it MUST serve from the restored LKG and MUST keep retrying the pull without crashing

#### Scenario: No LKG and control plane unreachable
- GIVEN no valid LKG and an unreachable control plane
- WHEN the worker starts
- THEN no snapshot MUST be loaded and readiness MUST remain not-ready

### Requirement: Notification-driven re-pull

The worker MUST re-pull the snapshot when notified via the Redis Stream, reading
from the last processed id (`XREAD` semantics) so no version bump is missed while
connected. Each re-pull MUST send `If-None-Match` with the current in-memory
version; a `304 Not Modified` MUST leave the in-memory snapshot unchanged and a
`200 OK` MUST replace it.

#### Scenario: Version bump triggers refresh
- GIVEN the worker is subscribed and holding version V
- WHEN a new version V' is published to the stream
- THEN the worker MUST pull and, on `200 OK`, load V'

#### Scenario: Redundant notification is a no-op
- GIVEN the worker holds the current version
- WHEN a pull returns `304 Not Modified`
- THEN the in-memory snapshot MUST remain unchanged

### Requirement: Atomic in-memory swap

Loading a new snapshot MUST replace the served snapshot atomically (single
pointer swap) so concurrent readers on the hot path always observe either the
complete previous snapshot or the complete new one, never a partially applied
state.

#### Scenario: Readers never see a partial snapshot
- GIVEN concurrent hot-path reads during a snapshot load
- WHEN a new snapshot is installed
- THEN every read MUST resolve against a single complete snapshot version

### Requirement: Encrypted LKG persistence and integrity

After successfully loading a snapshot from the control plane, the worker MUST
persist it to the configured LKG path encrypted with AES-256-GCM. On restore the
worker MUST verify integrity; a tampered, corrupt, or undecryptable LKG MUST be
rejected (treated as no valid LKG) and MUST trigger a fresh pull rather than
serving unverified data.

#### Scenario: Successful pull updates the LKG
- GIVEN a `200 OK` pull that loads a new snapshot
- WHEN the load succeeds
- THEN the worker MUST write the encrypted snapshot to the LKG path

#### Scenario: Tampered LKG is rejected
- GIVEN an LKG file whose contents fail AES-256-GCM authentication
- WHEN the worker attempts to restore it
- THEN restore MUST fail with an integrity error and the worker MUST fall back to pulling from the control plane

### Requirement: Readiness gating

The data plane MUST report not-ready on `/readyz` until a valid snapshot has been
loaded (from a successful pull or an integrity-verified LKG restore). While
not-ready it MUST NOT serve config-dependent traffic as if healthy. Once a valid
snapshot is loaded it MUST report ready.

#### Scenario: Not ready before first valid snapshot
- GIVEN a data plane that has not yet loaded any valid snapshot
- WHEN `/readyz` is probed
- THEN it MUST report not-ready

#### Scenario: Ready after snapshot load
- GIVEN a data plane that has loaded a valid snapshot via pull or verified LKG
- WHEN `/readyz` is probed
- THEN it MUST report ready
