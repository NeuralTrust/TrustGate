# Specification: snapshot-layered-pull

## Purpose

Phase 2: a data plane that supports layers downloads only the fragments it
does not already have. It works like `docker pull`: fetch a manifest of
fragment digests, then only the missing fragments. Support is negotiated in
`Hello`. Data planes that do not advertise it, such as older hybrid customer
builds, keep the current single-blob `GetSnapshot` path and the v1 version,
byte for byte.

## Requirements

### Requirement: Capability negotiation

A data plane MUST advertise `accepts_layered` in `Hello` only when it
implements this spec. The admin MUST serve manifests and fragments only to a
stream that advertised it. Every other stream MUST keep today's behaviour.

#### Scenario: New plane advertises

- GIVEN a data plane built with layered pull
- WHEN it sends `Hello` with `accepts_layered=true`
- THEN its version notices carry the layered version

#### Scenario: Old plane

- GIVEN a data plane from before this change
- WHEN it connects and calls `GetSnapshot`
- THEN it gets the same bytes and v1 version as a full compile, exactly as
  today

#### Scenario: New plane, old admin

- GIVEN a layered data plane and an admin without the new RPCs
- WHEN `GetManifest` returns Unimplemented
- THEN the data plane falls back to `GetSnapshot` and converges

### Requirement: Manifest

`GetManifest(scope)` MUST return the ordered list of fragment digests that
assembles the snapshot for the caller's scope. The snapshot version for
layered planes MUST be the hash of that manifest. The admin MUST derive the
manifest from the same compile that produced the v1 blob, so both describe
the same configuration.

Notices on the `Sync` stream MUST carry, for each stream, the version that
matches its capability: the manifest hash for layered planes, the v1 version
for the rest.

#### Scenario: Version per capability

- GIVEN one compile has published
- WHEN a layered plane and a v1 plane receive notices
- THEN the layered plane gets the manifest hash and the v1 plane gets the v1
  version, both from that compile

#### Scenario: Not modified

- GIVEN a layered plane whose applied version is the current manifest hash
- WHEN it asks for the manifest with that version
- THEN the admin answers not-modified

### Requirement: Fragment pull and verification

`GetFragments(digests)` MUST stream the requested fragments. Each fragment is
addressed by the sha256 of its bytes. The data plane MUST:

- request only the digests it does not have cached;
- verify every received fragment against its digest and reject any mismatch;
- assemble the snapshot in manifest order;
- check that the manifest hash matches the advertised version before
  applying.

A missing or unknown digest MUST fail the fetch without applying a partial
snapshot. The plane MUST keep serving its last applied snapshot.

#### Scenario: Only new fragments are fetched

- GIVEN a layered plane holds every fragment of version V1
- WHEN gateway G changes and V2 is published
- THEN the plane requests only G's changed fragments
- AND applies V2 after assembling it

#### Scenario: Corrupt fragment

- GIVEN a fragment whose bytes do not hash to its digest
- WHEN the plane receives it
- THEN the fetch fails with an integrity error and the previous snapshot stays
  live

#### Scenario: Digest evicted on the admin

- GIVEN the plane asks for a digest that the admin no longer holds
- WHEN `GetFragments` runs
- THEN it returns NotFound and the plane re-fetches the manifest and retries,
  or falls back to `GetSnapshot`

### Requirement: Compression

The `GetManifest` and `GetFragments` responses MUST be gzip-compressed when
the plane accepts gzip, using the same negotiation as `GetSnapshot` today.
Planes MUST NOT compress their own requests.

#### Scenario: Gzip negotiated

- GIVEN a layered plane that advertises gzip
- WHEN it fetches fragments
- THEN the response stream is gzip-encoded

### Requirement: Bounded fragment cache on the data plane

The data plane MUST drop fragments that the applied manifest no longer
references once the new snapshot is applied. It MUST persist its LKG as the
assembled snapshot, or as manifest plus fragments, so that a restart
restores without contacting the admin.

#### Scenario: Unreferenced fragments evicted

- GIVEN the plane applied V2, which no longer references fragment F
- WHEN the apply completes
- THEN F is removed from the cache

#### Scenario: Restart with LKG

- GIVEN the plane persisted V2
- WHEN it restarts while the admin is unreachable
- THEN it serves V2 from the LKG
