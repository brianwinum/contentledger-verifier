# ContentLedger Origin Evidence Manifest v2

## Status

Manifest version: `2.0`

Serialization: RFC 8785 JSON Canonicalization Scheme profile

Digest: SHA-256 over the exact UTF-8 canonical manifest bytes

Schema: `schemas/content-ledger-manifest-v2.schema.json`

## Design boundary

Manifest v2 is sealed from the canonical WordPress content evidence available when an eligible publication or material update is queued. It does not wait for Internet Archive and contains no mutable archive job, snapshot, signature, or timestamp state.

Later artifacts reference the immutable manifest digest:

- site-controlled Ed25519 compact JWS;
- OpenTimestamps receipts and Bitcoin attestations;
- public-representation digest, when retrieval succeeds;
- verified Wayback snapshot, when Internet Archive produces one.

Those artifacts can be added or upgraded without changing the manifest bytes.

## Top-level fields

`$schema`
: Public URL of the Manifest v2 JSON Schema.

`manifestVersion`
: The constant value `2.0`.

`entryId`
: Stable `urn:uuid:` identifier assigned before sealing.

`sealedAt`
: UTC time when the immutable manifest bytes were created. This is the start of the sealed-record claim and is never backdated.

`subject`
: Public metadata describing the web resource. The article body is not embedded.

`digests`
: SHA-256 statements. Manifest v2 requires the deterministic canonical-content digest and may include a public-representation digest already captured before migration sealing.

`evidenceScope`
: Conservative description of what the record covers: canonical-content integrity and publisher-controlled recording.

`chain`
: Optional SHA-256 reference to the preceding sealed manifest for the same canonical URL. The predecessor may be Manifest v1 or v2.

`provenance`
: Evidence-capture time, queue source, and a boolean disclosing whether previously stored evidence was sealed later during migration.

`limitations`
: Explicitly excludes claims of legal ownership, original authorship, first publication, or third-party preservation.

`generator`
: Plugin name and version that generated the manifest.

## Migration

Existing Manifest v1 documents are never rewritten. An unresolved pre-v0.8.0 record can receive Manifest v2 only when it already contains a canonical content digest and subject claim created by v0.3.0 or later. Its historical `evidenceCapturedAt` remains a recorded claim, while `sealedAt`, JWS `issuedAt`, OpenTimestamps receipt creation, and later Bitcoin attestations retain their actual v0.8.0-or-later dates. A pre-v0.3.0 row without that content evidence receives no retroactive origin-evidence claim; if its Wayback capture is later verified, it can still receive the archive-dependent Manifest v1 used by earlier releases.

Pre-v0.3.0 rows without a canonical content digest are not given retroactive origin-evidence manifests. A new record must be created from current eligible content instead.
