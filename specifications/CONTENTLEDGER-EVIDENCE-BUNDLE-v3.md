# WP ContentLedger Evidence Bundle v3

Version 3 is the native did:webvh-only portable evidence profile. It carries no did:web identity document, transition receipt, adoption proof, cutover marker, or dual-profile compatibility field.

## Verification order

1. Hash the complete archive when an external bundle digest is available.
2. Verify `inventory.sha256`, canonical `inventory.json`, and every inventory entry's exact size and SHA-256 digest before interpreting content.
3. Require `bundle.json` format `WP ContentLedger Evidence Bundle`, version `3.0`, and profile `contentledger-evidence-bundle-native-webvh-v1`.
4. Verify every `identityLogs` receipt as canonical JSON. Its `didLog` must be byte-for-byte identical to the separately carried `.jsonl` file, and its `identity.logBytes`, `identity.logSha256`, log head, assertion method, route, and public-state digest must all reproduce from that log.
5. Verify record and checkpoint Ed25519 compact JWS bytes, then authorize each key at its claimed time from the carried did:webvh log version interval.
6. Verify transparency predecessor consistency, immutable leaf roots, inclusion proofs, and any optional timestamp or archive-reference evidence.
7. Reject unreferenced archive entries and fail closed on every size, hash, path, profile, or authorization mismatch.

The log is the identity history. A signature by one assertion key is authorized from the version time that installs it until (but not including) the next verified version that replaces that assertion key; update-only appends do not end the interval. A contained or rotated key therefore remains valid for claims strictly before its replacement boundary and is rejected at or after that boundary.

Self-contained verification proves the internal byte and cryptographic relationships in the bundle. It does not by itself prove authorship, ownership, a trusted wall-clock time, complete publication, uncompromised keys, or agreement with the current live site. Supply external expected bundle, manifest, checkpoint, or DID values when those anchors matter.
