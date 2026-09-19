# ContentLedger Manifest v1

## Status

Manifest version: `1.0`

Serialization: RFC 8785 JSON Canonicalization Scheme profile

Digest: SHA-256 over the exact UTF-8 canonical manifest bytes

Schema: `schemas/content-ledger-manifest-v1.schema.json`

Manifest v1 is retained as the immutable historical format for records sealed only after verified archive completion. Version 0.8.0 does not rewrite it. New origin-evidence records use Manifest v2, which moves Internet Archive state outside the immutable manifest.

## Canonical JSON profile

Manifest values are limited to strings, booleans, null, arrays, objects, and integers in the I-JSON safe integer range. Floating-point values are prohibited. Object property names are ordered by UTF-16 code units as required by RFC 8785. JSON strings use unescaped Unicode and unescaped solidus serialization while retaining required JSON escaping.

This restricted data model avoids cross-runtime floating-point serialization ambiguity while producing RFC 8785-compatible JSON for every accepted manifest.

## Top-level fields

`$schema`
: Public URL of the JSON Schema used by the originating site.

`manifestVersion`
: The manifest format version. Version 1 is `1.0`.

`entryId`
: Stable `urn:uuid:` identifier assigned before or during sealing.

`sealedAt`
: UTC time at which the immutable manifest was created.

`subject`
: Public metadata describing the web resource. The article body is not embedded.

`digests`
: Zero or more digest statements. New v0.3 records normally include a canonical-content digest and may include a public-representation digest. Legacy imports have an empty list.

`archiveEvidence`
: Internet Archive provider, snapshot URL, capture time, discovery method, and HTTP-verification metadata.

`chain`
: Optional SHA-256 reference to the preceding sealed manifest for the same canonical URL.

`provenance`
: Evidence-capture time, queue source, and legacy-import flag.

`limitations`
: Explicit limitations applying to the record, including omitted retroactive hashes.

`generator`
: Plugin name and version that generated the manifest.

## Canonical content digest

The `wp-contentledger-content-v1` projection contains:

- canonical URL;
- content type and language;
- title, raw WordPress content, and excerpt with CRLF/CR normalized to LF;
- publication and modification dates in UTC;
- public author display name and author archive URL;
- publisher name and site URL;
- public taxonomy names and slugs in deterministic order;
- featured-image URL when present.

The complete projection is canonicalized and hashed, but the article body is not copied into the public manifest.

## Public representation digest

`http-response-body-v1` is SHA-256 over the exact decoded response body returned by the WordPress HTTP API immediately before the Internet Archive submission. It is recorded only for a successful HTML or XHTML response that fits within the capture limit.

This digest is deliberately distinct from the canonical content digest. Theme output, navigation, advertising, personalization, and other presentation details can change without changing the underlying article.

## Manifest digest

The manifest does not contain its own digest. Its SHA-256 value is stored in the ledger index, exposed on the verification page, and indexed as the manifest artifact. This avoids a circular self-hash.

OpenTimestamps receipts introduced in plugin version 0.4 and Ed25519 JWS signatures introduced in version 0.6 refer to this same subject digest. Both are append-only artifacts outside Manifest v1, so attaching them does not change these canonical bytes.

## Immutability

The application seals a manifest only when the database manifest field is null. Once sealed, proof layers—including upgradeable OpenTimestamps `.ots` receipts—are attached as artifacts and must not rewrite the manifest. A materially changed post receives a new record and new manifest.
