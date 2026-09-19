# Public conformance corpus

The ZIP files in `tests/fixtures/` are synthetic public ContentLedger evidence packages. They contain no customer data, private keys, recovery packs, passwords, tokens, or credentials.

The corpus was produced by the WP ContentLedger 0.13.12 synthetic test exporter before this browser-only project was separated. Production identity, signing, checkpoint, bundle-export, deterministic-ZIP, and portable-verifier code created the source packages. WordPress services, SQL storage, encrypted vault persistence, network providers, browser transport, and hosting were either local test doubles or out of scope. OpenTimestamps proofs and Internet Archive references were absent from the original positive corpus; focused public-only mutations add supporting-artifact positive and negative cases.

The private exporter and its generator harness are deliberately not included. Each fixture is instead pinned by byte length, SHA-256 digest, expected outcome, and expected result code in `corpus-manifest.json`. `public-conformance.test.ts` executes the public verifier directly against every pinned package.

`tests/fixtures/webvh/` also contains two deterministic, public-only did:webvh interoperability histories used by the browser verifier tests. They contain only public keys, successor commitments, hashes, signatures, and public DID state—no private construction material or production identity data. `public-boundary.test.mjs` pins their exact filenames, byte lengths, and SHA-256 values and refuses any test dependency on a parent or private QA fixture tree.

This corpus supports repeatable conformance testing. It is not an independent implementation, an independent security review, or proof that the private exporter is correct.
