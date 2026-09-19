# Third-party notices

The Ed25519 verifier's qualification corpus includes test vectors from RFC 8032 and the Web Platform Tests project. RFC 8032 is cited as a standards source. The Web Platform Tests vector attribution and BSD 3-Clause terms are retained verbatim in `src/verifier/ed25519-vectors.ts` and in generated JavaScript that contains those vectors.

Development/build dependencies are pinned in `package-lock.json` and retain their own licenses. They are not application runtime services: Vite and `tsx` are MIT-licensed; TypeScript and `@playwright/test` are Apache-2.0-licensed; `@axe-core/playwright` is MPL-2.0-licensed; and `@types/node` is MIT-licensed. Transitive development dependency notices remain in their distributed packages.
