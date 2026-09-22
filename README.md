# ContentLedger Public Verifier

An offline-first browser verifier for public ContentLedger Evidence Bundle v3 packages. Package parsing, hashing, signature verification, identity-history checks, checkpoint proof checks, scope checks, and optional independent comparisons run locally in browser memory. The selected package is not uploaded by this application.

## Current status

This source tree is a **development extraction** (`0.9.0-dev`). It has not completed cross-browser release qualification or independent security review and is not a production public verifier. Ordinary local builds identify themselves as unpublished. An explicitly revision-bound GitHub Pages build identifies itself as a public development preview. The project remains `private: true` in `package.json` to prevent accidental npm publication while it is reviewed.

## Local development

Requirements: Node.js 24 or newer and npm.

```text
npm ci --ignore-scripts
npm test
npx playwright install chromium firefox webkit
npm run test:e2e
npm run dev
```

Open `http://127.0.0.1:1430/`. A production-like static build is created with `npm run build` in `dist-browser/`; `npm run preview` serves it on `http://127.0.0.1:1431/`.

No environment files or runtime network dependencies are accepted by the production build. The generated Content Security Policy sets `connect-src 'none'`.

`npm run test:e2e` builds the production-like static application, starts it on loopback, and exercises package selection, verification, negative packages, cancellation, repeated checks, report downloads, drag/drop, the 128 MiB limit, observed verification-time network silence, keyboard paths, validation and completion focus, WCAG A/AA Axe scans, 200%/400%-equivalent reflow, forced colors, and reduced motion. Chromium and Firefox complete the signed-package workflow. Playwright WebKit is also exercised: it must complete the same signed-package checks when its host provides qualified Ed25519 WebCrypto, or fail closed with the bounded `browser_ed25519_unavailable` or `browser_ed25519_unqualified` capability result. These automated engines complement, but do not replace, testing with assistive technology or qualification in current branded browsers and real Safari on macOS.

On Windows, set `CONTENTLEDGER_WINDOWS_CHANNELS=1` before running `npm run test:e2e` to add the installed Google Chrome and Microsoft Edge channels to the standard Playwright projects. This opt-in keeps the default suite portable on developer machines that do not have both branded browsers installed.

## GitHub Pages development preview

The repository workflow `.github/workflows/public-verifier-pages.yml` runs the complete test suite for relevant pull requests and changes to `main`. Deployment is deliberately manual and is permitted only when all of these conditions hold:

- the workflow is dispatched from the repository's default branch;
- the repository is public, so the matching source remains inspectable;
- the operator types the exact confirmation `deploy development preview`;
- the full test suite passes;
- two production builds have identical paths, byte lengths, and SHA-256 values; and
- the uploaded static artifact records the exact 40-character source revision and the `development-preview` status.

The canonical public source repository is `brianwinum/contentledger-verifier`. The visibility gate intentionally prevents deployment from a private copy. Before the first deployment, set **Settings → Pages → Build and deployment → Source** to **GitHub Actions** and configure protection or required reviewers for the `github-pages` environment as appropriate. Then run **Public verifier Pages** from the Actions page on the default branch and provide the confirmation above. Pushes and pull requests validate the browser project but never deploy it.

GitHub Pages only serves the static HTML, CSS, and JavaScript. Package selection, hashing, and verification remain in browser memory; the production audit rejects application network APIs, and the generated CSP blocks connections. Hosting the app does not make the development preview release-qualified or independently audited.

## Shared site presentation

The header, footer, local fonts, and `src/site-shell.css` mirror the WP ContentLedger root site and certificate repository. This repository carries its own reviewed static copies; the production build does not import another project or fetch remote fonts. `src/site-integration.css` adapts that shared presentation to the checker controls, results, and narrow layouts. Typography licenses are included under `src/assets/` and in **About this checker build → Typography licenses**.

When refreshing shared presentation, preserve checker IDs, native controls, evidence status semantics, and keyboard focus. Keep every production input in `BROWSER_SOURCE_PATHS`, and run the existing build/privacy and browser accessibility checks. Cross-site links are ordinary user-activated navigation restricted to exact reviewed destinations by the production audit; package checking itself remains local and cannot initiate network connections.

## Repository boundary

This project contains only browser verifier source, public specifications and schemas, and synthetic public evidence packages used for conformance tests. It intentionally excludes:

- WordPress/PHP plugin source and database code
- desktop/Tauri adapters and native binaries
- evidence-package exporters and fixture generators
- signing keys, private identity material, and recovery packs
- deployment credentials and private hosting configuration

`npm run test:boundary` enforces this separation. Fixture provenance and limits are documented in [tests/CORPUS.md](tests/CORPUS.md).

## Verification limits

A passing result means the carried package satisfied this verifier's supported offline checks. It does not prove authorship, ownership, content truth, current website state, exclusive key custody, trusted time, or completeness beyond the supplied package. Timestamp proofs receive structural checks only; archive references receive metadata checks only.

## License

GPL-2.0-or-later. See [LICENSE](LICENSE) and [THIRD-PARTY-NOTICES.md](THIRD-PARTY-NOTICES.md).
