# Windows browser qualification record — 0.9.0-dev

Executed September 19, 2026 (America/New_York). This records the Windows checks
that were actually observed for the local browser checker. It is not a release
approval, independent security review, macOS qualification, or proof of complete
network silence.

## Environment

- Windows NT 10.0.26200.0, Arm64
- Microsoft Edge 153.0.4234.32
- Google Chrome 152.0.7977.83
- Node.js 24.17.0; npm 11.13.0
- Checker 0.9.0-dev; verifier browser-0.9.0-dev
- Reported build-source SHA-256:
  `fc8dbb6d7ef6d8f24391dbdbb7b93e6d2451b7257e0e1bf745009d37d96ce595`
- Source revision was not embedded in the development build. The public verifier
  directory was an untracked local worktree during this run.
- Playwright 1.63.0 and `@axe-core/playwright` 4.13.0 were used for the
  automated accessibility qualification added later that day.

## Fixtures

| Fixture | Size | SHA-256 | Purpose |
| --- | ---: | --- | --- |
| `site-chain.zip` | 76,492 bytes | `2f954c30e6ae3b6e41b3645cabdd84099497aa1c06ed8b9e115f61188654b018` | Supported package and report checks |
| `large-supporting-artifacts.zip` | 3,054,206 bytes | `ef6879fcf0ebc87487f4746cd43f5c89bb47351353098d27a6f8f4674b637bc3` | Larger valid package |
| `oversized-129mib.zip` | 135,266,304 bytes | `6315bc4997f3c9daa658eca781df65955cb4f2ab9481dfa5ae1ddb4baa12bd43` | Above-limit selection rejection |

`offline-site-chain.zip` was a local non-OneDrive copy of `site-chain.zip` and
had the same size and SHA-256. It was created only to avoid a native file-picker
automation limitation; the package bytes were unchanged.

## Executed observations

| Browser | Check | Observed result | Status |
| --- | --- | --- | --- |
| Chrome | Select and check `site-chain.zip` | `passed_with_limitations`; `browser_profile_checks_complete`; 17 checks | Passed |
| Chrome | Save and read ordinary report | 4,375-byte JSON; package SHA-256, versions, outcome, codes, limitations and 17 redacted checks present | Passed |
| Chrome | Keyboard focus order | Visible focus traversed report, disclosures, Check again, comparisons and chooser; no trap observed in the tested path | Passed |
| Chrome | Larger valid package | 3,054,206-byte fixture passed all 17 checks | Passed |
| Chrome | Above 128 MiB | Rejected at selection with the expected size-limit message; verification was not enabled | Passed |
| Chrome | Hosting server stopped | Already-loaded 3 MiB package passed all 17 checks after the loopback preview process was stopped | Passed |
| Edge | Select and check `site-chain.zip` | `passed_with_limitations`; `browser_profile_checks_complete`; 17 checks | Passed |
| Edge | Save and read ordinary report | 4,375-byte JSON; expected package SHA-256, versions, outcome, codes, limitations and 17 redacted checks present | Passed |
| Edge | Keyboard focus order | Visible focus traversed report disclosures, Check again and comparisons; no trap observed in the tested path | Passed |
| Edge | Larger valid package | 3,054,206-byte fixture passed all 17 checks | Passed |
| Edge | Above 128 MiB | Rejected at selection with `Choose one accessible Evidence Bundle v3 ZIP file no larger than 128 MiB.` | Passed |
| Edge | Hosting server stopped | Baseline passed 17 checks; the exact Vite preview listener on port 1460 was stopped and the port verified unavailable; Check again then passed all 17 checks without reloading | Passed |

The Edge valid-file selection used the native chooser. Automation could select
the oversized file but did not reliably deliver later valid selections from the
OneDrive-backed directory, so the operator manually selected the byte-identical
non-reparse-point copy for the final server-stopped test. This is an automation
limitation, not an observed checker failure.

## Automated accessibility and reflow qualification

The accessibility suite was run on Windows against Playwright Chromium
153.0.8010.12, Firefox 155.0, WebKit 26.6, installed Chrome 152.0.7977.83, and
installed Edge 153.0.4234.32. Eighteen checks passed and two engine-inapplicable
forced-colors checks were skipped.

| Coverage | Observed result | Status |
| --- | --- | --- |
| WCAG A/AA Axe scan | No violations reported in the initial, expanded-comparison, invalid-input, or completed-result states in all five engines | Passed with automated-scan limitation |
| Keyboard path | Header/chooser/disclosure/field order, native disclosure operation, implicit Enter submission, and absence of a tested focus trap passed; WebKit either includes the header link or begins at the first form control according to the host keyboard model | Passed |
| Validation focus | Invalid comparison value exposed `role=alert`, `aria-invalid`, and `aria-errormessage`, then returned focus to the field | Passed |
| Completion focus and announcement | Completed failure focused the result summary and populated the polite status announcement | Passed |
| 200%/400%-equivalent reflow | Completed interface at 640- and 320-CSS-pixel viewport widths had no document-level horizontal overflow and retained usable chooser/report controls | Passed |
| Windows forced colors | Chromium, installed Chrome, and installed Edge retained visible focus outlines and control boundaries under forced-colors/high-contrast emulation | Passed with emulation limitation |
| Reduced motion | Chromium-family engines removed the progress animation when reduced motion was requested | Passed |

Automated Axe scans cannot prove WCAG conformance, and viewport/media emulation is
not the same as operating Windows Narrator, browser zoom controls, or Windows
Contrast Themes by hand. Those manual assistive-technology checks remain open.

## Report custody

| Browser | Saved filename | Size | Saved-file SHA-256 |
| --- | --- | ---: | --- |
| Chrome | `contentledger-check-summary-2f954c30e6ae-20260919T171531Z.json` | 4,375 bytes | `82f66e32bee0b0d9d5c2b45b8d09879be5becd7f0373b9987270ce249d9b0efd` |
| Edge | `contentledger-check-summary-2f954c30e6ae-20260919T173747Z.json` | 4,375 bytes | `849c4e0b03a7ed3d9e9bed058fed13e2df3a2e9f3fe9120ba8f875885fd03835` |

The saved reports were read back locally. Their differing file hashes are
expected because their check timestamps differ.

## Still open

- macOS Safari/Chrome and VoiceOver testing
- Windows Narrator testing
- Manual browser 200%/400% zoom, Windows Contrast Themes, and OS text-enlargement testing
- Manual branded Firefox testing; automated Firefox checks pass
- Full browser request capture and host-level network observation
- Fully disconnected operation and offline-distribution cold start
- Independent security and cryptographic review

The server-stopped checks establish only that an already-loaded page can verify
locally without its loopback host. They do not establish a disconnected cold
start or silence by every process on the machine.
