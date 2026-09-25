# Contributing

This project is the public browser verifier. Keep every change within the browser-verifier boundary described in `README.md` and preserve fail-closed behavior.

Before proposing a change, run:

```text
npm ci --ignore-scripts
npm test
npm run test:e2e
```

Do not contribute real customer evidence, private keys, recovery packs, credentials, WordPress internals, native application code, generated build output, or fixture-generation code that depends on a private component. New fixtures must be synthetic, documented in `tests/CORPUS.md`, and accompanied by explicit expected results.

Security-sensitive changes should include focused negative tests and fail closed when a required capability or input cannot be validated.
