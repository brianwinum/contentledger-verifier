# Contributing

This project is currently a development preview. Keep every change within the public browser-verifier boundary described in `README.md`.

Before proposing a change, run:

```text
npm ci --ignore-scripts
npm test
```

Do not contribute real customer evidence, private keys, recovery packs, credentials, WordPress internals, native application code, generated build output, or fixture-generation code that depends on a private component. New fixtures must be synthetic, documented in `tests/CORPUS.md`, and accompanied by explicit expected results.

Security-sensitive changes should include focused negative tests and fail closed when a required capability or input cannot be validated.
