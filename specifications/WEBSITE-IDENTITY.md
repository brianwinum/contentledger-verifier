# Website Identity — pre-v1 native profile

Version: 0.13.1. Status: candidate, not independently reviewed for public v1.

Method semantics remain pinned to the DIF did:webvh v1.0 specification commit `8e3bbc39bb3d6456a89bd33985568d42306b1625` and its official test-suite commit `f792ce4568c8c3efb3b6a055a1c2ba963dc00c35`. The production verifier applies the restricted Ed25519 / `eddsa-jcs-2022` / RFC 8785 / SHA-256 rules represented by the retained interoperability fixtures. Historical development specifications are under repository `qa/spec-history`, not shipped as alternative product contracts.

## One method

New sites create a did:webvh identity directly. There is no did:web signing identity, parallel adoption, signing cutover, mixed-identity export, or legacy signing kit. The immutable JSONL history is the public authorization source.

Existing strict production verification and deterministic public-material composition are reused. Some internal class names retain development-stage labels; those names do not enable an old migration workflow.

## Three roles, one recovery format

- Assertion key: signs content and transparency evidence.
- Active update key: authorizes the next did:webvh log operation.
- Committed successor: the pre-rotated update key committed by the current log.

An append consumes the committed successor and commits a new successor. Assertion rotation and compromise operations also advance the log. Every identity change is prepared as a new password-encrypted **Identity Recovery Pack**. The administrator downloads and uploads those exact bytes for testing before commit. Only after the committed state, all three roles, and the public log read back exactly does that same tested file become the current pack; no second post-commit pack ceremony is required.

One password-encrypted portable format carries the exact three-role inventory and authenticated identity/operation bindings. Download the file and test those exact bytes. Wrong passwords, altered files, crossed operations, stale state, and mismatched keys fail closed. A generated-file notification or download attempt does not prove file custody.

The site vault uses a site protector. The portable pack has separate password-derived encryption and is not a copy of that protector. Store the pack and password separately.

Internet Archive credentials are not identity keys or part of this pack. Restore them from normal site backups or re-enter them from the Internet Archive account. Updating them does not invalidate identity recovery readiness.

## Workflow and state

The Website Identity screen exposes explicit bounded administrator actions: prepare, download, test, commit, cancel before commitment, and resume an interrupted commit. Operations cover genesis, update-key advancement, assertion rotation, containment, and controlled or unilateral assertion replacement. Preparing an operation immediately pauses new signing and redirects to the prepared-change panel. From that panel, download and save the retained Recovery Pack, test that exact saved file, then commit or cancel before commitment starts. No manual page refresh is needed. A blocked or cancelled download can be retried using the same retained-file action; it does not prepare another operation. A download attempt does not prove custody or automatically commit. This server-rendered sequence works without JavaScript.

Preparations expire. Cancellation cannot undo a journaled public operation. Once commitment starts, recovery is forward-only: validate the retained journal and complete the exact operation. Signing is blocked during incomplete operations, containment, invalid state, or missing current recovery readiness.

A retained journal is the forward-repair authority through state, role, recovery-readiness, and cleanup phases. Signing stays paused until the readiness record and journal cleanup read back exactly. Creating and testing another pack later is optional for another encrypted backup or a new pack password. This does not revoke previously saved valid copies for the same identity state; protect every copy and its password. An actual identity change, not re-encryption alone, changes which state is current.

An authentic older journal is not authority over a newer committed identity. Every resumed post-publication phase first authenticates and matches the exact current public state, before accessing or repairing private roles. A missing, corrupt, or mismatched current state fails closed; the rejected journal is retained for diagnosis, never silently deleted or used to roll back the current identity.

Pack restore does not interleave with a retained commit journal. Resume Commit can use that authenticated journal to repair a missing/unreadable vault provider and the exact three Website Identity roles while preserving unrelated Internet Archive ciphertext. The matching WordPress security salts are still required to authenticate and decrypt the journal; if those salts are lost, restore them from a coherent site backup. Never delete the journal or substitute a pack restore for its forward-only authority.

Native state and coordination are site-scoped and authenticated. Raw database reads and compare-and-swap boundaries, not object-cache answers, determine operation authority. Updates and destructive operations must not interleave with identity work.

The committed public log remains independently readable during an interrupted finalization, but publication alone never enables signing.

### Readiness is not private-key verification

From v0.13.11, the read-only state projection also checks bounded private-storage
metadata: required encrypted-role envelope shape and protector availability.
It never reads protector-file contents, derives a key, decrypts a private role,
initializes a provider, acquires a mutation lock, or writes state. Detectable
missing or malformed storage makes an otherwise active identity recovery-required
and pauses its signing-readiness projection. Prepared operations, retained commit
journals and containment retain their own higher-priority workflow guidance.

Passing that metadata check means only `not_verified`, never cryptographic
verification. A readable same-size wrong protector, corrupted ciphertext or
changed private-key bytes may remain undetected until the existing locked
signing/recovery action validates the exact key bindings. A recorded successful
Recovery Pack test is a historical fact, not proof that the installed keys remain
readable. System Status therefore reports signing readiness rather than claiming
to have tested signing capability.

If private storage is unavailable, use **Restore this identity from a saved pack**
with the exact current Recovery Pack and its password. A read-only pack test
cannot restore missing installed keys. An interrupted commit still requires its
authenticated forward-repair workflow, not a competing pack restore. These
diagnostics change no identity format, public log, recovery authority or evidence.

## Optional transparency checkpoints

With an active, recovery-current identity, enable signing in Settings and seal content before using **Create and publish current checkpoint** in Website Identity. That explicit action signs the exact eligible sealed-record set and current public identity history, retaining and publishing its exact public-only receipt as part of the same workflow. There is no separate manual receipt-retention or receipt-test prerequisite.

Opening the checkpoint panel only previews known public prerequisites. It does not decrypt signing keys, retain a receipt, create or publish a checkpoint, schedule a job, or contact a provider. Private-role and recovery bindings are rechecked by the actual locked action; a ready preview is not a guarantee that a later action can succeed after the site changes.

Retained checkpoints and identity receipts remain available after identity advancement. Their signatures and custody bindings are not rewritten to match a newer head. Internet Archive and OpenTimestamps enrollment is explicit and separate; queue controls identify the exact subject and provider. A checkpoint proves inclusion in a particular signed tree, not completeness, authorship, trusted time, or independent custody.

## Public verification and limits

GET and HEAD serve independently verified JSONL at the canonical HTTPS home route. Exact bytes, length, SHA-256, strong ETag, content type, method rules, and bounded readback are verification inputs. On cache mismatch, retry without cache and fail closed if consistency cannot be established.

This is a restricted did:webvh profile: 128 entries, 1 MiB log, three separate Ed25519 roles, and continuous update-key pre-rotation. Capacity exhaustion must not truncate history. Native Sodium and 64-bit PHP 8.2+ are required for private-key operations.

Domain/controller movement is deferred. Choose the permanent canonical HTTPS address before setup. Containment cannot retract earlier signatures or prove which preceded a compromise. A self-hosted log is not an independent witness; archives and timestamps add separate evidence. Losing both site keys and their current recovery material may make continuity unrecoverable.

A saved pre-commit pack proves only its authenticated encrypted contents. It does not claim that commit or publication occurred, and cancellation does not revoke copies already saved. Restoring such a pack on an absent same-site installation is an explicit administrator recovery action; a different existing Website Identity is never replaced by it.
