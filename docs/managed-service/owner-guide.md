# Owner guide

This guide covers the bounded managed certificate service with WP ContentLedger v0.13.26. Normal connection happens inside WordPress; a developer, DNS edit, or server-side key file is not normally required. Hosting must support the plugin's PHP requirements, native Sodium, HTTPS, and public site-control checks. Read the [preview details](public-preview.md) for availability, limits and public-data handling.

## Set up

1. Back up the site's files and database. Obtain the signed v0.13.26 package through the existing [plugin distribution channel](https://buy.wpcontentledger.com/), or contact support for installation access. Install using the supported plugin installation/update path. The private source repository is not a public download link. Keep the exact ZIP and release attestations if verifying the package independently.
2. Open **ContentLedger → Website Identity**. Prepare an Identity Recovery Pack with a strong password, save it safely, test that exact file, then commit the identity change using the saved-and-tested confirmation. Keep both the file and password private, in separate protected locations. An Active identity is required; Prepared is not committed.
3. Check that the intended signing and automatic recording options are enabled for **Posts** and **Pages**. Identity setup, recording settings, and repository connection are separate steps.
4. In **ContentLedger → Certificates**, review the editable email prefilled from WordPress's administrator email, consent to requesting a code, and request it. No manual email approval is required while bounded enrollment is available. Enter the emailed code, select the intended content types, review the connection consent, and connect. The service verifies control of the exact public HTTPS root origin and binds its Website Identity. Connection codes expire; never post them in support threads. A full service or exhausted delivery budget can deny admission.
5. Check the signed connection status and allowances. Create a marked synthetic public page without confidential data, wait for acceptance, update it once, save it unchanged, and return it to Draft. Confirm the update creates another revision, the unchanged save does not, and Draft withdraws the public certificate. Remove the test content from normal navigation.

Connecting does not automatically backfill the site's entire publication history. Use only an explicitly supported recording/backfill operation after reviewing scope and remaining allowances. Do not reset identity or clear retained evidence to fix a connection problem.

## Everyday operation

Eligible publication queues a certificate submission; a content change queues a new revision of the same work. Acceptance and a repository receipt confirm delivery. Pending means it has not yet been confirmed. Unchanged content should not manufacture another certificate revision.

The hosted service prompts WordPress to perform scheduled checks, normally about five minutes after the previous completed check. WordPress recording intervals, retries, provider delays and outages can lengthen delivery. It is not a five-minute publication guarantee. The plugin must first produce eligible native evidence; the repository cannot certify evidence that the site has not created.

**Pause** stops new and updated certificate publication while safety tasks such as withdrawals and pending delivery reconciliation can continue. Draft, private, or otherwise ineligible source content should withdraw its certificate; confirm that acknowledgment rather than assuming a WordPress status change was delivered instantly.

The current new-site preview allowance is **10 works, 50 certificate revisions per UTC calendar month, 16 MiB of retained primary evidence, one concurrent submission, and 500 admitted attempts per month**. Work and retained-storage usage do not reset each month. Withdrawn evidence remains counted. The plugin's signed status is the authoritative per-site readback; older manual publishers can have different limits. Limits protect service capacity and are not a paid plan or promise of unlimited storage.

## Common questions

**What is in a certificate?** A version record links the source URL, claimed author and publisher, dates, version relationships, and content/evidence fingerprints to retained verification material. A site signature proves verification against its signing key. Archive captures and Bitcoin-attested timestamp proofs are separate optional evidence; their absence is not silently replaced by a repository receipt.

**What does “verified” mean?** Read each evidence result. An accepted certificate may be valid with limitations: signature and binding verified while authorization, content comparison, or independent timestamp evidence remain unresolved or absent. It is not a legal copyright determination or proof that every metadata claim is true.

**Where do I check evidence?** Visit the certificate URL, use the [online checker](https://verify.wpcontentledger.com/), or use the packaged offline verifier. The online checker and repository acceptance are distinct checks. Retain a native evidence bundle when you need portable verification.

**Will my certificates appear in search?** Connection does not enable indexing. Reviewed managed certificates can become eligible only with an active publisher and a fresh signed positive source preference for the current revision. Unknown or restrictive preferences, withdrawal, pause and recovery suppress eligibility. The current review list is empty. SEO benefits are not guaranteed.

**Does noindex make a certificate private?** No. The exact certificate URL and evidence can remain public. Use source withdrawal for suppression of public details; search engines and third-party copies may take time to update.

**What information leaves my site?** Approved publication sends the certificate's metadata and compact native verification evidence, including source URL, fingerprints, and claimed author/publisher details. Site-control and scheduling checks contact the site. This is not a PDF archive or an article-file hosting service. Do not assume compact evidence contains no personal data; review it and the consent before publication. Private keys and the Identity Recovery Pack stay on your side.

**Will I get an alert email?** Connection codes go to the contact email submitted with consent. Current service incident emails go to the operator, with new durable managed connections automatically included in that monitoring scope; per-owner failure emails are not automatically provisioned. Check the plugin's signed status and contact support when delivery remains unresolved.

## Troubleshooting and support

| Symptom | Action |
| --- | --- |
| `wal_website_identity_producer_sodium_unavailable` or `wal_website_identity_runtime_sodium_unavailable` | Ask the host to enable native PHP Sodium for the PHP version serving WordPress, then retry the interrupted operation. For an existing identity, preserve it and retry verification; do not create a replacement. Recheck the extension after a hosting PHP change. A conflicting `pdo_mysql` warning does not prove Sodium failed; do not disable the site's required MySQL driver to solve it. |
| Recovery Pack test passed, identity still Prepared | Confirm the exact pack was saved and tested, then commit the retained identity change. Do not create a replacement identity merely to finish this step. |
| No connection code | Confirm the email and exact public HTTPS root origin, then request a code once. A generic accepted request does not prove admission or inbox delivery. Check spam, expiry, the one-hour resend cooldown, service capacity and delivery budgets with the operator. Ambiguous sends are not automatically resent. |
| Certificate remains Pending | Read the recorded failure/status and last-check age. Verify public HTTPS accessibility, native evidence eligibility, recording settings, and allowances. Let bounded retries run; repeated clicking can consume attempts. |
| Status is old or unavailable | Treat it as unknown, not healthy. Report the last successful status time and sanitized error code. Do not paste connection tokens or database credentials. |
| Site moved, cloned, or restored | Pause expansion and contact the operator before reconnecting. The origin and authority are bound; another invitation is not a takeover or recovery shortcut. |

For preview support contact **bw@brianwinum.com**. Include the plugin/PHP versions, exact public origin, sanitized error, time and time zone, and affected certificate URL if appropriate. Never send passwords, connection codes, private keys, or Recovery Packs. Report suspected security issues privately to the same address, separately from routine support; use synthetic evidence and do not post exploit details in a public issue.

Operational action-required notices identify the affected website and condition. A **Condition cleared** notice applies only to that condition on that website; it is not a claim that every service check passed. Current operator alerts do not automatically enroll each site owner for email notifications.
