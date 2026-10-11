# WP ContentLedger managed certificate preview

WP ContentLedger connects eligible public WordPress pages and posts to a
separate certificate repository. This limited production preview admits up to
**ten retained sites in total**, subject to availability and the limits below.
Connection happens in the plugin: request an emailed code, prove site control
automatically, and confirm public evidence publishing. No manual email approval
or routine developer setup is required.

## Connect your site

Use the current signed **v0.13.24** release and follow the
[owner setup guide](owner-guide.md). You need a single WordPress installation
at its public HTTPS root origin, WordPress 6.2 or newer, PHP 8.2 or newer with
native Sodium, and an
Active Website Identity with its exact Recovery Pack saved and tested.
Posts and Pages are the supported publication types. A code request does not
reserve a slot or guarantee delivery; codes expire after one hour. Connection
does not start a whole-site backfill.

Obtain the signed package through the existing
[plugin distribution channel](https://buy.wpcontentledger.com/); contact support
if you need installation access. The source/release repository is private and
is not a public download destination. Software licensing and
hosted-service admission are separate: a software copy or a purchase does not
bypass site-control checks, quotas or service capacity. No paid hosted tier,
license-key enrollment requirement or unlimited certificate entitlement is
offered by this preview.

## Your publishing allowance

| New managed site | Limit |
| --- | --- |
| Recorded works | 10 retained works |
| Accepted certificate revisions | 50 per UTC calendar month |
| Primary evidence | 16 MiB retained total |
| Concurrent submissions | One |
| Admitted submission attempts | 500 per UTC calendar month |

An update uses accepted-revision capacity; an exact duplicate does not charge
again. Works and retained storage do not reset monthly. Withdrawal does not
free historical storage or an admission slot. Older manual publishers may have
different allowances. Check the plugin's signed status for your site's actual
limits and remaining usage; contact support before starting a large import.

## Public information and search

Publishing sends source URLs, version metadata, fingerprints, claimed author
and publisher details, and compact native verification evidence to the
repository. Review the evidence before publishing personal or confidential
information. Noindex is not privacy: an active certificate and its evidence
may remain accessible at their exact public URLs.

Certificates are excluded from indexing by default. Search eligibility requires
an individually reviewed work and a fresh signed positive source preference,
with the current source's robots directives, canonical and attribution checked.
Connection alone never grants indexing. Withdrawn certificates, old revisions,
APIs and evidence downloads remain excluded. Search engines decide whether to
index eligible pages; no ranking, rich-result or AI-citation benefit is promised.

The [certificate repository](https://certificates.wpcontentledger.com/) shows
individual records and checks. Its browse list can be empty while exact-link
verification works. The [package checker](https://verify.wpcontentledger.com/)
runs public evidence-bundle checks locally in your browser without uploading
the bundle; it does not accept Recovery Packs or private keys. Check each
result's scope, including timestamp and signing-authorization limitations.

## Operator and data handling

The service is operated by **Brian Winum**, separately hosted from participating
WordPress sites. Separate hosting is not independent governance or a legal
determination of authorship, copyright, originality or factual accuracy.
Cloudflare provides hosted processing, storage and email delivery. GitHub holds
encrypted recovery artifacts and source/release assets. UptimeRobot checks
public service health. Local private signing keys and Recovery Packs stay with
the site owner; never send them to the operator.

Connection requests transmit the contact email and public origin with consent.
The admission registry uses hashes for email/IP budget matching; the email
provider necessarily receives a delivery address. This does not mean provider
logs or WordPress contain no identifying information. Certificate publication
and routine support use separate information and purposes.

Draft/private or otherwise ineligible source content should trigger withdrawal.
Confirm its repository acknowledgment: withdrawal suppresses public details
and evidence downloads, while receipts and recovery material remain retained.
It is not physical erasure of all historic bytes, search caches or downloaded
copies. Successful scheduling jobs are eligible for pruning after 30 days and
expired transient admission data after seven days; unresolved incidents,
evidence, receipts and authority records are retained. Routine uninstall does
not erase the site's retained plugin data.

## Availability and recovery

Delivery, archive captures, timestamp completion and hosted checks are
asynchronous. The preview has no fixed delivery or response-time SLA, guaranteed
permanent storage, or universal recovery-time/recovery-point promise. Preserve
your own WordPress backups, Recovery Pack and supported portable evidence
exports. A repository checkpoint covers immutable certificate history, not
your WordPress files, database, private keys or every mutable service record.

Daily signed checkpoints, encrypted off-source archives, tested closed replay,
operator alerts and independent health monitoring protect the current service
within their documented bounds. Expansion pauses on unresolved privacy,
integrity, delivery, recovery or cost issues. Support handles migration,
restoration, capacity exhaustion and closure individually; creating a new
identity or code is not a recovery shortcut. Retain portable evidence rather
than depending on indefinite hosted access.

## Help and incident reporting

Contact **bw@brianwinum.com** for setup and operational support. Include plugin
and PHP versions, the public site origin, a sanitized error, time and time zone,
and the affected public certificate URL when useful. Never send passwords,
connection codes, private keys, database exports or Recovery Packs. Current
failure/recovery alerts go to the operator; owner-specific incident emails are
not automatically provisioned. Support is operator-managed with no promised
round-the-clock response window.

Report suspected security issues privately to bw@brianwinum.com. Use synthetic
evidence and a sanitized reproduction; do not post exploit details or private
data in a public issue. The owner reports independent review of v0.13.23,
including security and cryptographic design. Newer changes have separate
first-party qualification. This bounded preview is not unrestricted public v1
acceptance or an independent audit of every subsequent deployment.
