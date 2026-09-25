# Upgrading to schema v4 (B4 storage foundation)

Schema v4 adds lossless inventory identity, retained typed review evidence and
the storage layout for preparation and admission. It does **not** activate the
v2 harness. Public survey, drilldown and campaign-verification claim gates stay
closed; production triggers and workers continue using the legacy pipeline.
Schema presence alone is not an implemented host or admission API.

The new server applies this migration automatically when opening the database.
This branch also requires the coordinated
[protocol-3 rollout](upgrading-protocol-v3.md). If upgrading from protocol 2,
update server, workers, CLI and web together; there is no mixed-version window.

## Offline upgrade

1. Arrange a maintenance window and disable new submissions. Let in-flight
   work finish where practical, then stop all workers and their automatic
   restarts. Stopping a worker does not clear its persisted lease. With the
   old server still running, wait for abandoned leases to be reaped or cancel
   them explicitly using the old deployment. Cancellation can discard
   unaccepted findings. A limited recent-jobs list cannot establish that every
   lease has cleared; the migration checks the entire jobs table.
2. Stop the old server and every other database user, including shells and
   backup readers. Take and verify a consistent SQLCipher backup using your
   existing tooling, retaining its matching master key securely and the old
   binary/image set. Follow the backup tool's WAL/checkpoint requirements;
   copying the main database file alone is not necessarily a complete backup.
   Loupe does not create or validate the backup for you.
3. Keep exclusive operational ownership of the database through migration.
   WAL and the migration's IMMEDIATE transaction do not prevent another
   process from keeping a reader open. Allow space and startup time for table
   copies, indexes, validation and the journal/WAL.
4. Start the new server with the existing database and key. Check successful
   startup before restarting matching workers and web/CLI clients. Keep all
   review-phase advertisements and production campaign triggers disabled.
5. Inspect existing findings and verification history, then smoke-test queued
   legacy scan and verification work. Confirm protocol 3 and normal CLI/web
   access before resuming submissions.

Queued legacy work can remain: this migration requires no leased jobs, not an
empty queue. The eventual production cutover has a separate activation gate.
Upgrades from schema v1 or v2 also run the intervening migrations; see the
[historical v3 procedure](upgrading-schema-v3.md) for their additional checks.

## Preserved data and new state

Historical inventory IDs and display paths are preserved. Unknown raw Git
path bytes are not guessed from display strings, and old inventory digests do
not certify a newly managed manifest. Trusted pinned-checkout reconstruction
and sealing belong to a later host implementation. Historical findings,
verification details, proofs, identities and provenance remain intact; absent
typed payloads remain explicitly historical, not fabricated evidence.

Preparation, pending-work and admission-accounting tables start without
invented historical records. Existing campaign snapshots are not rewritten,
and this migration does not switch campaign policy or enable phase workers.

## Refusals and recovery

Any leased job causes refusal before v4 table changes. Stop the new server's
restart loop, resolve the lease with the old deployment while workers remain
stopped, then repeat the offline procedure. Never edit schema markers or job
states directly to bypass a refusal.

From schema v3, a failure before commit rolls back the entire v4 migration and
leaves a readable v3 database. From v1 or v2, earlier migrations may already
have committed independently; inspect the reported version rather than
assuming the database is still at its original version. Both version markers
advance to 4 only after copy, foreign-key and integrity validation succeeds.
If restoring foreign-key enforcement fails after commit, startup fails and
discards the connection, but the database is already complete v4. Reopen it
with the new server, not an older binary.

After successful v4 migration, rollback requires restoring the external
backup and its matching key with the matching coordinated binary set. An
older binary cannot open schema v4, so binary-only rollback is not supported.
Restoring a backup loses all writes accepted since it was taken; prefer a
forward fix unless that loss is an explicit operator decision.
