# Protocol 3 rollout

Protocol 3 adds explicit review-phase lease payloads distinct from legacy
scan and verification. It requires a coordinated update of loupe-server,
loupe-worker, loupectl and loupe-web: these clients require an exact protocol
version. There is no protocol-2/3 compatibility window.

The server supports the pre-proof survey, drilldown and verification API,
including claim-time admission. Only explicit `review:survey:v1`,
`review:drilldown:v1` and `review:verify:v1` advertisements enable those leases;
legacy `verify:*` tags never do. Current workers advertise none and reject
unexpected review leases before checkout or legacy handling. B5–B7 supply
worker execution; production triggers remain legacy until the later cutover.
Reconciliation, successors and corroboration remain B8-held, and proof
execution/attestation remains Stage C work. Server API availability is not
end-to-end v2 activation or a deployment claim.

## Upgrade procedure

1. Disable scheduled/manual submissions and let in-flight work finish, or
   cancel it using the old deployment. Queued legacy work may remain. Stop
   workers before stopping the old server.
2. Follow the [schema-v4 offline procedure](upgrading-schema-v4.md), including
   clearing persisted leases, stopping all database users and verifying a
   recoverable SQLCipher backup with its matching master key.
3. Update server, workers, CLI and web together. Do not run protocol-2 clients
   against a protocol-3 server or vice versa.
4. Start the server and confirm its health response/header reports protocol 3.
   Start the matching web and workers, retaining empty review advertisements.
5. Smoke-test a legacy scan, finding ingestion and legacy verification using
   the deployment's normal test repository. Confirm CLI/web access and that
   no survey, drilldown or campaign verification is leased to these legacy
   advertisements. Do not add review capabilities to a worker whose handler
   has not been implemented and verified.
6. Resume legacy submissions. Keep production campaign triggers disabled
   until the later worker and cutover acceptance gates are complete.

Existing unrelated legacy routes retain their optional request-header behavior;
version-bearing bodies and supplied headers still require the current exact
version. New phase routes require one exact version header as well as the
version-bearing body where applicable. Phase failures and heartbeats share
legacy URLs but use their strict phase payloads and transaction-time authority.

New campaigns freeze policy version 2 and charge preparation once. Existing
version-1 snapshots are retained as compatibility-held work, never silently
rewritten using current defaults. Incompatible rebuildable state can be reset
only through the explicit quiescent admin operation described in the
[schema-v4 runbook](upgrading-schema-v4.md#incompatible-derived-review-state).

If smoke tests fail, stop the new processes. After a successful v4 migration,
rollback requires restoring the pre-upgrade database backup and matching
coordinated binary set as described in the schema runbook. Merely replacing
the binaries cannot downgrade the database.
Backup restoration discards writes accepted since the backup.
