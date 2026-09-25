# Protocol 3 rollout

Protocol 3 adds explicit review-phase lease payloads distinct from legacy
scan and verification. It requires a coordinated update of loupe-server,
loupe-worker, loupectl and loupe-web: these clients require an exact protocol
version. There is no protocol-2/3 compatibility window.

This foundation does **not** activate the v2 harness. Phase claim gates remain
closed, current workers advertise no review capabilities, and unexpected
review leases are rejected before repository preparation or legacy handlers.
Production triggers still use the legacy pipeline. Adding wire types is not
evidence that phase endpoints, migration v4, body limits, or admission policy
are implemented.

## Upgrade procedure

1. Disable scheduled/manual submissions and let existing work drain, or cancel
   it using the old deployment. Stop workers before stopping the old server.
2. Back up the database using the deployment's normal offline backup procedure.
   This protocol-only slice does not introduce a new database migration.
3. Update server, workers, CLI and web together. Do not run protocol-2 clients
   against a protocol-3 server or vice versa.
4. Start the server and confirm its health response/header reports protocol 3.
   Start the matching web and workers, retaining empty review advertisements.
5. Smoke-test a legacy scan, finding ingestion and legacy verification using
   the deployment's normal test repository. Confirm CLI/web access and that
   no survey, drilldown or campaign verification is publicly leased.
6. Resume legacy submissions. Keep campaign triggers disabled until all B4
   server handlers and the corresponding later worker gates are complete.

Existing unrelated legacy routes retain their optional request-header behavior;
version-bearing bodies and supplied headers still require the current exact
version. Required phase-route headers will be enforced with those routes.

If smoke tests fail, stop the new processes and roll back the coordinated
binary set. This slice leaves schema v3 unchanged; if later migrations were
also deployed, follow their offline rollback runbook rather than assuming
an older binary can open a newer database.
