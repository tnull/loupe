//! Schema v4 storage contracts. Published v1–v3 DDL remains unchanged.

pub(super) const REBUILDS: &str = r#"
CREATE TABLE generation_inventory_new (
    inventory_entry_id INTEGER PRIMARY KEY,
    generation_id      INTEGER NOT NULL REFERENCES review_generations(generation_id) ON DELETE CASCADE,
    path               TEXT NOT NULL,
    blob_sha           TEXT,
    entry_kind         TEXT NOT NULL CHECK (entry_kind IN ('tracked','submodule')),
    disposition        TEXT NOT NULL DEFAULT 'unresolved'
                            CHECK (disposition IN ('mapped','context','excluded','unresolved')),
    disposition_reason TEXT,
    highlighted        INTEGER NOT NULL DEFAULT 0,
    created_at         INTEGER NOT NULL,
    raw_path           BLOB CHECK (raw_path IS NULL OR (typeof(raw_path) = 'blob' AND length(raw_path) BETWEEN 1 AND 65536)),
    source_path        TEXT CHECK (source_path IS NULL OR length(CAST(source_path AS BLOB)) BETWEEN 1 AND 512),
    manifest_position  INTEGER CHECK (manifest_position IS NULL OR manifest_position >= 0),
    git_mode           INTEGER CHECK (git_mode IS NULL OR git_mode IN (33188,33261,40960,57344)),
    disposition_revision INTEGER NOT NULL DEFAULT 0 CHECK (disposition_revision >= 0),
    CHECK (source_path IS NULL OR raw_path IS NULL OR CAST(source_path AS BLOB) = raw_path),
    CHECK (manifest_position IS NULL OR
           (raw_path IS NOT NULL AND git_mode IS NOT NULL AND blob_sha IS NOT NULL
            AND length(blob_sha) IN (40,64) AND blob_sha NOT GLOB '*[^0-9a-f]*'
            AND ((git_mode = 57344 AND entry_kind = 'submodule')
                 OR (git_mode <> 57344 AND entry_kind = 'tracked'))))
);

CREATE TABLE finding_review_details_new (
    finding_id         INTEGER PRIMARY KEY REFERENCES findings(id) ON DELETE CASCADE,
    repo_id            INTEGER NOT NULL REFERENCES registered_repos(id) ON DELETE CASCADE,
    workflow_contract_version INTEGER NOT NULL,
    profile_version    INTEGER NOT NULL,
    profile_digest     BLOB,
    reviewed_commit_sha TEXT NOT NULL,
    identity_family    TEXT NOT NULL,
    identity_anchor    TEXT NOT NULL,
    identity_instance_key TEXT,
    identity_fingerprint BLOB NOT NULL,
    l2_argument        TEXT,
    counterevidence    TEXT,
    assumptions_gaps   TEXT,
    confidence         TEXT CHECK (confidence IN ('low','medium','high')),
    submitted_rung     TEXT NOT NULL CHECK (submitted_rung IN ('L2','L3')),
    origin_lead_id     INTEGER REFERENCES leads(lead_id) ON DELETE SET NULL,
    created_at         INTEGER NOT NULL,
    evidence_payload   TEXT,
    UNIQUE (repo_id, identity_fingerprint),
    FOREIGN KEY (repo_id, finding_id) REFERENCES findings(repo_id, id) ON DELETE CASCADE,
    CHECK ((evidence_payload IS NULL AND l2_argument IS NOT NULL
            AND counterevidence IS NOT NULL AND assumptions_gaps IS NOT NULL AND confidence IS NOT NULL)
        OR (evidence_payload IS NOT NULL AND l2_argument IS NULL
            AND counterevidence IS NULL AND assumptions_gaps IS NULL AND confidence IS NULL
            AND submitted_rung = 'L2'))
);

CREATE TABLE verification_attempt_details_new (
    verification_id    INTEGER PRIMARY KEY REFERENCES finding_verifications(id) ON DELETE CASCADE,
    workflow_contract_version INTEGER NOT NULL,
    checkout_commit_sha TEXT NOT NULL,
    established_rung   TEXT CHECK (established_rung IN ('L2','L3','L4')),
    e2e_applicability  TEXT CHECK (e2e_applicability IN ('applicable','not_applicable')),
    e2e_rationale      TEXT,
    blocker           TEXT,
    retry_condition   TEXT,
    verification_proof_id INTEGER,
    terminal_digest   BLOB NOT NULL,
    created_at        INTEGER NOT NULL,
    evidence_payload  TEXT,
    FOREIGN KEY (verification_id, verification_proof_id)
        REFERENCES verification_proofs(verification_id, verification_proof_id),
    CHECK ((evidence_payload IS NULL AND e2e_applicability IS NOT NULL)
        OR (evidence_payload IS NOT NULL AND established_rung IS NULL
            AND e2e_applicability IS NULL AND e2e_rationale IS NULL
            AND blocker IS NULL AND retry_condition IS NULL AND verification_proof_id IS NULL))
);
"#;

pub(super) const ADDITIONS: &str = r#"
ALTER TABLE jobs ADD COLUMN prepared_attempt INTEGER CHECK (prepared_attempt IS NULL OR prepared_attempt > 0);
ALTER TABLE jobs ADD COLUMN prepared_capability_hash BLOB
    CHECK (prepared_capability_hash IS NULL OR (typeof(prepared_capability_hash) = 'blob' AND length(prepared_capability_hash) = 32));
ALTER TABLE jobs ADD COLUMN prepared_at INTEGER CHECK (
    (prepared_attempt IS NULL AND prepared_capability_hash IS NULL AND prepared_at IS NULL)
    OR (prepared_attempt IS NOT NULL AND prepared_capability_hash IS NOT NULL AND prepared_at IS NOT NULL));
ALTER TABLE job_assigned_review_units ADD COLUMN assignment_epoch INTEGER
    CHECK (assignment_epoch IS NULL OR assignment_epoch >= 0);

CREATE UNIQUE INDEX idx_inventory_generation_entry ON generation_inventory(generation_id, inventory_entry_id);
CREATE UNIQUE INDEX idx_inventory_raw_path ON generation_inventory(generation_id, raw_path) WHERE raw_path IS NOT NULL;
CREATE UNIQUE INDEX idx_inventory_source_path ON generation_inventory(generation_id, source_path) WHERE source_path IS NOT NULL;
CREATE UNIQUE INDEX idx_inventory_position ON generation_inventory(generation_id, manifest_position) WHERE manifest_position IS NOT NULL;
CREATE UNIQUE INDEX idx_generations_repo_generation ON review_generations(repo_id, generation_id);
CREATE UNIQUE INDEX idx_units_generation_unit ON review_units(generation_id, review_unit_id);
CREATE UNIQUE INDEX idx_leads_generation_lead ON leads(generation_id, lead_id);
CREATE UNIQUE INDEX idx_jobs_generation_job ON jobs(generation_id, id);
CREATE UNIQUE INDEX idx_jobs_campaign_job ON jobs(campaign_id, id);
CREATE UNIQUE INDEX idx_results_unit_producer_result ON review_unit_results(review_unit_id, produced_by_job_id, review_unit_result_id);
CREATE UNIQUE INDEX idx_terminal_receipts_job_phase ON job_terminal_receipts(job_id, phase);
CREATE INDEX idx_checkpoints_job_operation ON job_checkpoints(job_id, operation);

CREATE TABLE generation_manifests (
    generation_id INTEGER PRIMARY KEY REFERENCES review_generations(generation_id) ON DELETE CASCADE,
    format_version INTEGER NOT NULL CHECK (format_version = 1),
    owner_job_id INTEGER REFERENCES jobs(id) ON DELETE SET NULL,
    expected_entry_count INTEGER NOT NULL CHECK (expected_entry_count BETWEEN 0 AND 1000000),
    expected_digest BLOB NOT NULL CHECK (typeof(expected_digest) = 'blob' AND length(expected_digest) = 32),
    received_entry_count INTEGER NOT NULL DEFAULT 0 CHECK (received_entry_count BETWEEN 0 AND expected_entry_count),
    received_canonical_bytes INTEGER NOT NULL DEFAULT 0 CHECK (received_canonical_bytes BETWEEN 0 AND 268435456),
    created_at INTEGER NOT NULL,
    sealed_at INTEGER,
    FOREIGN KEY (generation_id, owner_job_id) REFERENCES jobs(generation_id, id)
);

CREATE TABLE generation_inventory_units (
    generation_id INTEGER NOT NULL,
    inventory_entry_id INTEGER NOT NULL,
    review_unit_id INTEGER NOT NULL,
    PRIMARY KEY (inventory_entry_id, review_unit_id),
    FOREIGN KEY (generation_id, inventory_entry_id)
        REFERENCES generation_inventory(generation_id, inventory_entry_id) ON DELETE CASCADE,
    FOREIGN KEY (generation_id, review_unit_id)
        REFERENCES review_units(generation_id, review_unit_id) ON DELETE CASCADE
);

CREATE TABLE job_terminal_payloads (
    job_id INTEGER PRIMARY KEY REFERENCES jobs(id) ON DELETE CASCADE,
    phase TEXT NOT NULL CHECK (phase IN ('survey','drilldown','verify')),
    payload TEXT NOT NULL,
    FOREIGN KEY (job_id, phase) REFERENCES job_terminal_receipts(job_id, phase) ON DELETE CASCADE
);

CREATE TABLE lead_drilldown_intents (
    lead_id INTEGER PRIMARY KEY REFERENCES leads(lead_id) ON DELETE CASCADE,
    repo_id INTEGER NOT NULL REFERENCES registered_repos(id) ON DELETE CASCADE,
    generation_id INTEGER NOT NULL REFERENCES review_generations(generation_id) ON DELETE CASCADE,
    originating_job_id INTEGER NOT NULL,
    originating_campaign_id INTEGER NOT NULL,
    admission_campaign_id INTEGER NOT NULL,
    source_commit_sha TEXT NOT NULL,
    profile_version INTEGER NOT NULL CHECK (profile_version > 0),
    profile_digest BLOB NOT NULL CHECK (length(profile_digest) = 32),
    intent_revision INTEGER NOT NULL CHECK (intent_revision > 0),
    intent_kind TEXT NOT NULL CHECK (intent_kind IN ('initial_handoff','logical_continuation')),
    continuation_class TEXT CHECK (continuation_class IN ('source_analysis_remaining','awaiting_proof_infrastructure','external_dependency','requires_successor')),
    logical_sequence INTEGER NOT NULL CHECK (logical_sequence >= 0),
    state TEXT NOT NULL CHECK (state IN ('pending','blocked','admitted','complete')),
    not_before INTEGER,
    block_reason TEXT CHECK (block_reason IN ('awaiting_proof_infrastructure','external_dependency','requires_successor','campaign_budget','protected_capacity','campaign_cancelled','campaign_deadline','execution_exhausted','unsupported_recipe','compatibility_policy')),
    admitted_job_id INTEGER REFERENCES jobs(id) ON DELETE SET NULL,
    accepted_band TEXT NOT NULL CHECK (accepted_band IN ('urgent','high','normal','background')),
    accepted_score INTEGER NOT NULL CHECK (accepted_score BETWEEN 0 AND 550),
    priority_policy_version INTEGER NOT NULL CHECK (priority_policy_version = 1),
    created_at INTEGER NOT NULL,
    updated_at INTEGER NOT NULL,
    FOREIGN KEY (repo_id, generation_id) REFERENCES review_generations(repo_id, generation_id) ON DELETE CASCADE,
    FOREIGN KEY (generation_id, lead_id) REFERENCES leads(generation_id, lead_id) ON DELETE CASCADE,
    FOREIGN KEY (repo_id, originating_job_id) REFERENCES jobs(repo_id, id),
    FOREIGN KEY (repo_id, originating_campaign_id) REFERENCES review_campaigns(repo_id, campaign_id),
    FOREIGN KEY (repo_id, admission_campaign_id) REFERENCES review_campaigns(repo_id, campaign_id),
    FOREIGN KEY (repo_id, admitted_job_id) REFERENCES jobs(repo_id, id),
    CHECK ((intent_kind = 'initial_handoff' AND logical_sequence = 0 AND continuation_class IS NULL)
        OR (intent_kind = 'logical_continuation' AND logical_sequence > 0 AND continuation_class IS NOT NULL))
);

CREATE TABLE finding_verification_intents (
    finding_id INTEGER PRIMARY KEY,
    repo_id INTEGER NOT NULL REFERENCES registered_repos(id) ON DELETE CASCADE,
    generation_id INTEGER REFERENCES review_generations(generation_id) ON DELETE SET NULL,
    originating_job_id INTEGER NOT NULL,
    originating_campaign_id INTEGER NOT NULL,
    admission_campaign_id INTEGER NOT NULL,
    source_commit_sha TEXT NOT NULL,
    profile_version INTEGER NOT NULL CHECK (profile_version > 0),
    profile_digest BLOB NOT NULL CHECK (length(profile_digest) = 32),
    intent_revision INTEGER NOT NULL CHECK (intent_revision > 0),
    intent_kind TEXT NOT NULL CHECK (intent_kind IN ('initial_handoff','logical_continuation')),
    continuation_class TEXT CHECK (continuation_class IN ('source_analysis_remaining','awaiting_proof_infrastructure','external_dependency','requires_successor')),
    logical_sequence INTEGER NOT NULL CHECK (logical_sequence >= 0),
    state TEXT NOT NULL CHECK (state IN ('pending','blocked','admitted','complete')),
    not_before INTEGER,
    block_reason TEXT CHECK (block_reason IN ('awaiting_proof_infrastructure','external_dependency','requires_successor','campaign_budget','protected_capacity','campaign_cancelled','campaign_deadline','execution_exhausted','unsupported_recipe','compatibility_policy')),
    admitted_job_id INTEGER REFERENCES jobs(id) ON DELETE SET NULL,
    accepted_band TEXT NOT NULL CHECK (accepted_band IN ('urgent','high','normal','background')),
    accepted_score INTEGER NOT NULL CHECK (accepted_score BETWEEN 0 AND 550),
    priority_policy_version INTEGER NOT NULL CHECK (priority_policy_version = 1),
    created_at INTEGER NOT NULL,
    updated_at INTEGER NOT NULL,
    FOREIGN KEY (repo_id, finding_id) REFERENCES findings(repo_id, id) ON DELETE CASCADE,
    FOREIGN KEY (repo_id, generation_id) REFERENCES review_generations(repo_id, generation_id),
    FOREIGN KEY (repo_id, originating_job_id) REFERENCES jobs(repo_id, id),
    FOREIGN KEY (repo_id, originating_campaign_id) REFERENCES review_campaigns(repo_id, campaign_id),
    FOREIGN KEY (repo_id, admission_campaign_id) REFERENCES review_campaigns(repo_id, campaign_id),
    FOREIGN KEY (repo_id, admitted_job_id) REFERENCES jobs(repo_id, id),
    CHECK ((intent_kind = 'initial_handoff' AND logical_sequence = 0 AND continuation_class IS NULL)
        OR (intent_kind = 'logical_continuation' AND logical_sequence > 0 AND continuation_class IS NOT NULL))
);

CREATE TABLE survey_continuation_batches (
    batch_id INTEGER PRIMARY KEY,
    repo_id INTEGER NOT NULL REFERENCES registered_repos(id) ON DELETE CASCADE,
    generation_id INTEGER NOT NULL REFERENCES review_generations(generation_id) ON DELETE CASCADE,
    campaign_id INTEGER NOT NULL,
    producer_job_id INTEGER NOT NULL,
    batch_ordinal INTEGER NOT NULL CHECK (batch_ordinal >= 0),
    logical_sequence INTEGER NOT NULL CHECK (logical_sequence > 0),
    continuation_class TEXT NOT NULL CHECK (continuation_class IN ('source_analysis_remaining','awaiting_proof_infrastructure','external_dependency','requires_successor')),
    state TEXT NOT NULL CHECK (state IN ('pending','blocked','admitted','complete')),
    not_before INTEGER,
    block_reason TEXT CHECK (block_reason IN ('awaiting_proof_infrastructure','external_dependency','requires_successor','campaign_budget','protected_capacity','campaign_cancelled','campaign_deadline','execution_exhausted','unsupported_recipe','compatibility_policy')),
    admitted_job_id INTEGER UNIQUE REFERENCES jobs(id) ON DELETE SET NULL,
    expected_unit_count INTEGER NOT NULL CHECK (expected_unit_count BETWEEN 1 AND 32),
    accepted_band TEXT NOT NULL CHECK (accepted_band IN ('urgent','high','normal','background')),
    accepted_score INTEGER NOT NULL CHECK (accepted_score BETWEEN 0 AND 550),
    priority_policy_version INTEGER NOT NULL CHECK (priority_policy_version = 1),
    created_at INTEGER NOT NULL,
    UNIQUE (producer_job_id, batch_ordinal),
    UNIQUE (generation_id, batch_id),
    FOREIGN KEY (repo_id, generation_id) REFERENCES review_generations(repo_id, generation_id) ON DELETE CASCADE,
    FOREIGN KEY (repo_id, campaign_id) REFERENCES review_campaigns(repo_id, campaign_id),
    FOREIGN KEY (repo_id, producer_job_id) REFERENCES jobs(repo_id, id),
    FOREIGN KEY (generation_id, producer_job_id) REFERENCES jobs(generation_id, id),
    FOREIGN KEY (repo_id, admitted_job_id) REFERENCES jobs(repo_id, id)
);

CREATE TABLE review_unit_holds (
    review_unit_id INTEGER PRIMARY KEY REFERENCES review_units(review_unit_id) ON DELETE CASCADE,
    generation_id INTEGER NOT NULL REFERENCES review_generations(generation_id) ON DELETE CASCADE,
    producing_job_id INTEGER NOT NULL REFERENCES jobs(id),
    producing_result_id INTEGER NOT NULL REFERENCES review_unit_results(review_unit_result_id) ON DELETE CASCADE,
    source_assignment_epoch INTEGER NOT NULL CHECK (source_assignment_epoch >= 0),
    continuation_class TEXT NOT NULL CHECK (continuation_class IN ('source_analysis_remaining','awaiting_proof_infrastructure','external_dependency','requires_successor')),
    block_reason TEXT CHECK (block_reason IN ('awaiting_proof_infrastructure','external_dependency','requires_successor','campaign_budget','protected_capacity','campaign_cancelled','campaign_deadline','execution_exhausted','unsupported_recipe','compatibility_policy')),
    pending_batch_id INTEGER,
    batch_position INTEGER CHECK (batch_position IS NULL OR batch_position >= 0),
    created_at INTEGER NOT NULL,
    updated_at INTEGER NOT NULL,
    UNIQUE (pending_batch_id, batch_position),
    FOREIGN KEY (generation_id, review_unit_id) REFERENCES review_units(generation_id, review_unit_id) ON DELETE CASCADE,
    FOREIGN KEY (generation_id, producing_job_id) REFERENCES jobs(generation_id, id),
    FOREIGN KEY (review_unit_id, producing_job_id, producing_result_id)
        REFERENCES review_unit_results(review_unit_id, produced_by_job_id, review_unit_result_id) ON DELETE CASCADE,
    FOREIGN KEY (generation_id, pending_batch_id)
        REFERENCES survey_continuation_batches(generation_id, batch_id),
    CHECK ((pending_batch_id IS NULL) = (batch_position IS NULL))
);

CREATE TABLE campaign_admission_spending (
    campaign_id INTEGER PRIMARY KEY REFERENCES review_campaigns(campaign_id) ON DELETE CASCADE,
    policy_version INTEGER NOT NULL CHECK (policy_version = 2),
    general_spent INTEGER NOT NULL DEFAULT 0 CHECK (general_spent >= 0),
    urgent_spent INTEGER NOT NULL DEFAULT 0 CHECK (urgent_spent >= 0),
    verification_spent INTEGER NOT NULL DEFAULT 0 CHECK (verification_spent >= 0)
);
CREATE TRIGGER campaign_admission_spending_monotonic BEFORE UPDATE ON campaign_admission_spending
WHEN NEW.general_spent < OLD.general_spent OR NEW.urgent_spent < OLD.urgent_spent
    OR NEW.verification_spent < OLD.verification_spent
BEGIN
    SELECT RAISE(ABORT, 'campaign admission spending cannot decrease');
END;

CREATE TABLE job_admission_charges (
    job_id INTEGER PRIMARY KEY REFERENCES jobs(id) ON DELETE CASCADE,
    campaign_id INTEGER NOT NULL REFERENCES campaign_admission_spending(campaign_id) ON DELETE CASCADE,
    pool TEXT NOT NULL CHECK (pool IN ('general','urgent','verification')),
    FOREIGN KEY (campaign_id, job_id) REFERENCES jobs(campaign_id, id) ON DELETE CASCADE
);
"#;
