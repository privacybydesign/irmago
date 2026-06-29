-- Add canonical credential type column, aliasing the legacy verifiable_credential_type.
ALTER TABLE `credential_batches` ADD COLUMN `credential_type` text;

-- Add canonical claims column, aliasing the legacy processed_sd_jwt_payload.
ALTER TABLE `credential_batches` ADD COLUMN `processed_claims` JSON;

-- Add canonical issuance date column, aliasing the legacy issued_at.
ALTER TABLE `credential_batches` ADD COLUMN `issuance_date` datetime;

-- Backfill canonical columns from legacy values.
UPDATE `credential_batches`
SET `credential_type` = `verifiable_credential_type`
WHERE (`credential_type` IS NULL OR `credential_type` = '')
  AND `verifiable_credential_type` IS NOT NULL
  AND `verifiable_credential_type` != '';

UPDATE `credential_batches`
SET `processed_claims` = `processed_sd_jwt_payload`
WHERE (`processed_claims` IS NULL OR `processed_claims` = '')
  AND `processed_sd_jwt_payload` IS NOT NULL
  AND `processed_sd_jwt_payload` != '';

UPDATE `credential_batches`
SET `issuance_date` = `issued_at`
WHERE `issuance_date` IS NULL
  AND `issued_at` IS NOT NULL;

-- Backfill legacy columns from canonical values (keeps both in sync for rollback safety).
UPDATE `credential_batches`
SET `verifiable_credential_type` = `credential_type`
WHERE (`verifiable_credential_type` IS NULL OR `verifiable_credential_type` = '')
  AND `credential_type` IS NOT NULL
  AND `credential_type` != '';

UPDATE `credential_batches`
SET `processed_sd_jwt_payload` = `processed_claims`
WHERE (`processed_sd_jwt_payload` IS NULL OR `processed_sd_jwt_payload` = '')
  AND `processed_claims` IS NOT NULL
  AND `processed_claims` != '';

UPDATE `credential_batches`
SET `issued_at` = `issuance_date`
WHERE `issued_at` IS NULL
  AND `issuance_date` IS NOT NULL;

-- Add KB-JWT replay prevention table.
CREATE TABLE `kb_jwt_replay_entries` (
  `digest` text,
  `expires_at` datetime,
  `created_at` datetime,
  PRIMARY KEY (`digest`)
);

CREATE INDEX `idx_kb_jwt_replay_entries_expires_at` ON `kb_jwt_replay_entries`(`expires_at`);
