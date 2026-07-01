-- Full schema repair: (re-)creates every table, column and index the application expects,
-- regardless of which versioned migrations (see ../migrations) have actually been applied.
-- It is run on demand (developer mode only, see db.RunFullRepair) to repair a database that
-- has drifted from the canonical schema, e.g. because a migration silently failed to apply.
--
-- Every statement here must be safe to run against a database that already has some or all
-- of this schema in place:
--   - CREATE TABLE / CREATE INDEX use IF NOT EXISTS, which SQLite supports natively.
--   - ALTER TABLE ADD COLUMN has no IF NOT EXISTS equivalent in SQLite, so the runner
--     tolerates the resulting "duplicate column name" error when the column already exists.

CREATE TABLE IF NOT EXISTS `holder_binding_keys` (
  `id` TEXT,
  `issued_credential_instance_id` TEXT,
  `algorithm` text NOT NULL,
  `public_key_thumbprint` text,
  `did_url` text,
  `private_key` text NOT NULL,
  `created_at` datetime,
  PRIMARY KEY (`id`),
  CONSTRAINT `fk_issued_credential_instances_holder_binding_key` FOREIGN KEY (`issued_credential_instance_id`) REFERENCES `issued_credential_instances`(`id`) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS `ecdsa_key_metadata` (
  `holder_binding_key_id` TEXT,
  `curve_name` text,
  CONSTRAINT `fk_holder_binding_keys_ecdsa` FOREIGN KEY (`holder_binding_key_id`) REFERENCES `holder_binding_keys`(`id`) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS `rsa_key_metadata` (
  `holder_binding_key_id` TEXT,
  `modulus_bits` integer,
  `public_exponent` integer,
  CONSTRAINT `fk_holder_binding_keys_rsa` FOREIGN KEY (`holder_binding_key_id`) REFERENCES `holder_binding_keys`(`id`) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS `credential_batches` (
  `id` TEXT,
  `issuer_url` text,
  `verifiable_credential_type` text,
  `format` text,
  `hash` text,
  `processed_sd_jwt_payload` JSON NOT NULL,
  `issued_at` datetime,
  `expires_at` datetime,
  `not_before` datetime,
  `batch_size` integer,
  `remaining_count` integer,
  `credential_issuer` text,
  PRIMARY KEY (`id`)
);

CREATE TABLE IF NOT EXISTS `issued_credential_instances` (
  `id` TEXT,
  `credential_batch_id` TEXT,
  `raw_credential` text NOT NULL,
  `used` numeric DEFAULT false,
  PRIMARY KEY (`id`),
  CONSTRAINT `fk_credential_batches_instances` FOREIGN KEY (`credential_batch_id`) REFERENCES `credential_batches`(`id`) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS `issuer_metadata_displays` (
  `id` TEXT,
  `credential_batch_id` TEXT,
  `name` text,
  `locale` text,
  `logo_uri` text,
  `logo_alt_text` text,
  PRIMARY KEY (`id`),
  CONSTRAINT `fk_credential_batches_issuer_display` FOREIGN KEY (`credential_batch_id`) REFERENCES `credential_batches`(`id`) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS `credential_metadata` (
  `id` TEXT,
  `credential_batch_id` TEXT,
  PRIMARY KEY (`id`),
  CONSTRAINT `fk_credential_batches_credential_metadata` FOREIGN KEY (`credential_batch_id`) REFERENCES `credential_batches`(`id`) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS `credential_displays` (
  `id` TEXT,
  `credential_metadata_id` TEXT,
  `name` text,
  `locale` text,
  `logo_uri` text,
  `logo_alt_text` text,
  `description` text,
  `background_color` text,
  `background_image_uri` text,
  `background_image_alt_text` text,
  `text_color` text,
  PRIMARY KEY (`id`),
  CONSTRAINT `fk_credential_metadata_display` FOREIGN KEY (`credential_metadata_id`) REFERENCES `credential_metadata`(`id`) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS `credential_claims` (
  `id` TEXT,
  `credential_metadata_id` TEXT,
  `path` JSON NOT NULL,
  `mandatory` numeric DEFAULT false,
  PRIMARY KEY (`id`),
  CONSTRAINT `fk_credential_metadata_claims` FOREIGN KEY (`credential_metadata_id`) REFERENCES `credential_metadata`(`id`) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS `claim_displays` (
  `id` TEXT,
  `credential_claim_id` TEXT,
  `name` text,
  `locale` text,
  PRIMARY KEY (`id`),
  CONSTRAINT `fk_credential_claims_display` FOREIGN KEY (`credential_claim_id`) REFERENCES `credential_claims`(`id`) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS `eudi_log_entries` (
  `id` TEXT,
  `type` text,
  `protocol` text,
  `created_at` datetime,
  `requestor_id` text,
  `requestor_name` JSON,
  PRIMARY KEY (`id`)
);

CREATE TABLE IF NOT EXISTS `eudi_log_credentials` (
  `id` TEXT,
  `eudi_log_entry_id` TEXT,
  `credential_id` text,
  `formats` JSON,
  `name` JSON,
  `issuer_name` JSON,
  `issuer_id` text,
  `issuer_verified` numeric,
  `attributes` JSON,
  `issuance_date` datetime,
  `expiry_date` datetime,
  `revoked` numeric,
  `revocation_supported` numeric,
  `issue_url` JSON,
  PRIMARY KEY (`id`),
  CONSTRAINT `fk_eudi_log_entries_credentials` FOREIGN KEY (`eudi_log_entry_id`) REFERENCES `eudi_log_entries`(`id`) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS `kb_jwt_replay_entries` (
  `digest` text,
  `expires_at` datetime,
  `created_at` datetime,
  PRIMARY KEY (`digest`)
);

-- Columns added on top of a table's initial creation. The runner tolerates the
-- "duplicate column name" error these raise when already present.
ALTER TABLE `credential_batches` ADD COLUMN `credential_type` text;
ALTER TABLE `credential_batches` ADD COLUMN `processed_claims` JSON;
ALTER TABLE `credential_batches` ADD COLUMN `issuance_date` datetime;

CREATE UNIQUE INDEX IF NOT EXISTS `idx_credential_batches_hash` ON `credential_batches`(`hash`);
CREATE UNIQUE INDEX IF NOT EXISTS `idx_ecdsa_key_metadata_holder_binding_key_id` ON `ecdsa_key_metadata`(`holder_binding_key_id`);
CREATE INDEX IF NOT EXISTS `idx_eudi_log_credentials_eudi_log_entry_id` ON `eudi_log_credentials`(`eudi_log_entry_id`);
CREATE INDEX IF NOT EXISTS `idx_eudi_log_entries_created_at` ON `eudi_log_entries`(`created_at`);
CREATE INDEX IF NOT EXISTS `idx_holder_binding_keys_algorithm` ON `holder_binding_keys`(`algorithm`);
CREATE UNIQUE INDEX IF NOT EXISTS `idx_holder_binding_keys_did_url` ON `holder_binding_keys`(`did_url`);
CREATE UNIQUE INDEX IF NOT EXISTS `idx_holder_binding_keys_public_key_thumbprint` ON `holder_binding_keys`(`public_key_thumbprint`);
CREATE UNIQUE INDEX IF NOT EXISTS `idx_rsa_key_metadata_holder_binding_key_id` ON `rsa_key_metadata`(`holder_binding_key_id`);
CREATE INDEX IF NOT EXISTS `idx_kb_jwt_replay_entries_expires_at` ON `kb_jwt_replay_entries`(`expires_at`);

-- Backfill canonical columns from legacy values and vice versa, keeping both in sync,
-- in case the columns above were just added by this script.
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
