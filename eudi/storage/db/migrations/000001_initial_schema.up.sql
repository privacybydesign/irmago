CREATE TABLE `holder_binding_keys` (
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

CREATE TABLE `ecdsa_key_metadata` (
  `holder_binding_key_id` TEXT,
  `curve_name` text,
  CONSTRAINT `fk_holder_binding_keys_ecdsa` FOREIGN KEY (`holder_binding_key_id`) REFERENCES `holder_binding_keys`(`id`) ON DELETE CASCADE
);

CREATE TABLE `rsa_key_metadata` (
  `holder_binding_key_id` TEXT,
  `modulus_bits` integer,
  `public_exponent` integer,
  CONSTRAINT `fk_holder_binding_keys_rsa` FOREIGN KEY (`holder_binding_key_id`) REFERENCES `holder_binding_keys`(`id`) ON DELETE CASCADE
);

CREATE TABLE `credential_batches` (
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

CREATE TABLE `issued_credential_instances` (
  `id` TEXT,
  `credential_batch_id` TEXT,
  `raw_credential` text NOT NULL,
  `used` numeric DEFAULT false,
  PRIMARY KEY (`id`),
  CONSTRAINT `fk_credential_batches_instances` FOREIGN KEY (`credential_batch_id`) REFERENCES `credential_batches`(`id`) ON DELETE CASCADE
);

CREATE TABLE `issuer_metadata_displays` (
  `id` TEXT,
  `credential_batch_id` TEXT,
  `name` text,
  `locale` text,
  `logo_uri` text,
  `logo_alt_text` text,
  PRIMARY KEY (`id`),
  CONSTRAINT `fk_credential_batches_issuer_display` FOREIGN KEY (`credential_batch_id`) REFERENCES `credential_batches`(`id`) ON DELETE CASCADE
);

CREATE TABLE `credential_metadata` (
  `id` TEXT,
  `credential_batch_id` TEXT,
  PRIMARY KEY (`id`),
  CONSTRAINT `fk_credential_batches_credential_metadata` FOREIGN KEY (`credential_batch_id`) REFERENCES `credential_batches`(`id`) ON DELETE CASCADE
);

CREATE TABLE `credential_displays` (
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

CREATE TABLE `credential_claims` (
  `id` TEXT,
  `credential_metadata_id` TEXT,
  `path` JSON NOT NULL,
  `mandatory` numeric DEFAULT false,
  PRIMARY KEY (`id`),
  CONSTRAINT `fk_credential_metadata_claims` FOREIGN KEY (`credential_metadata_id`) REFERENCES `credential_metadata`(`id`) ON DELETE CASCADE
);

CREATE TABLE `claim_displays` (
  `id` TEXT,
  `credential_claim_id` TEXT,
  `name` text,
  `locale` text,
  PRIMARY KEY (`id`),
  CONSTRAINT `fk_credential_claims_display` FOREIGN KEY (`credential_claim_id`) REFERENCES `credential_claims`(`id`) ON DELETE CASCADE
);

CREATE TABLE `eudi_log_entries` (
  `id` TEXT,
  `type` text,
  `protocol` text,
  `created_at` datetime,
  `requestor_id` text,
  `requestor_name` JSON,
  PRIMARY KEY (`id`)
);

CREATE TABLE `eudi_log_credentials` (
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

CREATE UNIQUE INDEX `idx_credential_batches_hash` ON `credential_batches`(`hash`);
CREATE UNIQUE INDEX `idx_ecdsa_key_metadata_holder_binding_key_id` ON `ecdsa_key_metadata`(`holder_binding_key_id`);
CREATE INDEX `idx_eudi_log_credentials_eudi_log_entry_id` ON `eudi_log_credentials`(`eudi_log_entry_id`);
CREATE INDEX `idx_eudi_log_entries_created_at` ON `eudi_log_entries`(`created_at`);
CREATE INDEX `idx_holder_binding_keys_algorithm` ON `holder_binding_keys`(`algorithm`);
CREATE UNIQUE INDEX `idx_holder_binding_keys_did_url` ON `holder_binding_keys`(`did_url`);
CREATE UNIQUE INDEX `idx_holder_binding_keys_public_key_thumbprint` ON `holder_binding_keys`(`public_key_thumbprint`);
CREATE UNIQUE INDEX `idx_rsa_key_metadata_holder_binding_key_id` ON `rsa_key_metadata`(`holder_binding_key_id`);
