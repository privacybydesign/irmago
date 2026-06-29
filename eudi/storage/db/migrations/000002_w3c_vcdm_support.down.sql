DROP TABLE IF EXISTS `kb_jwt_replay_entries`;

ALTER TABLE `credential_batches` DROP COLUMN `issuance_date`;
ALTER TABLE `credential_batches` DROP COLUMN `processed_claims`;
ALTER TABLE `credential_batches` DROP COLUMN `credential_type`;
