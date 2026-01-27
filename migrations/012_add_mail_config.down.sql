-- Migration 012 Rollback: Remove mail_config columns and view

DROP VIEW IF EXISTS tenants_safe;

ALTER TABLE tenants
DROP COLUMN IF EXISTS mail_config,
DROP COLUMN IF EXISTS mail_config_key_version;
