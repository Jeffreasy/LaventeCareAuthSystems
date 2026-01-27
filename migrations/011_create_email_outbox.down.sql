-- Migration 011 Rollback: Drop email_outbox table

DROP POLICY IF EXISTS email_outbox_tenant_isolation ON email_outbox;
DROP TABLE IF EXISTS email_outbox;
