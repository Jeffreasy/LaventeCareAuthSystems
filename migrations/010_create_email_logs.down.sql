-- Migration 010 Rollback: Drop email_logs table

DROP POLICY IF EXISTS email_logs_tenant_isolation ON email_logs;
DROP TABLE IF EXISTS email_logs;
