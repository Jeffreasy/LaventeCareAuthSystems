CREATE TABLE iot_devices (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    device_id VARCHAR(64) NOT NULL UNIQUE, -- The hardware MAC or Serial
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    secret_hash TEXT NOT NULL, -- Bcrypt hash of the device token
    name VARCHAR(255) NOT NULL,
    is_active BOOLEAN NOT NULL DEFAULT true,
    last_seen_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- RLS: Tenant Isolation
ALTER TABLE iot_devices ENABLE ROW LEVEL SECURITY;

CREATE POLICY tenant_isolation_policy ON iot_devices
    FOR ALL
    USING (tenant_id = current_setting('app.current_tenant')::UUID);

-- Indexes for Gatekeeper lookups
CREATE INDEX idx_iot_devices_device_id ON iot_devices(device_id);
CREATE INDEX idx_iot_devices_tenant_id ON iot_devices(tenant_id);
