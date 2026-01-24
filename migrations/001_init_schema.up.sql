/*
 * ----------------------------------------------
 * HEADLESS AUTH PROVIDER (Go Optimized)
 * ----------------------------------------------
 */

CREATE EXTENSION IF NOT EXISTS "pgcrypto";
CREATE EXTENSION IF NOT EXISTS "citext";

-- Timestamp Trigger
CREATE OR REPLACE FUNCTION trigger_set_timestamp()
RETURNS TRIGGER AS $$
BEGIN
  NEW.updated_at = NOW();
  RETURN NEW;
END;
$$ LANGUAGE plpgsql;

-- 1. TENANTS (Eerst aanmaken, zodat Users ernaar kan verwijzen)
CREATE TABLE tenants (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name VARCHAR(255) NOT NULL,
    slug CITEXT NOT NULL UNIQUE,
    
    -- API Credentials
    -- Public key moet UNIQUE zijn voor snelle lookup via API
    public_key UUID DEFAULT gen_random_uuid() NOT NULL UNIQUE,
    -- LET OP: Sla dit in productie bij voorkeur gehasht op (net als wachtwoorden)
    -- Stuur dit veld NOOIT mee in JSON responses.
    secret_key_hash VARCHAR(255) NOT NULL,
    
    -- Security Whitelists (Go: []string)
    allowed_origins TEXT[] DEFAULT '{}',
    redirect_urls TEXT[] DEFAULT '{}',
    
    -- Branding & Config (Go: struct met Scan interface)
    branding JSONB DEFAULT '{ "logo_url": null, "primary_color": "#000000" }'::JSONB,
    settings JSONB DEFAULT '{ "allow_registration": true }'::JSONB,

    is_active BOOLEAN DEFAULT TRUE NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- 2. USERS
CREATE TABLE users (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    email CITEXT NOT NULL UNIQUE,
    password_hash VARCHAR(255),
    full_name VARCHAR(100),
    is_email_verified BOOLEAN DEFAULT FALSE NOT NULL,
    
    -- FK toegevoegd: ON DELETE SET NULL voorkomt dat users stukgaan als een tenant verwijderd wordt
    default_tenant_id UUID REFERENCES tenants(id) ON DELETE SET NULL,
    
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- 3. MEMBERSHIPS
CREATE TABLE memberships (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    role VARCHAR(50) NOT NULL DEFAULT 'user', -- Tip: Gebruik constants in Go
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    
    -- Constraint: Een user mag maar 1x lid zijn van dezelfde tenant
    CONSTRAINT unique_user_per_tenant UNIQUE (user_id, tenant_id)
);

-- 4. AUTH SESSIONS (Refresh Tokens)
CREATE TABLE refresh_tokens (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    token_hash VARCHAR(255) NOT NULL UNIQUE,
    
    -- Token Rotation
    parent_token_id UUID REFERENCES refresh_tokens(id) ON DELETE SET NULL,
    family_id UUID DEFAULT gen_random_uuid(),
    
    tenant_id UUID REFERENCES tenants(id) ON DELETE CASCADE,
    
    ip_address INET,            -- Go: net.IP
    user_agent VARCHAR(512),    -- Nieuw: Handig voor "Actieve Sessies" overzicht
    
    expires_at TIMESTAMPTZ NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- 5. VERIFICATION TOKENS
CREATE TABLE verification_tokens (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    token_hash VARCHAR(255) NOT NULL UNIQUE, -- Index voor snelheid
    type VARCHAR(20) NOT NULL, -- 'magic_link', 'reset_password'
    
    -- NIEUW: Tenant Context. Essentieel voor juiste redirect URLs.
    tenant_id UUID REFERENCES tenants(id) ON DELETE CASCADE,

    expires_at TIMESTAMPTZ NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- INDEXES (Performance)
CREATE INDEX idx_tenants_public_key ON tenants(public_key);
CREATE INDEX idx_users_email ON users(email);

-- Foreign Key Indexes (Postgres maakt deze niet automatisch aan, belangrijk voor DELETE performance)
CREATE INDEX idx_memberships_user_id ON memberships(user_id);
CREATE INDEX idx_memberships_tenant_id ON memberships(tenant_id);
CREATE INDEX idx_refresh_tokens_user_id ON refresh_tokens(user_id);

-- TRIGGERS
CREATE TRIGGER set_timestamp_users BEFORE UPDATE ON users FOR EACH ROW EXECUTE PROCEDURE trigger_set_timestamp();
CREATE TRIGGER set_timestamp_tenants BEFORE UPDATE ON tenants FOR EACH ROW EXECUTE PROCEDURE trigger_set_timestamp();

-- RLS (Veiligheidshalve aan, maar ZONDER open policy)
ALTER TABLE tenants ENABLE ROW LEVEL SECURITY;
-- Verwijderd: CREATE POLICY ... USING (true); -> Dit lekte de secret_key.
