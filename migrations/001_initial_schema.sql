-- Create extension for UUID generation
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";

-- Create gateways table
CREATE TABLE gateways (
    id UUID PRIMARY KEY,
    name VARCHAR(255) NOT NULL,
    subdomain VARCHAR(255) NOT NULL UNIQUE,
    api_key VARCHAR(255) NOT NULL UNIQUE,
    status VARCHAR(50) NOT NULL,
    tier VARCHAR(50) NOT NULL,
    created_at TIMESTAMP WITH TIME ZONE NOT NULL,
    updated_at TIMESTAMP WITH TIME ZONE NOT NULL,
    enabled_plugins JSONB NOT NULL DEFAULT '[]',
    required_plugins JSONB NOT NULL DEFAULT '{}'
);

-- Create forwarding_rules table
CREATE TABLE forwarding_rules (
    id UUID PRIMARY KEY,
    gateway_id UUID NOT NULL REFERENCES gateways(id) ON DELETE CASCADE,
    path VARCHAR(255) NOT NULL,
    target VARCHAR(255) NOT NULL,
    methods JSONB NOT NULL DEFAULT '[]',
    headers JSONB NOT NULL DEFAULT '[]',
    strip_path BOOLEAN NOT NULL DEFAULT false,
    preserve_host BOOLEAN NOT NULL DEFAULT false,
    retry_attempts INTEGER NOT NULL DEFAULT 0,
    plugin_chain JSONB NOT NULL DEFAULT '[]',
    active BOOLEAN NOT NULL DEFAULT true,
    public BOOLEAN NOT NULL DEFAULT false,
    created_at TIMESTAMP WITH TIME ZONE NOT NULL,
    updated_at TIMESTAMP WITH TIME ZONE NOT NULL
);

-- Create api_keys table
CREATE TABLE api_keys (
    id UUID PRIMARY KEY,
    name VARCHAR(255) NOT NULL,
    key VARCHAR(255) NOT NULL UNIQUE,
    gateway_id UUID NOT NULL REFERENCES gateways(id) ON DELETE CASCADE,
    created_at TIMESTAMP WITH TIME ZONE NOT NULL,
    expires_at TIMESTAMP WITH TIME ZONE,
    last_used_at TIMESTAMP WITH TIME ZONE,
    status VARCHAR(50) NOT NULL DEFAULT 'active'
);

-- Create indexes
CREATE INDEX idx_gateways_subdomain ON gateways(subdomain);
CREATE INDEX idx_gateways_api_key ON gateways(api_key);
CREATE INDEX idx_forwarding_rules_gateway_id ON forwarding_rules(gateway_id);
CREATE INDEX idx_api_keys_gateway_id ON api_keys(gateway_id);
CREATE INDEX idx_api_keys_key ON api_keys(key); 