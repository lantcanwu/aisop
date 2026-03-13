-- SecOps AI Database Schema
-- Phase 1: Data Collection Module

-- Security Events Table
CREATE TABLE IF NOT EXISTS security_events (
    id TEXT PRIMARY KEY,
    source TEXT NOT NULL,
    source_type TEXT NOT NULL,
    event_type TEXT,
    severity TEXT NOT NULL DEFAULT 'info',
    status TEXT NOT NULL DEFAULT 'created',
    classification TEXT DEFAULT 'pending',
    title TEXT NOT NULL,
    description TEXT,
    raw_data TEXT,
    asset_ids TEXT,
    iocs TEXT,
    ttp TEXT,
    correlation_ids TEXT,
    ai_analysis TEXT,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    classified_at TIMESTAMP,
    resolved_at TIMESTAMP,
    closed_at TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_events_source ON security_events(source);
CREATE INDEX IF NOT EXISTS idx_events_severity ON security_events(severity);
CREATE INDEX IF NOT EXISTS idx_events_status ON security_events(status);
CREATE INDEX IF NOT EXISTS idx_events_created_at ON security_events(created_at);
CREATE INDEX IF NOT EXISTS idx_events_classification ON security_events(classification);

-- Collector Configs Table
CREATE TABLE IF NOT EXISTS collector_configs (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    type TEXT NOT NULL,
    enabled INTEGER NOT NULL DEFAULT 1,
    config TEXT NOT NULL,
    schedule TEXT,
    last_run TIMESTAMP,
    last_status TEXT DEFAULT 'idle',
    last_error TEXT,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_collectors_type ON collector_configs(type);
CREATE INDEX IF NOT EXISTS idx_collectors_enabled ON collector_configs(enabled);

-- Collector Jobs Table
CREATE TABLE IF NOT EXISTS collector_jobs (
    id TEXT PRIMARY KEY,
    collector_id TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'idle',
    started_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    completed_at TIMESTAMP,
    error_message TEXT,
    events_count INTEGER DEFAULT 0,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (collector_id) REFERENCES collector_configs(id)
);

CREATE INDEX IF NOT EXISTS idx_jobs_collector_id ON collector_jobs(collector_id);
CREATE INDEX IF NOT EXISTS idx_jobs_status ON collector_jobs(status);

-- Webhook Endpoints Table
CREATE TABLE IF NOT EXISTS webhook_endpoints (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    token TEXT NOT NULL UNIQUE,
    signature_type TEXT DEFAULT 'none',
    signature_key TEXT,
    enabled INTEGER NOT NULL DEFAULT 1,
    event_types TEXT,
    parser_config TEXT,
    last_event_at TIMESTAMP,
    events_count INTEGER DEFAULT 0,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_webhooks_token ON webhook_endpoints(token);
CREATE INDEX IF NOT EXISTS idx_webhooks_enabled ON webhook_endpoints(enabled);

-- Webhook Events Table
CREATE TABLE IF NOT EXISTS webhook_events (
    id TEXT PRIMARY KEY,
    endpoint_id TEXT NOT NULL,
    source_ip TEXT,
    headers TEXT,
    payload TEXT,
    signature_valid INTEGER DEFAULT 1,
    processed INTEGER DEFAULT 0,
    error_message TEXT,
    received_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    processed_at TIMESTAMP,
    FOREIGN KEY (endpoint_id) REFERENCES webhook_endpoints(id)
);

CREATE INDEX IF NOT EXISTS idx_webhook_events_endpoint_id ON webhook_events(endpoint_id);
CREATE INDEX IF NOT EXISTS idx_webhook_events_received_at ON webhook_events(received_at);

-- IoC Table
CREATE TABLE IF NOT EXISTS iocs (
    id TEXT PRIMARY KEY,
    type TEXT NOT NULL,
    value TEXT NOT NULL,
    source TEXT,
    tags TEXT,
    confidence REAL DEFAULT 0.0,
    first_seen TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    last_seen TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    UNIQUE(type, value)
);

CREATE INDEX IF NOT EXISTS idx_iocs_type ON iocs(type);
CREATE INDEX IF NOT EXISTS idx_iocs_value ON iocs(value);
CREATE INDEX IF NOT EXISTS idx_iocs_last_seen ON iocs(last_seen);

-- Assets Table
CREATE TABLE IF NOT EXISTS assets (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    type TEXT NOT NULL,
    ip TEXT,
    mac TEXT,
    owner TEXT,
    business TEXT,
    criticality TEXT DEFAULT 'medium',
    tags TEXT,
    attributes TEXT,
    first_seen TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    last_seen TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_assets_type ON assets(type);
CREATE INDEX IF NOT EXISTS idx_assets_ip ON assets(ip);
CREATE INDEX IF NOT EXISTS idx_assets_name ON assets(name);
CREATE INDEX IF NOT EXISTS idx_assets_business ON assets(business);

-- Threat Intelligence Table
CREATE TABLE IF NOT EXISTS threat_intel (
    id TEXT PRIMARY KEY,
    ioc_type TEXT NOT NULL,
    ioc_value TEXT NOT NULL,
    threat_type TEXT,
    source TEXT NOT NULL,
    confidence REAL DEFAULT 0.0,
    tags TEXT,
    description TEXT,
    first_seen TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    last_seen TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    UNIQUE(ioc_type, ioc_value, source)
);

CREATE INDEX IF NOT EXISTS idx_threat_intel_type ON threat_intel(ioc_type);
CREATE INDEX IF NOT EXISTS idx_threat_intel_value ON threat_intel(ioc_value);
CREATE INDEX IF NOT EXISTS idx_threat_intel_source ON threat_intel(source);
