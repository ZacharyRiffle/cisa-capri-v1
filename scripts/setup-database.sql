-- Database setup script for threat intelligence storage
-- Run this script to create the necessary tables in your PostgreSQL database

-- Create threat_intelligence table
CREATE TABLE IF NOT EXISTS threat_intelligence (
    id VARCHAR(255) PRIMARY KEY,
    title TEXT NOT NULL,
    description TEXT,
    severity VARCHAR(20) CHECK (severity IN ('Critical', 'High', 'Medium', 'Low')),
    published TIMESTAMP WITH TIME ZONE,
    updated TIMESTAMP WITH TIME ZONE,
    source VARCHAR(255),
    source_url TEXT,
    sectors TEXT[], -- Array of sectors
    indicators JSONB, -- JSON array of indicators
    mitre_techniques TEXT[], -- Array of MITRE techniques
    tags TEXT[], -- Array of tags
    tlp VARCHAR(10) CHECK (tlp IN ('WHITE', 'GREEN', 'AMBER', 'RED')),
    raw_data JSONB, -- Original data from source
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- Create indexes for better query performance
CREATE INDEX IF NOT EXISTS idx_threat_intel_published ON threat_intelligence(published DESC);
CREATE INDEX IF NOT EXISTS idx_threat_intel_severity ON threat_intelligence(severity);
CREATE INDEX IF NOT EXISTS idx_threat_intel_source ON threat_intelligence(source);
CREATE INDEX IF NOT EXISTS idx_threat_intel_sectors ON threat_intelligence USING GIN(sectors);
CREATE INDEX IF NOT EXISTS idx_threat_intel_tags ON threat_intelligence USING GIN(tags);
CREATE INDEX IF NOT EXISTS idx_threat_intel_search ON threat_intelligence USING GIN(to_tsvector('english', title || ' ' || COALESCE(description, '')));

-- Create feed_status table
CREATE TABLE IF NOT EXISTS feed_status (
    id VARCHAR(255) PRIMARY KEY,
    name VARCHAR(255) NOT NULL,
    url TEXT NOT NULL,
    type VARCHAR(50) NOT NULL,
    category VARCHAR(100),
    enabled BOOLEAN DEFAULT true,
    last_fetch TIMESTAMP WITH TIME ZONE,
    status VARCHAR(20) CHECK (status IN ('active', 'error', 'disabled')) DEFAULT 'active',
    update_frequency INTEGER DEFAULT 60, -- minutes
    error_count INTEGER DEFAULT 0,
    last_error TEXT,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- Create indexes for feed_status
CREATE INDEX IF NOT EXISTS idx_feed_status_enabled ON feed_status(enabled);
CREATE INDEX IF NOT EXISTS idx_feed_status_last_fetch ON feed_status(last_fetch);

-- Create function to update updated_at timestamp
CREATE OR REPLACE FUNCTION update_updated_at_column()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = NOW();
    RETURN NEW;
END;
$$ language 'plpgsql';

-- Create triggers to automatically update updated_at
CREATE TRIGGER update_threat_intelligence_updated_at 
    BEFORE UPDATE ON threat_intelligence 
    FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

CREATE TRIGGER update_feed_status_updated_at 
    BEFORE UPDATE ON feed_status 
    FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

-- Insert initial feed configurations
INSERT INTO feed_status (id, name, url, type, category, enabled, update_frequency) VALUES
('nist-nvd', 'NIST NVD', 'https://services.nvd.nist.gov/rest/json/cves/2.0', 'nist', 'Vulnerabilities', true, 60),
('cisa-alerts', 'CISA Alerts', 'https://www.cisa.gov/sites/default/files/feeds/alerts.xml', 'cisa', 'Government', true, 30),
('cisa-kev', 'CISA KEV', 'https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json', 'cisa', 'Government', true, 120),
('microsoft-security', 'Microsoft Security', 'https://msrc.microsoft.com/blog/feed/', 'rss', 'Vendor Intelligence', true, 180),
('sans-isc', 'SANS ISC', 'https://isc.sans.edu/rssfeed.xml', 'rss', 'Community Intelligence', true, 60)
ON CONFLICT (id) DO NOTHING;

-- Create view for recent critical threats
CREATE OR REPLACE VIEW recent_critical_threats AS
SELECT *
FROM threat_intelligence
WHERE severity IN ('Critical', 'High')
  AND published >= NOW() - INTERVAL '7 days'
ORDER BY published DESC;

-- Create view for feed health monitoring
CREATE OR REPLACE VIEW feed_health AS
SELECT 
    id,
    name,
    status,
    enabled,
    last_fetch,
    error_count,
    CASE 
        WHEN last_fetch IS NULL THEN 'Never fetched'
        WHEN last_fetch < NOW() - INTERVAL '1 hour' * update_frequency / 60 * 2 THEN 'Overdue'
        ELSE 'On schedule'
    END as fetch_status,
    last_error
FROM feed_status
ORDER BY enabled DESC, error_count ASC, last_fetch DESC;
