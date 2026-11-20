-- What is known about each sending address: forward-confirmed reverse DNS,
-- the service it belongs to, its country and autonomous system. One row per
-- address, refreshed when it is older than the configured age.
CREATE TABLE sources (
	ip TEXT PRIMARY KEY,
	reverse_dns TEXT,
	reverse_dns_verified INTEGER NOT NULL DEFAULT 0,
	base_domain TEXT,
	name TEXT,
	type TEXT,
	country TEXT,
	asn INTEGER,
	as_name TEXT,
	as_domain TEXT,
	looked_up_at INTEGER NOT NULL
);

CREATE INDEX idx_sources_looked_up_at ON sources(looked_up_at);
