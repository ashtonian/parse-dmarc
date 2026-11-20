-- The schema as Parse DMARC created it before migrations existed. On a
-- database from that time every statement is a no-op; on a new one it is the
-- starting point the later migrations change.
CREATE TABLE IF NOT EXISTS reports (
	id INTEGER PRIMARY KEY AUTOINCREMENT,
	report_id TEXT UNIQUE NOT NULL,
	org_name TEXT NOT NULL,
	email TEXT,
	domain TEXT NOT NULL,
	date_begin INTEGER NOT NULL,
	date_end INTEGER NOT NULL,
	created_at INTEGER NOT NULL,
	policy_p TEXT,
	policy_sp TEXT,
	policy_pct INTEGER,
	total_messages INTEGER,
	compliant_messages INTEGER,
	raw_report TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS records (
	id INTEGER PRIMARY KEY AUTOINCREMENT,
	report_id INTEGER NOT NULL,
	source_ip TEXT NOT NULL,
	count INTEGER NOT NULL,
	disposition TEXT,
	dkim_result TEXT,
	spf_result TEXT,
	header_from TEXT,
	envelope_from TEXT,
	dkim_domains TEXT,
	spf_domains TEXT,
	FOREIGN KEY (report_id) REFERENCES reports(id)
);

CREATE INDEX IF NOT EXISTS idx_reports_date_begin ON reports(date_begin);
CREATE INDEX IF NOT EXISTS idx_reports_domain ON reports(domain);
CREATE INDEX IF NOT EXISTS idx_records_report_id ON records(report_id);
CREATE INDEX IF NOT EXISTS idx_records_source_ip ON records(source_ip);
