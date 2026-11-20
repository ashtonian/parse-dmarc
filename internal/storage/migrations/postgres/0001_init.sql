-- Aggregate reports and their records. A report is identified by its
-- reporter, its report ID and the policy domain it covers (RFC 7489 scopes
-- report_id to the generating organization). Times are Unix seconds, as in
-- the SQLite schema, so one set of queries serves both.
CREATE TABLE reports (
	id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
	report_id TEXT NOT NULL,
	org_name TEXT NOT NULL,
	email TEXT,
	domain TEXT NOT NULL,
	date_begin BIGINT NOT NULL,
	date_end BIGINT NOT NULL,
	created_at BIGINT NOT NULL,
	policy_p TEXT,
	policy_sp TEXT,
	policy_pct INTEGER,
	total_messages INTEGER,
	compliant_messages INTEGER,
	raw_report JSONB NOT NULL,
	UNIQUE (org_name, report_id, domain)
);

CREATE TABLE records (
	id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
	report_id BIGINT NOT NULL REFERENCES reports(id) ON DELETE CASCADE,
	source_ip TEXT NOT NULL,
	count INTEGER NOT NULL,
	disposition TEXT,
	dkim_result TEXT,
	spf_result TEXT,
	header_from TEXT,
	envelope_from TEXT,
	dkim_domains JSONB,
	spf_domains JSONB
);

CREATE INDEX idx_reports_date_begin ON reports(date_begin);
CREATE INDEX idx_reports_date_end ON reports(date_end);
CREATE INDEX idx_reports_domain ON reports(domain);
CREATE INDEX idx_records_report_id ON records(report_id);
CREATE INDEX idx_records_source_ip ON records(source_ip);
