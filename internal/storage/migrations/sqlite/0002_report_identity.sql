-- A report is identified by its reporter, its report ID and the policy
-- domain it covers. RFC 7489 scopes report_id to the generating
-- organization, and reporters reuse one ID across the domains of a batch, so
-- a table-wide UNIQUE on report_id silently dropped real reports. Records now
-- go with their report when it is deleted.
--
-- SQLite cannot change a constraint in place: both tables are rebuilt. The
-- foreign key check waits for the commit, when the renamed tables line up.
PRAGMA defer_foreign_keys = ON;

CREATE TABLE reports_v2 (
	id INTEGER PRIMARY KEY AUTOINCREMENT,
	report_id TEXT NOT NULL,
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
	raw_report TEXT NOT NULL,
	UNIQUE (org_name, report_id, domain)
);

INSERT INTO reports_v2 (
	id, report_id, org_name, email, domain, date_begin, date_end, created_at,
	policy_p, policy_sp, policy_pct, total_messages, compliant_messages, raw_report
)
SELECT
	id, report_id, org_name, email, domain, date_begin, date_end, created_at,
	policy_p, policy_sp, policy_pct, total_messages, compliant_messages, raw_report
FROM reports;

CREATE TABLE records_v2 (
	id INTEGER PRIMARY KEY AUTOINCREMENT,
	report_id INTEGER NOT NULL REFERENCES reports_v2(id) ON DELETE CASCADE,
	source_ip TEXT NOT NULL,
	count INTEGER NOT NULL,
	disposition TEXT,
	dkim_result TEXT,
	spf_result TEXT,
	header_from TEXT,
	envelope_from TEXT,
	dkim_domains TEXT,
	spf_domains TEXT
);

INSERT INTO records_v2 (
	id, report_id, source_ip, count, disposition, dkim_result, spf_result,
	header_from, envelope_from, dkim_domains, spf_domains
)
SELECT
	id, report_id, source_ip, count, disposition, dkim_result, spf_result,
	header_from, envelope_from, dkim_domains, spf_domains
FROM records;

DROP TABLE records;
DROP TABLE reports;
ALTER TABLE reports_v2 RENAME TO reports;
ALTER TABLE records_v2 RENAME TO records;

CREATE INDEX idx_reports_date_begin ON reports(date_begin);
CREATE INDEX idx_reports_date_end ON reports(date_end);
CREATE INDEX idx_reports_domain ON reports(domain);
CREATE INDEX idx_records_report_id ON records(report_id);
CREATE INDEX idx_records_source_ip ON records(source_ip);
