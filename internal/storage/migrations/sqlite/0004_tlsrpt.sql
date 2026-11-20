-- SMTP TLS Reporting (RFC 8460) reports. A report is identified by its
-- reporter and report ID; each covers one or more policies, and each policy
-- groups its failed sessions by cause and endpoints.
CREATE TABLE tlsrpt_reports (
	id INTEGER PRIMARY KEY AUTOINCREMENT,
	org_name TEXT NOT NULL,
	report_id TEXT NOT NULL,
	contact_info TEXT,
	date_begin INTEGER NOT NULL,
	date_end INTEGER NOT NULL,
	created_at INTEGER NOT NULL,
	successful_sessions INTEGER NOT NULL,
	failed_sessions INTEGER NOT NULL,
	raw_report TEXT NOT NULL,
	UNIQUE (org_name, report_id)
);

CREATE TABLE tlsrpt_policies (
	id INTEGER PRIMARY KEY AUTOINCREMENT,
	report_id INTEGER NOT NULL REFERENCES tlsrpt_reports(id) ON DELETE CASCADE,
	policy_type TEXT NOT NULL,
	policy_domain TEXT NOT NULL,
	policy_strings TEXT,
	mx_hosts TEXT,
	successful_sessions INTEGER NOT NULL,
	failed_sessions INTEGER NOT NULL
);

CREATE TABLE tlsrpt_failures (
	id INTEGER PRIMARY KEY AUTOINCREMENT,
	policy_id INTEGER NOT NULL REFERENCES tlsrpt_policies(id) ON DELETE CASCADE,
	result_type TEXT NOT NULL,
	sending_mta_ip TEXT,
	receiving_mx_hostname TEXT,
	receiving_mx_helo TEXT,
	receiving_ip TEXT,
	failed_sessions INTEGER NOT NULL,
	additional_information TEXT,
	failure_reason_code TEXT
);

CREATE INDEX idx_tlsrpt_reports_date_begin ON tlsrpt_reports(date_begin);
CREATE INDEX idx_tlsrpt_reports_date_end ON tlsrpt_reports(date_end);
CREATE INDEX idx_tlsrpt_policies_report_id ON tlsrpt_policies(report_id);
CREATE INDEX idx_tlsrpt_policies_domain ON tlsrpt_policies(policy_domain);
CREATE INDEX idx_tlsrpt_failures_policy_id ON tlsrpt_failures(policy_id);
