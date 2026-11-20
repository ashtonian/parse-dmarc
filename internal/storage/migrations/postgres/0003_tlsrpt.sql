-- SMTP TLS Reporting (RFC 8460) reports. A report is identified by its
-- reporter and report ID; each covers one or more policies, and each policy
-- groups its failed sessions by cause and endpoints.
CREATE TABLE tlsrpt_reports (
	id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
	org_name TEXT NOT NULL,
	report_id TEXT NOT NULL,
	contact_info TEXT,
	date_begin BIGINT NOT NULL,
	date_end BIGINT NOT NULL,
	created_at BIGINT NOT NULL,
	successful_sessions BIGINT NOT NULL,
	failed_sessions BIGINT NOT NULL,
	raw_report JSONB NOT NULL,
	UNIQUE (org_name, report_id)
);

CREATE TABLE tlsrpt_policies (
	id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
	report_id BIGINT NOT NULL REFERENCES tlsrpt_reports(id) ON DELETE CASCADE,
	policy_type TEXT NOT NULL,
	policy_domain TEXT NOT NULL,
	policy_strings JSONB,
	mx_hosts JSONB,
	successful_sessions BIGINT NOT NULL,
	failed_sessions BIGINT NOT NULL
);

CREATE TABLE tlsrpt_failures (
	id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
	policy_id BIGINT NOT NULL REFERENCES tlsrpt_policies(id) ON DELETE CASCADE,
	result_type TEXT NOT NULL,
	sending_mta_ip TEXT,
	receiving_mx_hostname TEXT,
	receiving_mx_helo TEXT,
	receiving_ip TEXT,
	failed_sessions BIGINT NOT NULL,
	additional_information TEXT,
	failure_reason_code TEXT
);

CREATE INDEX idx_tlsrpt_reports_date_begin ON tlsrpt_reports(date_begin);
CREATE INDEX idx_tlsrpt_reports_date_end ON tlsrpt_reports(date_end);
CREATE INDEX idx_tlsrpt_policies_report_id ON tlsrpt_policies(report_id);
CREATE INDEX idx_tlsrpt_policies_domain ON tlsrpt_policies(policy_domain);
CREATE INDEX idx_tlsrpt_failures_policy_id ON tlsrpt_failures(policy_id);
