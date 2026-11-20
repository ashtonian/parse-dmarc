-- The RFC 9990 policy fields, the envelope recipient, policy override
-- reasons and each record's class: pass (aligned), unaligned (SPF or DKIM
-- passed for another domain) or unauthenticated (nothing passed). Rows
-- stored before are classified from the results they already carry.
ALTER TABLE reports ADD COLUMN schema_version TEXT;
ALTER TABLE reports ADD COLUMN generator TEXT;
ALTER TABLE reports ADD COLUMN policy_np TEXT;
ALTER TABLE reports ADD COLUMN policy_adkim TEXT;
ALTER TABLE reports ADD COLUMN policy_aspf TEXT;
ALTER TABLE reports ADD COLUMN policy_fo TEXT;
ALTER TABLE reports ADD COLUMN policy_testing TEXT;
ALTER TABLE reports ADD COLUMN policy_discovery_method TEXT;

ALTER TABLE records ADD COLUMN envelope_to TEXT;
ALTER TABLE records ADD COLUMN override_reasons JSONB;
ALTER TABLE records ADD COLUMN auth_class TEXT;

UPDATE records SET auth_class = CASE
	WHEN dkim_result = 'pass' OR spf_result = 'pass' THEN 'pass'
	WHEN (jsonb_typeof(dkim_domains) = 'array' AND EXISTS (
	        SELECT 1 FROM jsonb_array_elements(dkim_domains) e WHERE e->>'Result' = 'pass'))
	  OR (jsonb_typeof(spf_domains) = 'array' AND EXISTS (
	        SELECT 1 FROM jsonb_array_elements(spf_domains) e WHERE e->>'Result' = 'pass'))
	THEN 'unaligned'
	ELSE 'unauthenticated'
END;

CREATE INDEX idx_records_header_from ON records(header_from);
CREATE INDEX idx_records_auth_class ON records(auth_class);
