// What each result type RFC 8460 section 4.3 defines means.
const RESULT_TYPE_DESCRIPTIONS = {
  "starttls-not-supported": "The MX host did not offer STARTTLS.",
  "certificate-host-mismatch":
    "The certificate does not match the MX host name the policy allows.",
  "certificate-expired": "The MX host's certificate has expired.",
  "certificate-not-trusted":
    "The certificate chain is not trusted, for example a self-signed certificate.",
  "validation-failure": "A failure outside the other result types.",
  "tlsa-invalid": "No record in the MX host's TLSA set validated.",
  "dnssec-invalid": "The resolver returned no DNSSEC-valid records.",
  "dane-required":
    "The sender requires DANE and found no DNSSEC-validated TLSA records for the MX host.",
  "sts-policy-fetch-error": "The MTA-STS policy could not be fetched.",
  "sts-policy-invalid": "The MTA-STS policy failed validation.",
  "sts-webpki-invalid":
    "The certificate of the MTA-STS policy host failed validation.",
};

// Policy types of RFC 8460 section 4.4: tlsa is a DANE policy.
const POLICY_TYPE_LABELS = {
  sts: "MTA-STS",
  tlsa: "DANE",
  "no-policy-found": "No policy",
};

// Both values come from the reporter, so only own keys count: a result type
// such as "constructor" must not resolve through the prototype.
const lookup = (table, key) => (Object.hasOwn(table, key) ? table[key] : "");

/**
 * The meaning of a TLS-RPT result type, or "" for one RFC 8460 does not define
 * @param {string} resultType
 */
export const describeResultType = (resultType) =>
  lookup(RESULT_TYPE_DESCRIPTIONS, resultType);

/**
 * The display name of a TLS-RPT policy type, else the type as reported
 * @param {string} policyType
 */
export const policyTypeLabel = (policyType) =>
  lookup(POLICY_TYPE_LABELS, policyType) || policyType;
