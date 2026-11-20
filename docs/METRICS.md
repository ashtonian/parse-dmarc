# Prometheus metrics and Grafana

Parse DMARC exposes Prometheus metrics at `/metrics` (on by default, `--metrics=false` turns it off) and ships two Grafana dashboards: `grafana/dashboard.json` on these metrics, and `grafana/dashboard-postgres.json`, a drill-down on the PostgreSQL tables for a `DATABASE_URL` deployment. This page is the full catalogue plus scrape, alert and provisioning examples. The README has the summary.

## Available metrics

### Build Information

| Metric                   | Type  | Description                                     |
| ------------------------ | ----- | ----------------------------------------------- |
| `parse_dmarc_build_info` | Gauge | Build information (version, commit, build_date) |

### Report Processing

| Metric                                             | Type      | Description                                                |
| -------------------------------------------------- | --------- | ---------------------------------------------------------- |
| `parse_dmarc_reports_fetched_total`                | Counter   | Total DMARC report emails fetched from IMAP                |
| `parse_dmarc_reports_parsed_total`                 | Counter   | Total DMARC reports successfully parsed                    |
| `parse_dmarc_reports_stored_total`                 | Counter   | Total DMARC reports stored in database                     |
| `parse_dmarc_reports_parse_errors_total`           | Counter   | Total parse errors                                         |
| `parse_dmarc_reports_store_errors_total`           | Counter   | Total storage errors                                       |
| `parse_dmarc_reports_archive_errors_total`         | Counter   | Reports the S3 archive refused; their messages are retried |
| `parse_dmarc_reports_attachments_total`            | Counter   | Total attachments processed                                |
| `parse_dmarc_reports_fetch_duration_seconds`       | Histogram | Duration of fetch operations                               |
| `parse_dmarc_reports_last_fetch_timestamp_seconds` | Gauge     | Unix timestamp of last successful fetch                    |
| `parse_dmarc_reports_fetch_cycles_total`           | Counter   | Total fetch cycles executed                                |
| `parse_dmarc_reports_fetch_errors_total`           | Counter   | Total fetch cycle errors                                   |

### IMAP Connection

| Metric                                         | Type      | Labels | Description                              |
| ---------------------------------------------- | --------- | ------ | ---------------------------------------- |
| `parse_dmarc_imap_connections_total`           | Counter   | status | IMAP connection attempts (success/error) |
| `parse_dmarc_imap_connection_duration_seconds` | Histogram |        | IMAP connection establishment duration   |

### DMARC Statistics

| Metric                                       | Type  | Description                       |
| -------------------------------------------- | ----- | --------------------------------- |
| `parse_dmarc_dmarc_reports_total`            | Gauge | Total reports in database         |
| `parse_dmarc_dmarc_messages_total`           | Gauge | Total messages across all reports |
| `parse_dmarc_dmarc_compliant_messages_total` | Gauge | Total DMARC-compliant messages    |
| `parse_dmarc_dmarc_compliance_rate`          | Gauge | Overall compliance rate (0-100)   |
| `parse_dmarc_dmarc_unique_source_ips`        | Gauge | Number of unique source IPs       |
| `parse_dmarc_dmarc_unique_domains`           | Gauge | Number of unique domains          |

### Per-Domain/Org Metrics

| Metric                                        | Type  | Labels      | Description                  |
| --------------------------------------------- | ----- | ----------- | ---------------------------- |
| `parse_dmarc_dmarc_messages_by_domain`        | Gauge | domain      | Messages per domain          |
| `parse_dmarc_dmarc_compliance_rate_by_domain` | Gauge | domain      | Compliance rate per domain   |
| `parse_dmarc_dmarc_reports_by_org`            | Gauge | org_name    | Reports per organization     |
| `parse_dmarc_dmarc_messages_by_disposition`   | Gauge | disposition | Messages by disposition type |

### Domain posture

Read from the store at each refresh, so they survive a restart. Timestamps are the end of the report period in Unix seconds, `0` for never. Domain and reporter labels come from report content, which anyone who can mail the report address controls: past 100 values the smallest are summed under `other`.

| Metric                                                     | Type  | Labels        | Description                                                                                                                  |
| ---------------------------------------------------------- | ----- | ------------- | ---------------------------------------------------------------------------------------------------------------------------- |
| `parse_dmarc_dmarc_messages_by_class`                      | Gauge | domain, class | Messages by class: `pass` (aligned), `unaligned` (SPF or DKIM passed for another domain), `unauthenticated` (nothing passed) |
| `parse_dmarc_dmarc_last_report_timestamp_seconds`          | Gauge | domain        | End of the newest DMARC report for the domain                                                                                |
| `parse_dmarc_dmarc_last_unaligned_timestamp_seconds`       | Gauge | domain        | End of the newest report with an unaligned record                                                                            |
| `parse_dmarc_dmarc_last_unauthenticated_timestamp_seconds` | Gauge | domain        | End of the newest report with an unauthenticated record                                                                      |

### TLS-RPT

| Metric                                              | Type  | Labels         | Description                                                                                                        |
| --------------------------------------------------- | ----- | -------------- | ------------------------------------------------------------------------------------------------------------------ |
| `parse_dmarc_tlsrpt_sessions`                       | Gauge | domain, result | TLS sessions reported per policy domain: `successful` or `failed`                                                  |
| `parse_dmarc_tlsrpt_last_report_timestamp_seconds`  | Gauge | domain         | End of the newest TLS-RPT report covering the policy domain                                                        |
| `parse_dmarc_tlsrpt_last_failure_timestamp_seconds` | Gauge | domain         | End of the newest report with a failed session for the domain                                                      |
| `parse_dmarc_tlsrpt_failed_sessions_by_type`        | Gauge | result_type    | Failed sessions by RFC 8460 result type (`certificate-expired`, `sts-policy-fetch-error`, ...); others are `other` |

### Authentication Results

| Metric                           | Type  | Labels | Description                       |
| -------------------------------- | ----- | ------ | --------------------------------- |
| `parse_dmarc_dmarc_spf_results`  | Gauge | result | SPF authentication result counts  |
| `parse_dmarc_dmarc_dkim_results` | Gauge | result | DKIM authentication result counts |

### HTTP Server

| Metric                                      | Type      | Labels               | Description                |
| ------------------------------------------- | --------- | -------------------- | -------------------------- |
| `parse_dmarc_http_requests_total`           | Counter   | method, path, status | Total HTTP requests        |
| `parse_dmarc_http_request_duration_seconds` | Histogram | method, path         | HTTP request duration      |
| `parse_dmarc_http_requests_in_flight`       | Gauge     |                      | Current in-flight requests |

### Go Runtime (Built-in)

Standard Go runtime metrics are also exposed:

- `go_goroutines` - Number of goroutines
- `go_memstats_*` - Memory statistics
- `go_gc_*` - Garbage collection metrics
- `process_*` - Process metrics (CPU, memory, file descriptors)

## Disabling metrics

To disable the metrics endpoint:

```bash
# Command line
./parse-dmarc --metrics=false

# Environment variable
export PARSE_DMARC_METRICS=false

# Docker
docker run -e PARSE_DMARC_METRICS=false ghcr.io/dmarcguardhq/parse-dmarc:latest
```

## Prometheus configuration

Add Parse DMARC to your `prometheus.yml`:

```yaml
scrape_configs:
  - job_name: "parse-dmarc"
    static_configs:
      - targets: ["parse-dmarc:8080"]
    scrape_interval: 30s
    metrics_path: /metrics
```

For Kubernetes with ServiceMonitor (Prometheus Operator):

```yaml
apiVersion: monitoring.coreos.com/v1
kind: ServiceMonitor
metadata:
  name: parse-dmarc
  labels:
    app: parse-dmarc
spec:
  selector:
    matchLabels:
      app: parse-dmarc
  endpoints:
    - port: http
      path: /metrics
      interval: 30s
```

## Grafana dashboard

Two dashboards ship in `grafana/`, tagged `parse-dmarc` and linked to each other:

- `grafana/dashboard.json` reads the Prometheus metrics above.
- `grafana/dashboard-postgres.json` reads the reports from the PostgreSQL database for drill-down: senders, published policies, reporters and TLS-RPT failure details. See [PostgreSQL dashboard](#postgresql-dashboard).

### Import Manually

1. In Grafana, go to **Dashboards** > **Import**
2. Upload `grafana/dashboard.json` (or `grafana/dashboard-postgres.json`) or paste its contents
3. Click **Import**
4. Pick the data source in the dashboard's `datasource` variable: Prometheus for `dashboard.json`, PostgreSQL for `dashboard-postgres.json`

### Provision Automatically (Recommended for Production)

```bash
# Copy the dashboards to Grafana dashboards directory
cp grafana/dashboard.json grafana/dashboard-postgres.json /var/lib/grafana/dashboards/parse-dmarc/

# Copy provisioning config
cp grafana/provisioning.yaml /etc/grafana/provisioning/dashboards/parse-dmarc.yaml

# Restart Grafana or wait for it to pick up changes
systemctl restart grafana-server
```

### Dashboard Variables

| Variable     | Purpose                                                          |
| ------------ | ---------------------------------------------------------------- |
| `datasource` | Prometheus datasource to query                                   |
| `job`        | Filter by Prometheus job label                                   |
| `instance`   | Filter by instance(s)                                            |
| `domain`     | Filter by domain(s), DMARC policy domains and TLS-RPT ones alike |

### Dashboard Sections

| Section                            | What It Shows                                                                                                                                                                  |
| ---------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| **Overview - Golden Signals**      | Compliance rate, total messages, reports count, time since last fetch                                                                                                          |
| **DMARC Authentication Results**   | SPF/DKIM pass rates, disposition breakdown, per-domain compliance                                                                                                              |
| **Report Sources & Organizations** | Top reporting organizations (Google, Microsoft, etc.), messages by domain                                                                                                      |
| **Domain Posture**                 | Per domain: time since the last report, days since the last unaligned and the last unauthenticated record (`never` when there was none), messages by class                     |
| **TLS-RPT**                        | TLS sessions per policy domain, failed sessions by result type, time since the last TLS-RPT report and the last failed session per policy domain (`never` when there was none) |
| **IMAP & Fetch Operations**        | Connection health, fetch cycle monitoring, latency heatmaps                                                                                                                    |
| **Error Tracking**                 | Parse errors, storage errors, S3 archive errors, fetch failures                                                                                                                |
| **HTTP Server**                    | Request rates, latency percentiles, error rates                                                                                                                                |
| **Go Runtime**                     | Goroutines, memory usage, GC stats, CPU usage                                                                                                                                  |

The days since the last unaligned record turn green at 14, the wait the `DMARCReadyForStricterPolicy` alert below uses; within 2 days they are red, as the `DMARCUnalignedSender` alert fires.

### PostgreSQL dashboard

`grafana/dashboard-postgres.json` queries the store through Grafana's built-in PostgreSQL data source (plugin `grafana-postgresql-datasource`), so Parse DMARC has to store its reports in PostgreSQL (`DATABASE_URL`); Grafana cannot read the SQLite file. A role that can read the tables the dashboard queries is enough:

```sql
CREATE ROLE grafana_reader LOGIN PASSWORD 'change-me';
GRANT CONNECT ON DATABASE dmarc TO grafana_reader;
GRANT USAGE ON SCHEMA public TO grafana_reader;
GRANT SELECT ON reports, records, sources, tlsrpt_reports, tlsrpt_policies, tlsrpt_failures TO grafana_reader;
-- Optional: keep a slow panel query from holding the database Parse DMARC writes to
ALTER ROLE grafana_reader SET statement_timeout = '30s';
```

Use the database name and schema `DATABASE_URL` points at in place of `dmarc` and `public`. Then add the data source, for example by provisioning:

```yaml
apiVersion: 1
datasources:
  - name: Parse DMARC
    type: grafana-postgresql-datasource
    url: db.example.com:5432
    user: grafana_reader
    jsonData:
      database: dmarc
      sslmode: verify-full
    secureJsonData:
      password: change-me
```

| Variable     | Purpose                                                                         |
| ------------ | ------------------------------------------------------------------------------- |
| `datasource` | PostgreSQL data source to query                                                 |
| `domain`     | Filter by domain(s): every DMARC policy domain and TLS-RPT policy domain stored |

The dashboard shows UTC. A report counts at the start of the period it covers (`date_begin`): the time series group by UTC day, and every panel takes the reports that begin in the time range, except **Last Report per Domain**, which covers every stored report as the posture metrics do.

| Section                  | What It Shows                                                                                                                                                                                          |
| ------------------------ | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| **Overview**             | Reports, messages, pass rate, unaligned and unauthenticated messages; per domain the newest DMARC report, unaligned record, unauthenticated record, TLS-RPT report and TLS failure (`never` for none)  |
| **DMARC**                | Messages per day by class, stacked; DMARC pass rate per domain per day                                                                                                                                 |
| **Senders**              | The top 50 unaligned senders with the domains SPF and DKIM passed for, the top 50 unauthenticated sources with the dispositions applied; each with the service, forward-confirmed PTR, ASN and country |
| **Policy and Reporters** | Each published policy (`p`, `sp`, `np`, `adkim`, `aspf`, `pct`, `testing`) with the first and last report that carried it, dispositions by class, policy override reasons, reporters                   |
| **TLS-RPT**              | Sessions per policy domain per day, failed sessions by result type, failure details: result type, receiving MX and IP, sending MTA, reason code                                                        |

The service, PTR, ASN and country columns are filled in by source enrichment (`ENRICH_*` in the README) and stay empty for addresses it has not looked up.

### Example Grafana Panels

**Compliance Rate Gauge:**

```promql
parse_dmarc_dmarc_compliance_rate
```

**Messages Over Time:**

```promql
rate(parse_dmarc_dmarc_messages_total[5m])
```

**Compliance Rate by Domain:**

```promql
parse_dmarc_dmarc_compliance_rate_by_domain
```

**SPF/DKIM Pass Rate:**

```promql
# SPF Pass Rate
parse_dmarc_dmarc_spf_results{result="pass"} / ignoring(result) sum(parse_dmarc_dmarc_spf_results) * 100

# DKIM Pass Rate
parse_dmarc_dmarc_dkim_results{result="pass"} / ignoring(result) sum(parse_dmarc_dmarc_dkim_results) * 100
```

**Fetch Success Rate:**

```promql
1 - (rate(parse_dmarc_reports_fetch_errors_total[1h]) / rate(parse_dmarc_reports_fetch_cycles_total[1h]))
```

**IMAP Connection Health:**

```promql
rate(parse_dmarc_imap_connections_total{status="success"}[5m]) /
(rate(parse_dmarc_imap_connections_total{status="success"}[5m]) + rate(parse_dmarc_imap_connections_total{status="error"}[5m]))
```

**HTTP Request Latency (p95):**

```promql
histogram_quantile(0.95, rate(parse_dmarc_http_request_duration_seconds_bucket[5m]))
```

**Reports by Organization:**

```promql
topk(10, parse_dmarc_dmarc_reports_by_org)
```

**Days Since the Last Unaligned Record (`-1` for never, which the dashboard maps to "never"):**

```promql
((time() - (parse_dmarc_dmarc_last_unaligned_timestamp_seconds > 0)) / 86400)
or ((parse_dmarc_dmarc_last_unaligned_timestamp_seconds == 0) - 1)
```

### Alerting Rules

Example Prometheus alerting rules:

```yaml
groups:
  - name: parse-dmarc
    rules:
      - alert: DMARCComplianceLow
        expr: parse_dmarc_dmarc_compliance_rate < 90
        for: 1h
        labels:
          severity: warning
        annotations:
          summary: "DMARC compliance rate is below 90%"
          description: "Current compliance rate: {{ $value }}%"

      - alert: DMARCFetchFailures
        expr: rate(parse_dmarc_reports_fetch_errors_total[15m]) > 0
        for: 30m
        labels:
          severity: critical
        annotations:
          summary: "Parse DMARC fetch failures detected"
          description: "IMAP fetch operations are failing"

      - alert: IMAPConnectionErrors
        expr: rate(parse_dmarc_imap_connections_total{status="error"}[5m]) > 0
        for: 10m
        labels:
          severity: warning
        annotations:
          summary: "IMAP connection errors detected"
          description: "Check IMAP credentials and server connectivity"

      - alert: NoRecentFetch
        expr: time() - parse_dmarc_reports_last_fetch_timestamp_seconds > 600
        for: 5m
        labels:
          severity: warning
        annotations:
          summary: "No recent DMARC report fetch"
          description: "Last fetch was {{ humanizeDuration $value }} ago"

      # A sender passes SPF or DKIM, but not for your domain: a service
      # sending on your behalf without alignment, or a forwarder. These are
      # the records to fix before p=quarantine or p=reject.
      - alert: DMARCUnalignedSender
        expr: |
          parse_dmarc_dmarc_last_unaligned_timestamp_seconds > 0
          and time() - parse_dmarc_dmarc_last_unaligned_timestamp_seconds < 2 * 86400
        labels:
          severity: warning
        annotations:
          summary: "Unaligned mail for {{ $labels.domain }}"
          description: "A report ending {{ $value | humanizeTimestamp }} counts mail that passed SPF or DKIM for another domain"

      # Reports usually arrive daily from every large receiver your mail
      # reaches. Silence means the rua address, the mail filter or the
      # intake broke; or the domain sent no mail.
      - alert: DMARCReportsMissing
        expr: time() - parse_dmarc_dmarc_last_report_timestamp_seconds > 3 * 86400
        labels:
          severity: warning
        annotations:
          summary: "No DMARC report for {{ $labels.domain }} in 3 days"

      # Days without an unaligned record: the evidence for tightening the
      # policy, for example 14 days before moving to p=quarantine.
      - alert: DMARCReadyForStricterPolicy
        expr: |
          (time() - parse_dmarc_dmarc_last_unaligned_timestamp_seconds > 14 * 86400)
          and (time() - parse_dmarc_dmarc_last_report_timestamp_seconds < 2 * 86400)
        labels:
          severity: info
        annotations:
          summary: "{{ $labels.domain }} has had 14 days of aligned mail"

      # A sending MTA could not deliver over TLS under your MTA-STS or DANE
      # policy: an expired certificate, a policy it could not fetch, an MX
      # outside the policy.
      - alert: TLSRPTFailures
        expr: |
          parse_dmarc_tlsrpt_last_failure_timestamp_seconds > 0
          and time() - parse_dmarc_tlsrpt_last_failure_timestamp_seconds < 2 * 86400
        labels:
          severity: warning
        annotations:
          summary: "TLS delivery failures to {{ $labels.domain }}"

      - alert: DMARCReportParseErrors
        expr: increase(parse_dmarc_reports_parse_errors_total[1d]) > 0
        labels:
          severity: warning
        annotations:
          summary: "Report attachments that do not parse"
          description: 'The log line "failed to parse report" names the message'

      - alert: DMARCArchiveErrors
        expr: increase(parse_dmarc_reports_archive_errors_total[1h]) > 0
        labels:
          severity: warning
        annotations:
          summary: "The S3 archive refuses reports; their mail is retried every fetch"
```

## Docker Compose with Prometheus and Grafana

Complete monitoring stack:

```yaml
services:
  parse-dmarc:
    image: ghcr.io/dmarcguardhq/parse-dmarc:latest
    ports:
      - "8080:8080"
    volumes:
      - ./config.json:/app/config.json
      - ./data:/data

  prometheus:
    image: prom/prometheus
    ports:
      - "9090:9090"
    volumes:
      - ./prometheus.yml:/etc/prometheus/prometheus.yml
    command:
      - "--config.file=/etc/prometheus/prometheus.yml"

  grafana:
    image: grafana/grafana
    ports:
      - "3000:3000"
    environment:
      - GF_SECURITY_ADMIN_PASSWORD=admin
    volumes:
      - grafana-data:/var/lib/grafana

volumes:
  grafana-data:
```

With `prometheus.yml`:

```yaml
global:
  scrape_interval: 15s

scrape_configs:
  - job_name: "parse-dmarc"
    static_configs:
      - targets: ["parse-dmarc:8080"]
```

Access:

- Parse DMARC Dashboard: http://localhost:8080
- Prometheus: http://localhost:9090
- Grafana: http://localhost:3000 (admin/admin)
