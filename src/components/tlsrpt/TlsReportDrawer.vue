<script setup>
import { computed, ref } from "vue";
import DetailDrawer from "../common/DetailDrawer.vue";
import { formatDate, formatNumber, formatRate } from "@/lib/format.js";
import { describeResultType, policyTypeLabel } from "@/lib/tlsrpt.js";

const props = defineProps({
  isOpen: Boolean,
  // The list row the report was opened from: it carries the backend's
  // verdict for the report.
  summary: {
    type: Object,
    default: null,
  },
  report: {
    type: Object,
    default: null,
  },
  loading: {
    type: Boolean,
    default: false,
  },
  // Why the report could not be loaded, if it could not.
  error: {
    type: String,
    default: "",
  },
});

const emit = defineEmits(["close"]);

const activeTab = ref("overview");

const STATUS_LABEL = {
  empty: "EMPTY",
  pass: "PASS",
  fail: "FAIL",
};

const VERDICT_CLASS = {
  empty: "badge-neutral",
  pass: "badge-success",
  fail: "badge-danger",
};

const status = computed(() => props.summary?.status ?? "empty");

// date_range is RFC 3339; formatDate takes unix seconds.
const formatRFC3339 = (value) =>
  value ? formatDate(Date.parse(value) / 1000, { withYear: true }) : "N/A";

// The endpoints a failure detail names, in RFC 8460 order.
const FAILURE_FIELDS = [
  ["sending_mta_ip", "Sending MTA"],
  ["receiving_mx_hostname", "Receiving MX"],
  ["receiving_mx_helo", "MX HELO"],
  ["receiving_ip", "Receiving IP"],
  ["failure_reason_code", "Reason Code"],
  ["additional_information", "Details"],
];

const failureFields = (failure) =>
  FAILURE_FIELDS.filter(([key]) => failure[key]);
</script>

<template>
  <DetailDrawer
    :is-open="isOpen"
    :loading="loading"
    :empty="!report"
    :title="report?.organization_name || 'TLS Report'"
    :subtitle="summary?.policy_domains?.join(', ') ?? ''"
    close-label="Close TLS report details panel"
    :empty-text="error ? `Could not load the report: ${error}` : undefined"
    @close="emit('close')"
  >
    <!-- TLS Verdict Card -->
    <div class="verdict-card" :class="VERDICT_CLASS[status]">
      <div class="verdict-row">
        <span class="verdict-label">TLS Result</span>
        <span class="verdict-value">{{ STATUS_LABEL[status] }}</span>
      </div>
      <div class="verdict-meta">
        <span
          >Successful:
          <strong>{{
            formatNumber(summary?.successful_sessions)
          }}</strong></span
        >
        <span
          >Failed:
          <strong>{{ formatNumber(summary?.failed_sessions) }}</strong></span
        >
        <span
          >Success rate:
          <strong>{{ formatRate(summary?.success_rate) }}</strong></span
        >
      </div>
    </div>

    <!-- Tabs -->
    <div class="tabs">
      <button
        :class="{ active: activeTab === 'overview' }"
        @click="activeTab = 'overview'"
      >
        Overview
      </button>
      <button
        :class="{ active: activeTab === 'policies' }"
        @click="activeTab = 'policies'"
      >
        Policies ({{ report.policies.length }})
      </button>
      <button
        :class="{ active: activeTab === 'raw' }"
        @click="activeTab = 'raw'"
      >
        Raw Data
      </button>
    </div>

    <!-- Overview Tab -->
    <div v-if="activeTab === 'overview'" class="tab-content">
      <div class="info-grid">
        <div class="info-item">
          <span class="info-label">Report ID</span>
          <span class="info-value font-mono">{{
            report.report_id || "N/A"
          }}</span>
        </div>
        <div class="info-item">
          <span class="info-label">Contact</span>
          <span class="info-value">{{ report.contact_info || "N/A" }}</span>
        </div>
        <div class="info-item">
          <span class="info-label">Date Range</span>
          <span class="info-value">
            {{ formatRFC3339(report.date_range?.start) }} -
            {{ formatRFC3339(report.date_range?.end) }}
          </span>
        </div>
        <div class="info-item">
          <span class="info-label">Policy Domains</span>
          <span class="info-value font-mono">{{
            summary?.policy_domains?.join(", ") || "N/A"
          }}</span>
        </div>
      </div>
    </div>

    <!-- Policies Tab -->
    <div v-if="activeTab === 'policies'" class="tab-content">
      <div v-if="!report.policies.length" class="empty-state">
        No policies found in this report.
      </div>

      <div
        v-for="(policy, idx) in report.policies"
        :key="idx"
        class="policy-card"
      >
        <div class="policy-header">
          <div class="policy-domain">
            <span class="font-mono">{{ policy.policy_domain }}</span>
            <span class="policy-type">{{
              policyTypeLabel(policy.policy_type)
            }}</span>
          </div>
          <span class="policy-count">
            <span class="text-success"
              >{{ formatNumber(policy.successful_sessions) }} ok</span
            >
            /
            <span :class="{ 'text-danger': policy.failed_sessions > 0 }"
              >{{ formatNumber(policy.failed_sessions) }} failed</span
            >
          </span>
        </div>

        <div class="policy-body">
          <div v-if="policy.mx_hosts.length" class="policy-field">
            <span class="info-label">MX Hosts</span>
            <span class="domain-mono">{{ policy.mx_hosts.join(", ") }}</span>
          </div>

          <div v-if="policy.policy_strings.length" class="policy-field">
            <span class="info-label">Policy</span>
            <pre class="policy-strings">{{
              policy.policy_strings.join("\n")
            }}</pre>
          </div>

          <div v-if="policy.failure_details.length" class="policy-field">
            <span class="info-label">Failure Details</span>
            <div
              v-for="(failure, fIdx) in policy.failure_details"
              :key="fIdx"
              class="failure-item"
            >
              <div class="failure-header">
                <span class="failure-type">{{ failure.result_type }}</span>
                <span class="failure-count"
                  >{{ formatNumber(failure.failed_sessions) }} sessions</span
                >
              </div>
              <p
                v-if="describeResultType(failure.result_type)"
                class="failure-desc"
              >
                {{ describeResultType(failure.result_type) }}
              </p>
              <dl v-if="failureFields(failure).length" class="failure-fields">
                <template
                  v-for="[key, label] in failureFields(failure)"
                  :key="key"
                >
                  <dt>{{ label }}</dt>
                  <dd>{{ failure[key] }}</dd>
                </template>
              </dl>
            </div>
          </div>
          <div v-else-if="policy.failed_sessions > 0" class="empty-auth">
            The reporter sent no failure details.
          </div>
        </div>
      </div>
    </div>

    <!-- Raw Data Tab -->
    <div v-if="activeTab === 'raw'" class="tab-content">
      <div class="raw-data-section">
        <pre class="code-block">{{ JSON.stringify(report, null, 2) }}</pre>
      </div>
    </div>
  </DetailDrawer>
</template>

<style scoped>
/* --- Verdict Card --- */
.verdict-card {
  padding: 16px;
  border-radius: var(--radius-card);
  margin-bottom: 20px;
  border: 1px solid transparent;
}

.badge-success {
  background: var(--c-success-soft);
  border-color: var(--c-success);
  color: var(--c-success);
}
.badge-danger {
  background: var(--c-danger-soft);
  border-color: var(--c-danger);
  color: var(--c-danger);
}
.badge-neutral {
  background: var(--bg-app);
  border-color: var(--border-subtle);
  color: var(--text-muted);
}

.verdict-row {
  display: flex;
  justify-content: space-between;
  align-items: center;
  margin-bottom: 8px;
}
.verdict-label {
  font-size: 0.75rem;
  font-weight: 600;
  text-transform: uppercase;
  opacity: 0.8;
}
.verdict-value {
  font-size: 1.25rem;
  font-weight: 800;
}

.verdict-meta {
  font-size: 0.875rem;
  opacity: 0.9;
  display: flex;
  gap: 16px;
  flex-wrap: wrap;
}

/* --- Tabs --- */
.tabs {
  display: flex;
  gap: 4px;
  border-bottom: 1px solid var(--border-subtle);
  margin-bottom: 20px;
}

.tabs button {
  background: transparent;
  border: none;
  padding: 10px 16px;
  font-size: 0.875rem;
  font-weight: 500;
  color: var(--text-muted);
  cursor: pointer;
  border-bottom: 2px solid transparent;
  margin-bottom: -1px;
  transition: all 0.2s;
  font-family: var(--font-sans);
}

.tabs button:hover {
  color: var(--text-main);
}

.tabs button.active {
  color: var(--c-primary);
  border-bottom-color: var(--c-primary);
}

/* --- Tab Content --- */
.tab-content {
  animation: fadeIn 0.2s ease;
}

@keyframes fadeIn {
  from {
    opacity: 0;
    transform: translateY(4px);
  }
  to {
    opacity: 1;
    transform: translateY(0);
  }
}

/* --- Info Grid (Overview) --- */
.info-grid {
  display: grid;
  gap: 16px;
}

.info-item {
  display: flex;
  flex-direction: column;
  gap: 4px;
}

.info-label {
  font-size: 0.75rem;
  text-transform: uppercase;
  letter-spacing: 0.05em;
  color: var(--text-muted);
  font-weight: 600;
}

.info-value {
  font-size: 0.875rem;
  color: var(--text-main);
  overflow-wrap: anywhere;
}

/* --- Policy Card --- */
.policy-card {
  background: var(--bg-app);
  border: 1px solid var(--border-subtle);
  border-radius: var(--radius-card);
  margin-bottom: 16px;
  overflow: hidden;
}

.policy-header {
  padding: 12px 16px;
  display: flex;
  justify-content: space-between;
  align-items: center;
  gap: 12px;
  border-bottom: 1px solid var(--border-subtle);
  background: var(--bg-card);
}

.policy-domain {
  display: flex;
  align-items: center;
  gap: 8px;
  color: var(--text-main);
  font-weight: 500;
  min-width: 0;
  overflow-wrap: anywhere;
}

.policy-type {
  font-size: 0.65rem;
  padding: 2px 6px;
  border-radius: 4px;
  text-transform: uppercase;
  font-weight: 600;
  background: var(--bg-app);
  border: 1px solid var(--border-subtle);
  color: var(--text-muted);
  white-space: nowrap;
}

.policy-count {
  font-size: 0.8125rem;
  color: var(--text-muted);
  font-family: var(--font-mono);
  white-space: nowrap;
}

.policy-body {
  padding: 12px 16px;
  display: flex;
  flex-direction: column;
  gap: 12px;
}

.policy-field {
  display: flex;
  flex-direction: column;
  gap: 6px;
}

.domain-mono {
  font-family: var(--font-mono);
  font-size: 0.75rem;
  color: var(--text-main);
  word-break: break-all;
}

.policy-strings {
  margin: 0;
  padding: 10px;
  background: var(--bg-card);
  border: 1px solid var(--border-subtle);
  border-radius: 6px;
  font-family: var(--font-mono);
  font-size: 0.75rem;
  color: var(--text-main);
  white-space: pre-wrap;
  word-break: break-all;
}

/* --- Failure Details --- */
.failure-item {
  background: var(--bg-card);
  border: 1px solid var(--border-subtle);
  border-radius: 6px;
  padding: 10px;
}

.failure-header {
  display: flex;
  justify-content: space-between;
  align-items: baseline;
  gap: 12px;
}

.failure-type {
  font-family: var(--font-mono);
  font-size: 0.75rem;
  font-weight: 700;
  color: var(--c-danger);
  word-break: break-all;
}

.failure-count {
  font-size: 0.7rem;
  color: var(--text-muted);
  white-space: nowrap;
}

.failure-desc {
  margin: 4px 0 0 0;
  font-size: 0.75rem;
  color: var(--text-muted);
}

.failure-fields {
  display: grid;
  grid-template-columns: max-content 1fr;
  gap: 4px 12px;
  margin: 8px 0 0 0;
  font-size: 0.75rem;
}

.failure-fields dt {
  color: var(--text-muted);
}

.failure-fields dd {
  margin: 0;
  font-family: var(--font-mono);
  color: var(--text-main);
  word-break: break-all;
}

.empty-auth {
  font-size: 0.8125rem;
  color: var(--text-muted);
  font-style: italic;
}

.text-success {
  color: var(--c-success);
}
.text-danger {
  color: var(--c-danger);
}

/* --- Raw Data --- */
.raw-data-section {
  overflow: hidden;
  border-radius: var(--radius-card);
}

.code-block {
  background: var(--code-bg);
  color: #d4d4d4;
  padding: 16px;
  font-family: var(--font-mono);
  font-size: 0.75rem;
  overflow-x: auto;
  white-space: pre-wrap;
  word-break: break-all;
  margin: 0;
  max-height: 60vh;
  border-radius: var(--radius-card);
}

/* --- Empty State --- */
.empty-state {
  text-align: center;
  color: var(--text-muted);
  padding: 32px;
  font-style: italic;
}

/* --- Utility --- */
.font-mono {
  font-family: var(--font-mono);
}

/* --- Responsive --- */
@media (max-width: 600px) {
  .verdict-meta {
    flex-direction: column;
    gap: 4px;
  }

  .policy-header {
    flex-direction: column;
    align-items: flex-start;
  }
}
</style>
