<script setup>
import { computed } from "vue";
import { formatNumber, formatRate } from "@/lib/format.js";

const props = defineProps({
  statistics: { type: Object, default: null },
  error: { type: String, default: "" },
  loading: { type: Boolean, default: false },
});

const emit = defineEmits(["refresh"]);

const totalSessions = computed(
  () =>
    (props.statistics?.successful_sessions ?? 0) +
    (props.statistics?.failed_sessions ?? 0),
);

// Any failed session marks the summary, as the backend marks a report with
// one as a fail.
const hasFailures = computed(
  () => (props.statistics?.failed_sessions ?? 0) > 0,
);
</script>

<template>
  <div class="hero-container">
    <header class="page-header">
      <div>
        <h1 class="page-title">TLS Reporting</h1>
        <p class="page-subtitle">
          TLS sessions sending servers reported for your MX hosts (RFC 8460)
        </p>
      </div>
      <div class="actions">
        <button class="btn-ghost" @click="emit('refresh')" :disabled="loading">
          <svg
            :class="{ spinning: loading }"
            width="16"
            height="16"
            viewBox="0 0 24 24"
            fill="none"
            stroke="currentColor"
            stroke-width="2"
            stroke-linecap="round"
            stroke-linejoin="round"
          >
            <path d="M21 12a9 9 0 0 0-9-9 9.75 9.75 0 0 0-6.74 2.74L3 8" />
            <path d="M3 3v5h5" />
            <path d="M3 12a9 9 0 0 0 9 9 9.75 9.75 0 0 0 6.74-2.74L21 16" />
            <path d="M16 21h5v-5" />
          </svg>
          Refresh
        </button>
      </div>
    </header>

    <div v-if="error" class="card error-card" role="alert">
      Could not load TLS-RPT data: {{ error }}
    </div>

    <div v-if="statistics?.has_data" class="stat-grid">
      <div
        class="card metric-card verdict"
        :class="hasFailures ? 'fail' : 'pass'"
      >
        <div class="metric-header">
          <span class="stat-label">Success Rate</span>
          <svg
            class="icon-subtle"
            width="20"
            height="20"
            viewBox="0 0 24 24"
            fill="none"
            stroke="currentColor"
            stroke-width="2"
            stroke-linecap="round"
            stroke-linejoin="round"
          >
            <rect x="3" y="11" width="18" height="11" rx="2" ry="2" />
            <path d="M7 11V7a5 5 0 0 1 10 0v4" />
          </svg>
        </div>
        <div class="stat-value mono rate">
          {{ formatRate(statistics.success_rate) }}
        </div>
        <div class="stat-desc">Sessions that negotiated TLS</div>
      </div>

      <div class="card metric-card">
        <div class="metric-header">
          <span class="stat-label">Sessions</span>
          <svg
            class="icon-subtle"
            width="20"
            height="20"
            viewBox="0 0 24 24"
            fill="none"
            stroke="currentColor"
            stroke-width="2"
            stroke-linecap="round"
            stroke-linejoin="round"
          >
            <polyline points="22 12 18 12 15 21 9 3 6 12 2 12" />
          </svg>
        </div>
        <div class="stat-value mono">{{ formatNumber(totalSessions) }}</div>
        <div class="stat-desc">
          Across {{ formatNumber(statistics.total_reports) }}
          {{ statistics.total_reports === 1 ? "report" : "reports" }}
        </div>
      </div>

      <div class="card metric-card">
        <div class="metric-header">
          <span class="stat-label">Failed Sessions</span>
          <svg
            class="icon-subtle"
            width="20"
            height="20"
            viewBox="0 0 24 24"
            fill="none"
            stroke="currentColor"
            stroke-width="2"
            stroke-linecap="round"
            stroke-linejoin="round"
          >
            <circle cx="12" cy="12" r="10" />
            <line x1="15" y1="9" x2="9" y2="15" />
            <line x1="9" y1="9" x2="15" y2="15" />
          </svg>
        </div>
        <div class="stat-value mono" :class="{ failed: hasFailures }">
          {{ formatNumber(statistics.failed_sessions) }}
        </div>
        <div class="stat-desc">Could not negotiate TLS</div>
      </div>

      <div class="card metric-card">
        <div class="metric-header">
          <span class="stat-label">Policy Domains</span>
          <svg
            class="icon-subtle"
            width="20"
            height="20"
            viewBox="0 0 24 24"
            fill="none"
            stroke="currentColor"
            stroke-width="2"
            stroke-linecap="round"
            stroke-linejoin="round"
          >
            <circle cx="12" cy="12" r="10" />
            <line x1="2" y1="12" x2="22" y2="12" />
            <path
              d="M12 2a15.3 15.3 0 0 1 4 10 15.3 15.3 0 0 1-4 10 15.3 15.3 0 0 1-4-10 15.3 15.3 0 0 1 4-10z"
            />
          </svg>
        </div>
        <div class="stat-value mono">
          {{ formatNumber(statistics.domains.length) }}
        </div>
        <div class="stat-desc">Covered by the reports</div>
      </div>
    </div>

    <div v-else-if="statistics" class="card setup-card">
      <div class="setup-icon">
        <svg
          width="24"
          height="24"
          viewBox="0 0 24 24"
          fill="none"
          stroke="currentColor"
          stroke-width="2"
          stroke-linecap="round"
          stroke-linejoin="round"
        >
          <circle cx="12" cy="12" r="10" />
          <line x1="12" y1="16" x2="12" y2="12" />
          <line x1="12" y1="8" x2="12.01" y2="8" />
        </svg>
      </div>
      <div class="setup-body">
        <div class="stat-value">No TLS-RPT reports yet</div>
        <p class="stat-desc">
          Mail servers that support TLS-RPT send reports once your domain
          publishes a <code>_smtp._tls</code> TXT record. Point its
          <code>rua</code> at the mailbox Parse DMARC already reads for DMARC
          reports:
        </p>
        <code class="record"
          >_smtp._tls.example.com. IN TXT "v=TLSRPTv1;
          rua=mailto:dmarc@example.com"</code
        >
        <p class="stat-desc">
          Reports cover sessions to your MX hosts under your MTA-STS or DANE
          policy, or without one.
        </p>
      </div>
    </div>
  </div>
</template>

<style scoped>
/* --- Layout --- */
.hero-container {
  display: flex;
  flex-direction: column;
  gap: 24px;
  width: 100%;
}

.page-header {
  display: flex;
  justify-content: space-between;
  align-items: flex-end;
  padding-bottom: 8px;
  border-bottom: 1px solid var(--border-subtle);
}

.page-title {
  font-size: 1.5rem;
  font-weight: 700;
  color: var(--text-main);
  margin: 0;
  letter-spacing: -0.02em;
}

.page-subtitle {
  color: var(--text-muted);
  font-size: 0.875rem;
  margin: 4px 0 0 0;
}

.actions {
  display: flex;
  gap: 8px;
}

/* --- Grid System --- */
.stat-grid {
  display: grid;
  grid-template-columns: 1fr;
  gap: 16px;
}

@media (min-width: 560px) {
  .stat-grid {
    grid-template-columns: 1fr 1fr;
  }
}

@media (min-width: 1024px) {
  .stat-grid {
    grid-template-columns: repeat(4, 1fr);
  }
}

/* --- Card Base --- */
.card {
  background: var(--bg-card);
  border: 1px solid var(--border-subtle);
  border-radius: 8px;
  padding: 20px;
  box-shadow: 0 1px 2px rgba(0, 0, 0, 0.05);
}

/* --- Text Utility --- */
.stat-label {
  font-size: 0.75rem;
  text-transform: uppercase;
  letter-spacing: 0.05em;
  font-weight: 600;
  color: var(--text-muted);
  margin-bottom: 4px;
}

.stat-value {
  font-size: 1.5rem;
  font-weight: 600;
  color: var(--text-main);
  line-height: 1.2;
}

.stat-value.mono {
  font-family: var(--font-mono);
  letter-spacing: -0.03em;
}

.stat-desc {
  font-size: 0.875rem;
  color: var(--text-muted);
  margin-top: 4px;
}

/* --- Metric Cards --- */
.metric-card {
  display: flex;
  flex-direction: column;
  justify-content: flex-start;
}
.metric-header {
  display: flex;
  justify-content: space-between;
  align-items: center;
  margin-bottom: 8px;
}
.icon-subtle {
  color: var(--text-muted);
  opacity: 0.5;
}

/* Success rate: green with no failed session, red with any */
.verdict.pass {
  border-left: 4px solid var(--c-success);
}
.verdict.pass .rate {
  color: var(--c-success);
}
.verdict.fail {
  border-left: 4px solid var(--c-danger);
}
.verdict.fail .rate,
.stat-value.failed {
  color: var(--c-danger);
}

/* --- Error --- */
.error-card {
  border-left: 4px solid var(--c-danger);
  color: var(--c-danger);
  font-size: 0.875rem;
}

/* --- Setup (no reports yet) --- */
.setup-card {
  display: flex;
  gap: 16px;
  align-items: flex-start;
  border-left: 4px solid var(--c-primary);
}

.setup-icon {
  padding: 10px;
  border-radius: 8px;
  display: flex;
  align-items: center;
  justify-content: center;
  flex-shrink: 0;
  background-color: rgba(99, 102, 241, 0.1);
  color: var(--c-primary);
}

.setup-body {
  min-width: 0;
}

.setup-body .stat-desc {
  margin: 8px 0 0 0;
}

.setup-body code {
  font-family: var(--font-mono);
  font-size: 0.8125rem;
}

.record {
  display: block;
  margin-top: 12px;
  padding: 12px 14px;
  background: var(--bg-app);
  border: 1px solid var(--border-subtle);
  border-radius: 6px;
  color: var(--text-main);
  overflow-wrap: anywhere;
}

/* --- Buttons --- */
.btn-ghost {
  background: transparent;
  border: none;
  color: var(--text-muted);
  cursor: pointer;
  display: flex;
  align-items: center;
  gap: 6px;
  font-size: 0.875rem;
  padding: 6px 12px;
  border-radius: 6px;
  transition: all 0.2s;
  font-family: var(--font-sans);
}
.btn-ghost:hover {
  background: var(--border-subtle);
  color: var(--text-main);
}
.btn-ghost:disabled {
  opacity: 0.5;
  cursor: not-allowed;
}

/* Spinning animation for refresh */
@keyframes spin {
  from {
    transform: rotate(0deg);
  }
  to {
    transform: rotate(360deg);
  }
}
.spinning {
  animation: spin 1s linear infinite;
}

/* --- Responsive --- */
@media (max-width: 767px) {
  .page-header {
    flex-direction: column;
    align-items: flex-start;
    gap: 12px;
  }

  .actions {
    width: 100%;
  }

  .btn-ghost {
    flex: 1;
    justify-content: center;
  }

  .setup-card {
    flex-direction: column;
  }
}
</style>
