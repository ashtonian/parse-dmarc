<script setup>
import {
  formatDate,
  formatNumber,
  formatRate,
  formatRelative,
} from "@/lib/format.js";

defineProps({
  domains: {
    type: Array,
    default: () => [],
  },
});

const successRate = (domain) => {
  const total = domain.successful_sessions + domain.failed_sessions;
  return total > 0 ? (domain.successful_sessions / total) * 100 : null;
};
</script>

<template>
  <div class="card table-container">
    <div class="table-toolbar">
      <h2 class="section-title">Policy Domains</h2>
    </div>

    <div class="table-responsive">
      <table class="report-table">
        <thead>
          <tr>
            <th>Domain</th>
            <th class="text-right">Successful</th>
            <th class="text-right">Failed</th>
            <th class="text-right">Success</th>
            <th>Last Report</th>
            <th>Last Failure</th>
          </tr>
        </thead>
        <tbody>
          <tr v-for="domain in domains" :key="domain.policy_domain">
            <td class="font-mono">{{ domain.policy_domain }}</td>
            <td class="text-right font-mono">
              {{ formatNumber(domain.successful_sessions) }}
            </td>
            <td
              class="text-right font-mono"
              :class="{ 'text-danger': domain.failed_sessions > 0 }"
            >
              {{ formatNumber(domain.failed_sessions) }}
            </td>
            <td class="text-right font-mono">
              {{ formatRate(successRate(domain)) }}
            </td>
            <td
              class="text-muted"
              :title="formatDate(domain.last_report, { withYear: true })"
            >
              {{ formatRelative(domain.last_report) }}
            </td>
            <td
              v-if="domain.last_failure"
              class="text-danger"
              :title="formatDate(domain.last_failure, { withYear: true })"
            >
              {{ formatRelative(domain.last_failure) }}
            </td>
            <td v-else class="text-muted">Never</td>
          </tr>
        </tbody>
      </table>
    </div>

    <div v-if="domains.length === 0" class="empty-table">
      <p>No policy domains reported.</p>
    </div>
  </div>
</template>

<style scoped>
/* --- Container --- */
.table-container {
  background: var(--bg-card);
  border: 1px solid var(--border-subtle);
  border-radius: var(--radius-card);
  overflow: hidden;
  display: flex;
  flex-direction: column;
}

.table-toolbar {
  padding: 16px 20px;
  display: flex;
  justify-content: space-between;
  align-items: center;
  border-bottom: 1px solid var(--border-subtle);
}

.section-title {
  font-size: 1rem;
  font-weight: 600;
  margin: 0;
  color: var(--text-main);
}

/* --- Table Structure --- */
.table-responsive {
  width: 100%;
  overflow-x: auto;
}

.report-table {
  width: 100%;
  border-collapse: collapse;
  font-size: 0.875rem;
  white-space: nowrap;
}

th {
  text-align: left;
  padding: 12px 20px;
  background: var(--bg-app);
  color: var(--text-muted);
  font-weight: 600;
  font-size: 0.75rem;
  text-transform: uppercase;
  letter-spacing: 0.05em;
  border-bottom: 1px solid var(--border-subtle);
}

td {
  padding: 14px 20px;
  border-bottom: 1px solid var(--border-subtle);
  color: var(--text-main);
}

tr:last-child td {
  border-bottom: none;
}

.font-mono {
  font-family: var(--font-mono);
  font-size: 0.8125rem;
}

.text-muted {
  color: var(--text-muted);
}

.text-danger {
  color: var(--c-danger);
}

.text-right {
  text-align: right;
}

/* --- Empty State --- */
.empty-table {
  padding: 32px 20px;
  text-align: center;
  color: var(--text-muted);
}

.empty-table p {
  margin: 0;
  font-size: 0.875rem;
}

/* --- Responsive --- */
@media (max-width: 768px) {
  th,
  td {
    padding: 12px 16px;
  }
}
</style>
