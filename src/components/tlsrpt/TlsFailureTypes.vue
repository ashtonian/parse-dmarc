<script setup>
import { computed } from "vue";
import { formatNumber } from "@/lib/format.js";
import { describeResultType } from "@/lib/tlsrpt.js";

const props = defineProps({
  failureTypes: {
    type: Array,
    default: () => [],
  },
});

// Shares are of the failed sessions the failure details account for.
const totalFailed = computed(() =>
  props.failureTypes.reduce((sum, f) => sum + f.failed_sessions, 0),
);

const share = (failure) =>
  totalFailed.value > 0
    ? (failure.failed_sessions / totalFailed.value) * 100 + "%"
    : "0%";
</script>

<template>
  <div class="card failures-card">
    <h2 class="section-title">
      <svg
        width="18"
        height="18"
        viewBox="0 0 24 24"
        fill="none"
        stroke="currentColor"
        stroke-width="2"
        stroke-linecap="round"
        stroke-linejoin="round"
      >
        <path
          d="M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z"
        />
        <line x1="12" y1="9" x2="12" y2="13" />
        <line x1="12" y1="17" x2="12.01" y2="17" />
      </svg>
      Failure Types
    </h2>

    <div v-if="failureTypes.length > 0" class="failure-list">
      <div
        v-for="failure in failureTypes"
        :key="failure.result_type"
        class="failure-item"
      >
        <div class="failure-header">
          <span class="failure-type font-mono">{{ failure.result_type }}</span>
          <span class="failure-count"
            >{{ formatNumber(failure.failed_sessions) }} sessions</span
          >
        </div>
        <div class="failure-bar">
          <div
            class="failure-bar-fill"
            :style="{ width: share(failure) }"
          ></div>
        </div>
        <p v-if="describeResultType(failure.result_type)" class="failure-desc">
          {{ describeResultType(failure.result_type) }}
        </p>
      </div>
    </div>
    <div v-else class="empty-state">
      <p>No failed sessions reported.</p>
    </div>
  </div>
</template>

<style scoped>
/* --- Card --- */
.card {
  background: var(--bg-card);
  border: 1px solid var(--border-subtle);
  border-radius: var(--radius-card);
  padding: 20px;
}

.section-title {
  font-size: 1rem;
  font-weight: 600;
  color: var(--text-main);
  margin: 0 0 20px 0;
  padding-bottom: 12px;
  border-bottom: 1px solid var(--border-subtle);
  display: flex;
  align-items: center;
  gap: 8px;
}

.section-title svg {
  color: var(--text-muted);
}

/* --- Failure List --- */
.failure-list {
  display: flex;
  flex-direction: column;
  gap: 12px;
}

.failure-item {
  padding: 12px 14px;
  background: var(--bg-app);
  border: 1px solid var(--border-subtle);
  border-radius: 8px;
}

.failure-header {
  display: flex;
  justify-content: space-between;
  align-items: baseline;
  gap: 12px;
  margin-bottom: 6px;
}

.failure-type {
  font-weight: 600;
  color: var(--c-danger);
  font-size: 0.8125rem;
  overflow-wrap: anywhere;
}

.failure-count {
  font-size: 0.8125rem;
  color: var(--text-muted);
  white-space: nowrap;
}

.failure-bar {
  height: 6px;
  background: var(--border-subtle);
  border-radius: 3px;
  overflow: hidden;
}

.failure-bar-fill {
  height: 100%;
  background: var(--c-danger);
  transition: width 0.3s;
}

.failure-desc {
  margin: 6px 0 0 0;
  font-size: 0.75rem;
  color: var(--text-muted);
}

/* --- Empty State --- */
.empty-state {
  text-align: center;
  padding: 24px 20px;
  color: var(--text-muted);
}

.empty-state p {
  margin: 0;
  font-size: 0.875rem;
}

/* --- Utilities --- */
.font-mono {
  font-family: var(--font-mono);
}
</style>
