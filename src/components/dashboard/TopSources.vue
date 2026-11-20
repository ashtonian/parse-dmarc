<script setup>
import { formatNumber } from "@/lib/format.js";

defineProps({
  sources: {
    type: Array,
    default: () => [],
  },
});

// The sender the backend attributed the address to, else its
// forward-confirmed reverse DNS name. An unverified PTR is whatever the
// address owner set, so it never names the sender.
const senderName = (source) =>
  source.name || (source.reverse_dns_verified ? source.reverse_dns : "");

const asLabel = (source) =>
  source.as_name ? `AS${source.asn} ${source.as_name}` : `AS${source.asn}`;

const share = (part, source) =>
  source.count > 0 ? (part / source.count) * 100 + "%" : "0%";

const UNALIGNED_HINT =
  "SPF or DKIM passed for another domain: a service sending without alignment, or a forwarder";
const UNAUTHENTICATED_HINT = "Neither SPF nor DKIM passed";
</script>

<template>
  <div class="card sources-card">
    <h2 class="section-title">
      <svg
        width="18"
        height="18"
        viewBox="0 0 24 24"
        fill="none"
        stroke="currentColor"
        stroke-width="2"
      >
        <rect x="2" y="2" width="20" height="8" rx="2" ry="2" />
        <rect x="2" y="14" width="20" height="8" rx="2" ry="2" />
        <line x1="6" y1="6" x2="6.01" y2="6" />
        <line x1="6" y1="18" x2="6.01" y2="18" />
      </svg>
      Top Sending Sources
    </h2>

    <div class="source-list" v-if="sources?.length > 0">
      <div
        v-for="source in sources"
        :key="source.source_ip"
        class="source-item"
      >
        <div class="source-id">
          <div class="source-name">
            <template v-if="senderName(source)">
              <span class="source-label">{{ senderName(source) }}</span>
              <span class="source-ip font-mono">{{ source.source_ip }}</span>
            </template>
            <span v-else class="source-label font-mono">{{
              source.source_ip
            }}</span>
            <span v-if="source.type" class="source-type">{{
              source.type
            }}</span>
          </div>
          <div
            class="source-meta"
            v-if="source.reverse_dns || source.country || source.asn"
          >
            <span
              v-if="source.reverse_dns"
              class="source-ptr"
              :class="{ verified: source.reverse_dns_verified }"
              :title="
                source.reverse_dns_verified
                  ? 'Reverse DNS name that resolves back to this address'
                  : 'Reverse DNS name that does not resolve back to this address'
              "
            >
              <svg
                v-if="source.reverse_dns_verified"
                width="12"
                height="12"
                viewBox="0 0 24 24"
                fill="none"
                stroke="currentColor"
                stroke-width="3"
                stroke-linecap="round"
                stroke-linejoin="round"
                role="img"
                aria-label="Verified"
              >
                <polyline points="20 6 9 17 4 12" />
              </svg>
              <span class="font-mono">{{ source.reverse_dns }}</span>
              <span v-if="!source.reverse_dns_verified" class="ptr-unverified"
                >unverified</span
              >
            </span>
            <span v-if="source.country" title="Country">{{
              source.country
            }}</span>
            <span v-if="source.asn" title="Autonomous system">{{
              asLabel(source)
            }}</span>
          </div>
        </div>
        <div class="source-stats">
          <div class="source-count">
            {{ formatNumber(source.count) }} messages
          </div>
          <div class="source-bar">
            <div
              class="source-bar-pass"
              :style="{ width: share(source.pass, source) }"
            ></div>
            <div
              class="source-bar-unaligned"
              :style="{ width: share(source.unaligned, source) }"
            ></div>
            <div
              class="source-bar-unauthenticated"
              :style="{ width: share(source.unauthenticated, source) }"
            ></div>
          </div>
          <div class="source-legend">
            <span class="legend-pass"
              >{{ formatNumber(source.pass) }} pass</span
            >
            <span class="legend-unaligned" :title="UNALIGNED_HINT"
              >{{ formatNumber(source.unaligned) }} unaligned</span
            >
            <span class="legend-unauthenticated" :title="UNAUTHENTICATED_HINT"
              >{{ formatNumber(source.unauthenticated) }} unauthenticated</span
            >
          </div>
        </div>
      </div>
    </div>
    <div v-else class="empty-state">
      <svg
        width="40"
        height="40"
        viewBox="0 0 24 24"
        fill="none"
        stroke="currentColor"
        stroke-width="1.5"
      >
        <circle cx="12" cy="12" r="10" />
        <line x1="12" y1="8" x2="12" y2="12" />
        <line x1="12" y1="16" x2="12.01" y2="16" />
      </svg>
      <p>No data available yet. Reports will appear here once fetched.</p>
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
  margin: 0 0 16px 0;
  display: flex;
  align-items: center;
  gap: 8px;
}

.section-title svg {
  color: var(--text-muted);
}

.sources-card .section-title {
  margin-bottom: 20px;
  padding-bottom: 12px;
  border-bottom: 1px solid var(--border-subtle);
}

/* --- Source List --- */
.source-list {
  display: flex;
  flex-direction: column;
  gap: 12px;
}

.source-item {
  padding: 14px 16px;
  background: var(--bg-app);
  border-radius: 8px;
  display: flex;
  justify-content: space-between;
  align-items: center;
  gap: 16px;
  border: 1px solid var(--border-subtle);
}

.source-id {
  flex: 0 1 360px;
  min-width: 0;
}

.source-name {
  display: flex;
  align-items: baseline;
  flex-wrap: wrap;
  gap: 4px 8px;
}

.source-label {
  font-weight: 600;
  color: var(--text-main);
  font-size: 0.875rem;
  overflow-wrap: anywhere;
}

.source-ip {
  color: var(--text-muted);
  font-size: 0.8125rem;
}

.source-type {
  font-size: 0.7rem;
  font-weight: 600;
  padding: 1px 6px;
  border-radius: 4px;
  background: var(--bg-card);
  border: 1px solid var(--border-subtle);
  color: var(--text-muted);
}

.source-meta {
  display: flex;
  flex-wrap: wrap;
  gap: 2px 12px;
  margin-top: 4px;
  font-size: 0.75rem;
  color: var(--text-muted);
}

.source-ptr {
  display: inline-flex;
  align-items: center;
  gap: 4px;
  overflow-wrap: anywhere;
}

.source-ptr.verified svg {
  color: var(--c-success);
  flex-shrink: 0;
}

.ptr-unverified {
  font-size: 0.65rem;
  font-weight: 600;
  text-transform: uppercase;
  padding: 0 4px;
  border-radius: 4px;
  background: var(--border-subtle);
}

.source-stats {
  flex: 1;
}

.source-count {
  font-size: 0.8125rem;
  color: var(--text-muted);
  margin-bottom: 6px;
}

.source-bar {
  height: 6px;
  background: var(--border-subtle);
  border-radius: 3px;
  overflow: hidden;
  display: flex;
  margin-bottom: 6px;
}

.source-bar-pass {
  background: var(--c-success);
  transition: width 0.3s;
}

.source-bar-unaligned {
  background: var(--c-warning);
  transition: width 0.3s;
}

.source-bar-unauthenticated {
  background: var(--c-danger);
  transition: width 0.3s;
}

.source-legend {
  display: flex;
  flex-wrap: wrap;
  gap: 4px 12px;
  font-size: 0.75rem;
}

.legend-pass {
  color: var(--c-success);
  font-weight: 500;
}

.legend-unaligned {
  color: var(--c-warning);
  font-weight: 500;
  cursor: help;
}

.legend-unauthenticated {
  color: var(--c-danger);
  font-weight: 500;
  cursor: help;
}

/* --- Empty State --- */
.empty-state {
  text-align: center;
  padding: 40px 20px;
  color: var(--text-muted);
  display: flex;
  flex-direction: column;
  align-items: center;
  gap: 12px;
}

.empty-state svg {
  opacity: 0.3;
}

.empty-state p {
  margin: 0;
  font-size: 0.875rem;
}

/* --- Utilities --- */
.font-mono {
  font-family: var(--font-mono);
}

/* --- Responsive --- */
@media (max-width: 768px) {
  .source-item {
    flex-direction: column;
    align-items: flex-start;
  }

  .source-id {
    flex-basis: auto;
    width: 100%;
    margin-bottom: 8px;
  }

  .source-stats {
    width: 100%;
  }
}
</style>
