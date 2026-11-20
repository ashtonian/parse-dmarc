<script setup>
import { onMounted, onUnmounted, ref } from "vue";
import TlsSummary from "./TlsSummary.vue";
import TlsDomains from "./TlsDomains.vue";
import TlsFailureTypes from "./TlsFailureTypes.vue";
import TlsReports from "./TlsReports.vue";
import TlsReportDrawer from "./TlsReportDrawer.vue";
import {
  getTLSStatistics,
  getTLSReports,
  getTLSReportById,
} from "@/lib/api.js";

// State
const statistics = ref(null);
const reports = ref([]);
const error = ref("");
const loading = ref(true);
const selectedSummary = ref(null);
const selectedReport = ref(null);
const loadingDetail = ref(false);
const detailError = ref("");
const isDrawerOpen = ref(false);

// Auto-refresh interval
let refreshInterval = null;

// Data fetching. Each request keeps its last good result when the other
// fails; the first failure is shown.
const loadData = async () => {
  loading.value = true;
  const [stats, list] = await Promise.allSettled([
    getTLSStatistics(),
    getTLSReports({ limit: 20 }),
  ]);
  if (stats.status === "fulfilled") statistics.value = stats.value;
  if (list.status === "fulfilled") reports.value = list.value;
  const failed = [stats, list].find((r) => r.status === "rejected");
  if (failed) console.error("Failed to fetch TLS-RPT data:", failed.reason);
  error.value = failed ? failed.reason?.message || String(failed.reason) : "";
  loading.value = false;
};

// Report detail handling
const openReportDetails = async (summary) => {
  selectedSummary.value = summary;
  isDrawerOpen.value = true;
  loadingDetail.value = true;
  detailError.value = "";
  try {
    selectedReport.value = await getTLSReportById(summary.id);
  } catch (err) {
    console.error("Failed to fetch TLS report details:", err);
    selectedReport.value = null;
    detailError.value = err?.message || String(err);
  } finally {
    loadingDetail.value = false;
  }
};

// The report is cleared once the panel has slid out, unless another one was
// opened in the meantime.
const closeDrawer = () => {
  isDrawerOpen.value = false;
  setTimeout(() => {
    if (isDrawerOpen.value) return;
    selectedReport.value = null;
    selectedSummary.value = null;
    detailError.value = "";
  }, 300);
};

// Lifecycle
onMounted(() => {
  loadData();
  // Auto-refresh every 5 minutes, as the dashboard does
  refreshInterval = setInterval(loadData, 5 * 60 * 1000);
});

onUnmounted(() => {
  if (refreshInterval) {
    clearInterval(refreshInterval);
  }
});
</script>

<template>
  <div class="tls-view">
    <TlsSummary
      :statistics="statistics"
      :error="error"
      :loading="loading"
      @refresh="loadData"
    />

    <template v-if="statistics?.has_data">
      <section class="section tls-breakdown">
        <TlsDomains :domains="statistics.domains" />
        <TlsFailureTypes :failure-types="statistics.failure_types" />
      </section>

      <section class="section">
        <TlsReports :reports="reports" @view-details="openReportDetails" />
      </section>
    </template>

    <TlsReportDrawer
      :is-open="isDrawerOpen"
      :summary="selectedSummary"
      :report="selectedReport"
      :loading="loadingDetail"
      :error="detailError"
      @close="closeDrawer"
    />
  </div>
</template>

<style scoped>
.section {
  margin-top: 24px;
}

.tls-breakdown {
  display: grid;
  grid-template-columns: 1fr;
  gap: 24px;
  align-items: start;
}

@media (min-width: 1024px) {
  .tls-breakdown {
    grid-template-columns: minmax(0, 2fr) minmax(0, 1fr);
  }
}
</style>
