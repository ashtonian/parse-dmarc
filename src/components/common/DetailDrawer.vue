<script setup>
import { nextTick, onBeforeUnmount, ref, watch } from "vue";

// The slide-in panel a report opens in. The parent renders the body into
// the default slot; the panel handles opening, closing, and the loading and
// empty states.
const props = defineProps({
  isOpen: Boolean,
  loading: {
    type: Boolean,
    default: false,
  },
  // True while there is nothing to show: no header, only the empty text.
  empty: {
    type: Boolean,
    default: true,
  },
  title: {
    type: String,
    default: "",
  },
  subtitle: {
    type: String,
    default: "",
  },
  closeLabel: {
    type: String,
    default: "Close details panel",
  },
  loadingText: {
    type: String,
    default: "Loading report details...",
  },
  emptyText: {
    type: String,
    default: "Select a report to view details",
  },
});

const emit = defineEmits(["close"]);

const panel = ref(null);
let returnFocus = null;

// Escape closes the panel wherever focus is, not only inside it.
const handleKeydown = (e) => {
  if (e.key === "Escape") emit("close");
};

watch(
  () => props.isOpen,
  async (open) => {
    if (open) {
      returnFocus = document.activeElement;
      window.addEventListener("keydown", handleKeydown);
      await nextTick();
      panel.value?.focus();
      return;
    }
    window.removeEventListener("keydown", handleKeydown);
    returnFocus?.focus?.();
    returnFocus = null;
  },
);

onBeforeUnmount(() => {
  window.removeEventListener("keydown", handleKeydown);
});
</script>

<template>
  <Teleport to="body">
    <div class="drawer-root" :class="{ 'is-open': isOpen }">
      <div class="backdrop" @click="emit('close')"></div>

      <div
        ref="panel"
        class="panel"
        role="dialog"
        aria-modal="true"
        :aria-label="title || undefined"
        tabindex="-1"
      >
        <!-- Header -->
        <header class="panel-header" v-if="!empty">
          <div>
            <h2 class="panel-title">{{ title }}</h2>
            <div class="panel-subtitle" v-if="subtitle">{{ subtitle }}</div>
          </div>
          <button
            class="btn-close"
            @click="emit('close')"
            :aria-label="closeLabel"
          >
            <svg
              width="24"
              height="24"
              viewBox="0 0 24 24"
              fill="none"
              stroke="currentColor"
              stroke-width="2"
            >
              <line x1="18" y1="6" x2="6" y2="18"></line>
              <line x1="6" y1="6" x2="18" y2="18"></line>
            </svg>
          </button>
        </header>

        <!-- Loading State -->
        <div v-if="loading" class="panel-loading">
          <div class="spinner"></div>
          <p>{{ loadingText }}</p>
        </div>

        <!-- Body -->
        <div class="panel-body" v-else-if="!empty">
          <slot />
        </div>

        <!-- Empty State -->
        <div v-else class="panel-empty">
          <p>{{ emptyText }}</p>
        </div>
      </div>
    </div>
  </Teleport>
</template>

<style scoped>
/* --- Drawer Mechanism --- */
.drawer-root {
  position: fixed;
  inset: 0;
  z-index: 50;
  pointer-events: none;
  visibility: hidden;
  transition: visibility 0.3s;
}

.drawer-root.is-open {
  pointer-events: auto;
  visibility: visible;
}

.backdrop {
  position: absolute;
  inset: 0;
  background: rgba(15, 23, 42, 0.5);
  backdrop-filter: blur(2px);
  opacity: 0;
  transition: opacity 0.3s;
}

.is-open .backdrop {
  opacity: 1;
}

.panel {
  position: absolute;
  top: 0;
  right: 0;
  bottom: 0;
  width: 100%;
  max-width: 540px;
  background: var(--bg-card);
  border-left: 1px solid var(--border-subtle);
  box-shadow: -4px 0 24px rgba(0, 0, 0, 0.15);
  transform: translateX(100%);
  transition: transform 0.3s cubic-bezier(0.16, 1, 0.3, 1);
  display: flex;
  flex-direction: column;
  overflow: hidden;
}

.panel:focus {
  outline: none;
}

.is-open .panel {
  transform: translateX(0);
}

/* --- Panel Header --- */
.panel-header {
  padding: 20px 24px;
  border-bottom: 1px solid var(--border-subtle);
  display: flex;
  justify-content: space-between;
  align-items: flex-start;
  background: var(--bg-app);
  flex-shrink: 0;
}

.panel-title {
  margin: 0;
  font-size: 1.125rem;
  font-weight: 600;
  color: var(--text-main);
}

.panel-subtitle {
  color: var(--text-muted);
  font-size: 0.875rem;
  font-family: var(--font-mono);
  margin-top: 4px;
}

.btn-close {
  background: none;
  border: none;
  cursor: pointer;
  color: var(--text-muted);
  padding: 4px;
  border-radius: 4px;
  transition: background 0.2s;
  flex-shrink: 0;
}
.btn-close:hover {
  background: var(--border-subtle);
  color: var(--text-main);
}

/* --- Loading State --- */
.panel-loading {
  flex: 1;
  display: flex;
  flex-direction: column;
  align-items: center;
  justify-content: center;
  gap: 16px;
  color: var(--text-muted);
}

.spinner {
  width: 32px;
  height: 32px;
  border: 3px solid var(--border-subtle);
  border-top-color: var(--c-primary);
  border-radius: 50%;
  animation: spin 1s linear infinite;
}

@keyframes spin {
  to {
    transform: rotate(360deg);
  }
}

/* --- Panel Body --- */
.panel-body {
  padding: 20px 24px;
  overflow-y: auto;
  flex: 1;
}

.panel-empty {
  flex: 1;
  display: flex;
  align-items: center;
  justify-content: center;
  color: var(--text-muted);
}

/* --- Responsive --- */
@media (max-width: 600px) {
  .panel {
    max-width: 100%;
  }
}
</style>
