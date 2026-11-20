const numberFormat = new Intl.NumberFormat("en-US");

const dateFormat = new Intl.DateTimeFormat("en-US", {
  month: "short",
  day: "numeric",
  hour: "2-digit",
  minute: "2-digit",
});

const dateFormatWithYear = new Intl.DateTimeFormat("en-US", {
  year: "numeric",
  month: "short",
  day: "numeric",
  hour: "2-digit",
  minute: "2-digit",
});

const relativeFormat = new Intl.RelativeTimeFormat("en-US", {
  numeric: "auto",
});

// Largest first: a timestamp is shown in the largest unit it spans.
const RELATIVE_UNITS = [
  ["year", 365 * 24 * 60 * 60],
  ["month", 30 * 24 * 60 * 60],
  ["week", 7 * 24 * 60 * 60],
  ["day", 24 * 60 * 60],
  ["hour", 60 * 60],
  ["minute", 60],
];

/**
 * A count with thousands separators, e.g. 12,450
 * @param {number} n
 */
export function formatNumber(n) {
  return numberFormat.format(n ?? 0);
}

/**
 * A unix timestamp in seconds as a date and time, e.g. "Nov 18, 09:00 AM"
 * @param {number} seconds
 * @param {Object} options
 * @param {boolean} options.withYear - Include the year
 */
export function formatDate(seconds, { withYear = false } = {}) {
  if (!seconds) return "N/A";
  const date = new Date(seconds * 1000);
  return (withYear ? dateFormatWithYear : dateFormat).format(date);
}

/**
 * A unix timestamp in seconds relative to now, e.g. "3 days ago"
 * @param {number} seconds
 * @param {number} now - Milliseconds since the epoch
 */
export function formatRelative(seconds, now = Date.now()) {
  const diff = seconds - now / 1000;
  for (const [unit, size] of RELATIVE_UNITS) {
    if (Math.abs(diff) >= size) {
      return relativeFormat.format(Math.round(diff / size), unit);
    }
  }
  return relativeFormat.format(Math.round(diff), "second");
}

/**
 * A percentage with one decimal, e.g. "98.5%", or "N/A" for null
 * @param {number|null} rate
 */
export function formatRate(rate) {
  return rate == null ? "N/A" : `${rate.toFixed(1)}%`;
}
