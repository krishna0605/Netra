/**
 * CSV export.
 *
 * Exports exactly the rows on screen, filters included. An export that
 * silently returns everything, or something subtly different from what was
 * being looked at, is worse than none — the operator would have no reason to
 * doubt it.
 */

/** RFC 4180 quoting, plus a guard against spreadsheet formula injection. */
function cell(value: unknown): string {
  const text = value === null || value === undefined ? "" : String(value);

  // A leading =, +, - or @ is executed as a formula by Excel and Sheets when
  // the file is opened. Prefixing with a quote neutralises it without altering
  // what the reader sees.
  const guarded = /^[=+\-@\t\r]/.test(text) ? `'${text}` : text;

  return /[",\n\r]/.test(guarded) ? `"${guarded.replace(/"/g, '""')}"` : guarded;
}

export function toCsv<T>(rows: T[], columns: { header: string; value: (row: T) => unknown }[]): string {
  const head = columns.map((column) => cell(column.header)).join(",");
  const body = rows.map((row) => columns.map((column) => cell(column.value(row))).join(","));
  // CRLF and a BOM so Excel opens UTF-8 correctly on Windows without a prompt.
  return `\uFEFF${[head, ...body].join("\r\n")}\r\n`;
}

export function downloadCsv(filename: string, contents: string) {
  const blob = new Blob([contents], { type: "text/csv;charset=utf-8" });
  const url = URL.createObjectURL(blob);
  const anchor = document.createElement("a");
  anchor.href = url;
  anchor.download = filename;
  document.body.append(anchor);
  anchor.click();
  anchor.remove();
  URL.revokeObjectURL(url);
}

/** "netra-activity-2026-08-12.csv" */
export function stampedName(prefix: string) {
  const now = new Date();
  const date = `${now.getFullYear()}-${String(now.getMonth() + 1).padStart(2, "0")}-${String(now.getDate()).padStart(2, "0")}`;
  return `netra-${prefix}-${date}.csv`;
}
