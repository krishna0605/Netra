import { describe, expect, it } from "vitest";

import { toCsv } from "./csv";

describe("toCsv", () => {
  it("quotes values containing commas, quotes or newlines", () => {
    const csv = toCsv([{ note: 'He said "no", twice' }, { note: "line one\nline two" }], [
      { header: "Note", value: (row) => row.note },
    ]);

    expect(csv).toContain('"He said ""no"", twice"');
    expect(csv).toContain('"line one\nline two"');
  });

  it("neutralises values a spreadsheet would execute as a formula", () => {
    // Excel and Sheets run these on open. An activity log is full of
    // attacker-influenced strings, so an export is a plausible delivery route.
    const csv = toCsv(
      [{ action: "=cmd|'/c calc'!A1" }, { action: "+1+1" }, { action: "-2+3" }, { action: "@SUM(A1)" }],
      [{ header: "Action", value: (row) => row.action }],
    );

    for (const line of csv.trim().split("\r\n").slice(1)) {
      expect(line.startsWith("'") || line.startsWith('"\'')).toBe(true);
    }
  });

  it("leaves ordinary values untouched", () => {
    const csv = toCsv([{ action: "permission:export" }], [{ header: "Action", value: (row) => row.action }]);
    expect(csv).toContain("permission:export");
    expect(csv).not.toContain("'permission:export");
  });

  it("renders empty cells for null and undefined", () => {
    const csv = toCsv([{ a: null, b: undefined }], [
      { header: "A", value: (row) => row.a },
      { header: "B", value: (row) => row.b },
    ]);
    expect(csv.trim().split("\r\n")[1]).toBe(",");
  });
});
