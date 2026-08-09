import { describe, expect, it } from "vitest";

import consoleSource from "./NetraConsole.tsx?raw";
import applicationSource from "./ConsoleApplication.tsx?raw";
import coreSource from "./ConsoleCore.tsx?raw";
import providerSource from "./ConsoleProvider.tsx?raw";
import shellSource from "./ConsoleShell.tsx?raw";
import trafficSource from "./analysis/TrafficPages.tsx?raw";
import findingsSource from "./analysis/FindingPages.tsx?raw";
import casesSource from "./cases/CasePages.tsx?raw";
import evidenceSource from "./evidence/EvidencePages.tsx?raw";
import integrationSource from "./integrations/IntegrationPages.tsx?raw";
import operationsSource from "./operations/OperationsPages.tsx?raw";
import evidenceReportSource from "./reports/EvidenceReportPages.tsx?raw";
import reportSource from "./reports/ReportPages.tsx?raw";

describe("console module boundary", () => {
  it("keeps the public console entry composition-only", () => {
    expect(consoleSource.split(/\r?\n/).length).toBeLessThan(40);
    expect(consoleSource).not.toContain("fetch(");
    expect(consoleSource).not.toContain("createContext(");
    expect(applicationSource.split(/\r?\n/).length).toBeLessThan(10);
  });

  it("keeps feature-owned console modules within the reviewed boundary", () => {
    const modules = [
      coreSource, providerSource, shellSource, trafficSource, findingsSource, casesSource,
      evidenceSource, integrationSource, operationsSource, evidenceReportSource, reportSource,
    ];
    for (const source of modules) {
      expect(source.split(/\r?\n/).filter((line) => line.trim()).length).toBeLessThanOrEqual(600);
    }
    expect(shellSource).not.toContain("fetch(");
  });
});
