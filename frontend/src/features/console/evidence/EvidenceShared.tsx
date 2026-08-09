import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "../../../components/ui/primitives";
import type { AnalysisStatus } from "../../../lib/types";
import { useNetra } from "../ConsoleCore";

export function analysisStateLabel(state?: AnalysisStatus["state"]) {
  return ({
    "no-evidence": "Waiting for evidence",
    accepted: "Case created",
    uploading: "Uploading",
    finalizing: "Verifying evidence",
    queued: "Queued",
    running: "Analyzing",
    completed: "Analysis complete",
    failed: "Analysis failed",
    canceled: "Analysis canceled",
    expired: "Upload expired",
  } as Record<string, string>)[state ?? "no-evidence"] ?? "Waiting for evidence";
}

export function CaseContextSelector({ value, onChange, label = "Selected case" }: { value: string; onChange: (caseId: string) => void; label?: string }) {
  const { caseRecords } = useNetra();
  return (
    <label className="grid min-w-[17rem] gap-1 text-xs font-bold uppercase tracking-[0.12em] text-muted">
      {label}
      <Select value={value} onValueChange={onChange}>
        <SelectTrigger className="w-full normal-case tracking-normal"><SelectValue placeholder="Select a case" /></SelectTrigger>
        <SelectContent>
          {caseRecords.map((record) => (
            <SelectItem key={record.id} value={record.id}>
              {record.id} · {record.title} · {analysisStateLabel(record.analysisStatus?.state)}
            </SelectItem>
          ))}
        </SelectContent>
      </Select>
    </label>
  );
}
