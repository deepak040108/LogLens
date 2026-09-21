import { FileJson, FileSpreadsheet, FileText } from "lucide-react";
import { useJob } from "../context/JobContext";
import { reportUrl } from "../lib/api";
import EmptyJobState from "../components/EmptyJobState";
import Panel from "../components/Panel";

export default function Reports() {
  const { job, isDone } = useJob();

  if (!isDone || !job?.summary) {
    return (
      <div>
        <h1 className="text-xl font-bold mb-5">Reports</h1>
        <EmptyJobState />
      </div>
    );
  }

  const s = job.summary;

  return (
    <div className="max-w-3xl">
      <h1 className="text-xl font-bold mb-1">Reports</h1>
      <p className="text-[13px] text-[var(--color-text-dim)] mb-6">Export the current analysis as a downloadable report.</p>

      <div className="grid sm:grid-cols-3 gap-3 mb-6">
        <a
          href={reportUrl(job.job_id, "json")}
          download
          className="rounded-xl border border-[var(--color-border)] bg-[var(--color-surface)]/80 p-5 hover:border-[var(--color-primary)]/40 transition-colors"
        >
          <FileJson size={20} className="text-[var(--color-primary)] mb-3" strokeWidth={2} />
          <div className="font-medium text-[13.5px] mb-1">JSON Report</div>
          <div className="text-[11.5px] text-[var(--color-text-dim)]">Full structured data</div>
        </a>
        <a
          href={reportUrl(job.job_id, "csv")}
          download
          className="rounded-xl border border-[var(--color-border)] bg-[var(--color-surface)]/80 p-5 hover:border-[var(--color-primary)]/40 transition-colors"
        >
          <FileSpreadsheet size={20} className="text-[var(--color-safe)] mb-3" strokeWidth={2} />
          <div className="font-medium text-[13.5px] mb-1">CSV Report</div>
          <div className="text-[11.5px] text-[var(--color-text-dim)]">Top attackers, spreadsheet-ready</div>
        </a>
        <a
          href={reportUrl(job.job_id, "pdf")}
          download
          className="rounded-xl border border-[var(--color-border)] bg-[var(--color-surface)]/80 p-5 hover:border-[var(--color-primary)]/40 transition-colors"
        >
          <FileText size={20} className="text-[var(--color-warning)] mb-3" strokeWidth={2} />
          <div className="font-medium text-[13.5px] mb-1">PDF Report</div>
          <div className="text-[11.5px] text-[var(--color-text-dim)]">Printable security report</div>
        </a>
      </div>

      <Panel title="Report Preview">
        <dl className="space-y-3 text-[13px]">
          <div className="flex justify-between">
            <dt className="text-[var(--color-text-dim)]">File</dt>
            <dd className="font-mono">{job.job_id.slice(0, 8)}</dd>
          </div>
          <div className="flex justify-between">
            <dt className="text-[var(--color-text-dim)]">Total Requests</dt>
            <dd className="font-mono">{s.totalRequests.toLocaleString()}</dd>
          </div>
          <div className="flex justify-between">
            <dt className="text-[var(--color-text-dim)]">Malformed Requests</dt>
            <dd className="font-mono">{s.malformedLines.toLocaleString()}</dd>
          </div>
          <div className="flex justify-between">
            <dt className="text-[var(--color-text-dim)]">Total Attacks</dt>
            <dd className="font-mono">{s.totalAttacks.toLocaleString()}</dd>
          </div>
          <div className="flex justify-between">
            <dt className="text-[var(--color-text-dim)]">Unique Attackers</dt>
            <dd className="font-mono">{s.uniqueAttackerIps}</dd>
          </div>
          <div className="flex justify-between">
            <dt className="text-[var(--color-text-dim)]">Attack Types</dt>
            <dd className="font-mono">{s.byType.length}</dd>
          </div>
        </dl>
      </Panel>
    </div>
  );
}
