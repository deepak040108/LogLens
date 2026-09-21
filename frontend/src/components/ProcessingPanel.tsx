import { Check, Loader2 } from "lucide-react";
import { useJob } from "../context/JobContext";

// Real, backend-driven progress -- percent, processed/total lines all
// come from job.progress / job.processed_lines / job.total_lines,
// never a fixed/fake animation (spec §14).
export default function ProcessingPanel() {
  const { job } = useJob();
  if (!job) return null;

  const stages = [
    { key: "parsing", label: "Parsing", done: job.processed_lines > 0 },
    { key: "detection", label: "Detection", done: job.status === "completed" || job.processed_lines > 0 },
    { key: "aggregation", label: "Aggregation", done: job.status === "completed" },
    { key: "geoip", label: "GeoIP", done: job.status === "completed" },
  ];

  return (
    <div className="rounded-xl border border-[var(--color-border)] bg-[var(--color-surface)]/80 p-5">
      <div className="flex items-center justify-between text-[13px] mb-3">
        <span className="font-medium">Analyzing {job.job_id.slice(0, 8)}…</span>
        <span className="text-[var(--color-text-dim)] font-mono">
          {job.processed_lines.toLocaleString()} / {job.total_lines.toLocaleString()} lines
        </span>
      </div>
      <div className="h-1.5 rounded-full bg-[var(--color-surface-2)] overflow-hidden mb-4">
        <div
          className="h-full bg-[var(--color-primary)] transition-all duration-300"
          style={{ width: `${Math.min(job.progress, 100)}%` }}
        />
      </div>
      <div className="text-right text-[12px] font-mono text-[var(--color-primary)] mb-4">{job.progress.toFixed(1)}%</div>

      <div className="grid grid-cols-2 sm:grid-cols-4 gap-2">
        {stages.map((s) => (
          <div
            key={s.key}
            className={`flex items-center gap-2 px-3 py-2 rounded-lg text-[12px] border ${
              s.done
                ? "border-[var(--color-safe)]/30 bg-[var(--color-safe-glow)] text-[var(--color-safe)]"
                : "border-[var(--color-border)] text-[var(--color-text-dim)]"
            }`}
          >
            {s.done ? <Check size={13} strokeWidth={2.5} /> : <Loader2 size={13} className="animate-spin" strokeWidth={2.5} />}
            {s.label}
          </div>
        ))}
      </div>

      {job.malformed_lines > 0 && (
        <div className="text-[11.5px] text-[var(--color-text-faint)] mt-3">
          {job.malformed_lines.toLocaleString()} malformed line(s) skipped so far — never fatal to the rest of the file.
        </div>
      )}
    </div>
  );
}
