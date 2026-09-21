import { useJob } from "../context/JobContext";
import { Circle } from "lucide-react";

function StatusPill() {
  const { job, isBusy, isDone } = useJob();
  if (!job) {
    return (
      <span className="flex items-center gap-1.5 text-[12px] text-[var(--color-text-faint)]">
        <Circle size={7} fill="currentColor" strokeWidth={0} />
        no file loaded
      </span>
    );
  }
  if (isBusy) {
    return (
      <span className="flex items-center gap-1.5 text-[12px] text-[var(--color-warning)]">
        <Circle size={7} fill="currentColor" strokeWidth={0} className="animate-pulse" />
        processing — {job.progress.toFixed(0)}%
      </span>
    );
  }
  if (job.status === "failed") {
    return (
      <span className="flex items-center gap-1.5 text-[12px] text-[var(--color-critical)]">
        <Circle size={7} fill="currentColor" strokeWidth={0} />
        analysis failed
      </span>
    );
  }
  if (isDone) {
    return (
      <span className="flex items-center gap-1.5 text-[12px] text-[var(--color-safe)]">
        <Circle size={7} fill="currentColor" strokeWidth={0} />
        analysis complete
      </span>
    );
  }
  return null;
}

export default function Topbar() {
  const { job } = useJob();
  return (
    <header className="h-16 shrink-0 border-b border-[var(--color-border)] bg-[var(--color-surface)]/60 backdrop-blur flex items-center justify-between px-6">
      <div>
        <div className="text-[13px] font-medium text-[var(--color-text)]">
          {job ? job.job_id.slice(0, 8) + " — " + (job.status === "processing" ? "Analyzing…" : job.status) : "No analysis loaded"}
        </div>
        <StatusPill />
      </div>
    </header>
  );
}
