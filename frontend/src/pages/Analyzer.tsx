import { useNavigate } from "react-router-dom";
import { CheckCircle2, ArrowRight } from "lucide-react";
import { useJob } from "../context/JobContext";
import UploadZone from "../components/UploadZone";
import ProcessingPanel from "../components/ProcessingPanel";

export default function Analyzer() {
  const { job, error, isBusy, isDone, reset } = useJob();
  const navigate = useNavigate();

  return (
    <div className="max-w-3xl mx-auto">
      <h1 className="text-xl font-bold mb-1">Log Analyzer</h1>
      <p className="text-[13px] text-[var(--color-text-dim)] mb-6">
        Upload an Apache or Nginx access log, or load the bundled demo log to see LogLens process real attack traffic.
      </p>

      {error && (
        <div className="mb-5 rounded-lg border border-[var(--color-critical)]/40 bg-[var(--color-critical-glow)] text-[var(--color-critical)] text-[13px] px-4 py-3">
          {error}
        </div>
      )}

      {!job && <UploadZone />}

      {isBusy && <ProcessingPanel />}

      {job && job.status === "failed" && (
        <div className="rounded-xl border border-[var(--color-critical)]/40 bg-[var(--color-critical-glow)] p-6 text-center">
          <div className="text-[var(--color-critical)] font-semibold mb-1">Analysis failed</div>
          <p className="text-[13px] text-[var(--color-text-dim)] mb-4">The server could not process this file.</p>
          <button
            onClick={reset}
            className="px-4 py-2 rounded-lg bg-[var(--color-primary)] text-white text-[13px] font-semibold"
          >
            Try Again
          </button>
        </div>
      )}

      {isDone && job?.summary && (
        <div className="rounded-xl border border-[var(--color-safe)]/30 bg-[var(--color-safe-glow)] p-6 text-center">
          <CheckCircle2 size={28} className="text-[var(--color-safe)] mx-auto mb-2" strokeWidth={2} />
          <div className="font-semibold mb-1">Analysis complete</div>
          <p className="text-[13px] text-[var(--color-text-dim)] mb-5">
            {job.summary.totalRequests.toLocaleString()} requests parsed · {job.summary.totalAttacks.toLocaleString()} attacks detected
          </p>
          <div className="flex justify-center gap-3">
            <button
              onClick={() => navigate("/app/dashboard")}
              className="px-5 py-2.5 rounded-lg bg-[var(--color-primary)] text-white text-[13px] font-semibold flex items-center gap-2 hover:opacity-90"
            >
              View Dashboard <ArrowRight size={14} strokeWidth={2.5} />
            </button>
            <button
              onClick={reset}
              className="px-5 py-2.5 rounded-lg border border-[var(--color-border)] text-[13px] font-medium hover:bg-[var(--color-surface-2)]"
            >
              Analyze Another File
            </button>
          </div>
        </div>
      )}
    </div>
  );
}
