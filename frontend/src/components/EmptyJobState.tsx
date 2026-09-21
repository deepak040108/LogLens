import { useNavigate } from "react-router-dom";
import { ScanLine } from "lucide-react";

export default function EmptyJobState({ message }: { message?: string }) {
  const navigate = useNavigate();
  return (
    <div className="rounded-xl border border-dashed border-[var(--color-border)] p-14 text-center">
      <div className="w-11 h-11 mx-auto rounded-xl bg-[var(--color-primary)]/12 flex items-center justify-center mb-4">
        <ScanLine size={20} className="text-[var(--color-primary)]" strokeWidth={2} />
      </div>
      <p className="text-[13.5px] text-[var(--color-text-dim)] mb-5">
        {message || "No analysis loaded yet. Upload a log file or load the demo to see this page populate."}
      </p>
      <button
        onClick={() => navigate("/app/analyzer")}
        className="px-4 py-2 rounded-lg bg-[var(--color-primary)] text-white text-[13px] font-semibold hover:opacity-90"
      >
        Go to Log Analyzer
      </button>
    </div>
  );
}
