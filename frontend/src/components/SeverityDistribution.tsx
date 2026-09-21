import type { SeverityBreakdownEntry } from "../types";
import SeverityBadge from "./SeverityBadge";

const BAR_COLOR: Record<string, string> = {
  critical: "bg-[var(--color-critical)]",
  high: "bg-[var(--color-high)]",
  medium: "bg-[var(--color-warning)]",
  low: "bg-[var(--color-safe)]",
};

export default function SeverityDistribution({ breakdown }: { breakdown: SeverityBreakdownEntry[] }) {
  if (breakdown.length === 0) {
    return <div className="text-[12.5px] text-[var(--color-text-faint)] text-center py-8">No findings yet.</div>;
  }
  return (
    <div className="space-y-3">
      {breakdown.map((b) => (
        <div key={b.severity}>
          <div className="flex items-center justify-between mb-1.5">
            <SeverityBadge severity={b.severity} />
            <span className="text-[12px] font-mono text-[var(--color-text-dim)]">
              {b.count} · {b.percentage}%
            </span>
          </div>
          <div className="h-1.5 rounded-full bg-[var(--color-surface-2)] overflow-hidden">
            <div className={`h-full ${BAR_COLOR[b.severity] ?? "bg-[var(--color-primary)]"}`} style={{ width: `${b.percentage}%` }} />
          </div>
        </div>
      ))}
    </div>
  );
}
