import { AlertOctagon, AlertTriangle, AlertCircle, Info } from "lucide-react";
import type { Severity } from "../types";

// Accessibility requirement (spec §37): severity must never rely on
// color alone. Every badge pairs a distinct icon + text label with
// the color, so it still reads correctly for colorblind users or
// anyone with a screen reader.
const CONFIG: Record<Severity, { icon: typeof AlertOctagon; className: string; label: string }> = {
  critical: { icon: AlertOctagon, className: "text-[var(--color-critical)] bg-[var(--color-critical-glow)] border-[var(--color-critical)]/30", label: "Critical" },
  high: { icon: AlertTriangle, className: "text-[var(--color-high)] bg-[var(--color-high-glow)] border-[var(--color-high)]/30", label: "High" },
  medium: { icon: AlertCircle, className: "text-[var(--color-warning)] bg-[var(--color-warning-glow)] border-[var(--color-warning)]/30", label: "Medium" },
  low: { icon: Info, className: "text-[var(--color-safe)] bg-[var(--color-safe-glow)] border-[var(--color-safe)]/30", label: "Low" },
};

export default function SeverityBadge({ severity }: { severity: Severity }) {
  const cfg = CONFIG[severity] ?? CONFIG.low;
  const Icon = cfg.icon;
  return (
    <span className={`inline-flex items-center gap-1 px-2 py-0.5 rounded-md border text-[10.5px] font-semibold uppercase tracking-wide ${cfg.className}`}>
      <Icon size={11} strokeWidth={2.5} />
      {cfg.label}
    </span>
  );
}
