import type { ComponentType } from "react";

interface Props {
  label: string;
  value: string | number;
  icon: ComponentType<{ size?: number; strokeWidth?: number; className?: string }>;
  tone?: "default" | "critical" | "warning" | "safe";
}

const TONE_TEXT: Record<string, string> = {
  default: "text-[var(--color-text)]",
  critical: "text-[var(--color-critical)]",
  warning: "text-[var(--color-warning)]",
  safe: "text-[var(--color-safe)]",
};

const TONE_ICON_BG: Record<string, string> = {
  default: "bg-[var(--color-primary)]/12 text-[var(--color-primary)]",
  critical: "bg-[var(--color-critical-glow)] text-[var(--color-critical)]",
  warning: "bg-[var(--color-warning-glow)] text-[var(--color-warning)]",
  safe: "bg-[var(--color-safe-glow)] text-[var(--color-safe)]",
};

export default function KpiCard({ label, value, icon: Icon, tone = "default" }: Props) {
  return (
    <div className="rounded-xl border border-[var(--color-border)] bg-[var(--color-surface)]/80 backdrop-blur-sm p-4 flex items-start justify-between">
      <div>
        <div className="text-[11px] uppercase tracking-wide text-[var(--color-text-dim)] font-medium">{label}</div>
        <div className={`text-2xl font-bold mt-1.5 ${TONE_TEXT[tone]}`}>{value}</div>
      </div>
      <div className={`w-9 h-9 rounded-lg flex items-center justify-center shrink-0 ${TONE_ICON_BG[tone]}`}>
        <Icon size={17} strokeWidth={2.25} />
      </div>
    </div>
  );
}
