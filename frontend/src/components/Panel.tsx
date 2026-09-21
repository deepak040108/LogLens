import type { ReactNode } from "react";

export default function Panel({ title, action, children }: { title: string; action?: ReactNode; children: ReactNode }) {
  return (
    <div className="rounded-xl border border-[var(--color-border)] bg-[var(--color-surface)]/80 backdrop-blur-sm p-5">
      <div className="flex items-center justify-between mb-4">
        <h3 className="text-[12.5px] font-semibold uppercase tracking-wide text-[var(--color-text-dim)]">{title}</h3>
        {action}
      </div>
      {children}
    </div>
  );
}
