import { NavLink } from "react-router-dom";
import {
  LayoutDashboard, ScanLine, ShieldAlert, Users, Clock, Globe2,
  FileText, ListChecks, Settings as SettingsIcon, ShieldCheck,
} from "lucide-react";

const NAV_ITEMS = [
  { to: "/app/dashboard", label: "Dashboard", icon: LayoutDashboard },
  { to: "/app/analyzer", label: "Log Analyzer", icon: ScanLine },
  { to: "/app/threats", label: "Threats", icon: ShieldAlert },
  { to: "/app/attackers", label: "Attackers", icon: Users },
  { to: "/app/timeline", label: "Timeline", icon: Clock },
  { to: "/app/geo", label: "Geo Map", icon: Globe2 },
  { to: "/app/reports", label: "Reports", icon: FileText },
  { to: "/app/rules", label: "Detection Rules", icon: ListChecks },
  { to: "/app/settings", label: "Settings", icon: SettingsIcon },
];

export default function Sidebar() {
  return (
    <aside className="hidden md:flex w-56 shrink-0 flex-col border-r border-[var(--color-border)] bg-[var(--color-surface)]">
      <div className="flex items-center gap-2 px-4 h-14 border-b border-[var(--color-border)]">
        <div className="w-7 h-7 rounded-lg bg-[var(--color-primary)]/15 border border-[var(--color-primary)]/30 flex items-center justify-center">
          <ShieldCheck size={15} className="text-[var(--color-primary)]" strokeWidth={2.25} />
        </div>
        <span className="font-semibold text-[14px] tracking-tight">LogLens</span>
      </div>

      <nav className="flex-1 overflow-y-auto py-3 px-2.5 space-y-0.5">
        {NAV_ITEMS.map(({ to, label, icon: Icon }) => (
          <NavLink
            key={to}
            to={to}
            className={({ isActive }) =>
              `flex items-center gap-2.5 px-3 py-[7px] rounded-lg text-[13px] transition-colors ${
                isActive
                  ? "bg-[var(--color-primary)]/12 text-[var(--color-primary)] font-medium"
                  : "text-[var(--color-text-dim)] hover:bg-[var(--color-surface-2)] hover:text-[var(--color-text)]"
              }`
            }
          >
            <Icon size={15} strokeWidth={2} />
            {label}
          </NavLink>
        ))}
      </nav>
    </aside>
  );
}
