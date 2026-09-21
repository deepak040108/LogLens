import { FileStack, ShieldAlert, Users, AlertOctagon, KeyRound, Activity } from "lucide-react";
import { useJob } from "../context/JobContext";
import EmptyJobState from "../components/EmptyJobState";
import KpiCard from "../components/KpiCard";
import Panel from "../components/Panel";
import AttackTimelineChart from "../components/AttackTimelineChart";
import AttackDistributionChart from "../components/AttackDistributionChart";
import SeverityDistribution from "../components/SeverityDistribution";
import SeverityBadge from "../components/SeverityBadge";

export default function Dashboard() {
  const { job, isDone } = useJob();

  if (!isDone || !job?.summary) {
    return (
      <div>
        <h1 className="text-xl font-bold mb-5">Dashboard</h1>
        <EmptyJobState />
      </div>
    );
  }

  const s = job.summary;
  const highCritical = s.severityBreakdown
    .filter((b) => b.severity === "high" || b.severity === "critical")
    .reduce((sum, b) => sum + b.count, 0);
  const bruteForceCount = s.byType.find((t) => t.attack_type === "brute_force")?.count ?? 0;
  const criticalCount = s.severityBreakdown.find((b) => b.severity === "critical")?.count ?? 0;

  return (
    <div className="space-y-5">
      <div className="flex items-center justify-between">
        <h1 className="text-xl font-bold">Dashboard</h1>
        <div className="flex items-center gap-1.5 text-[11.5px] text-[var(--color-text-faint)]">
          <Activity size={12} className="text-[var(--color-safe)]" />
          <span>Live analysis</span>
        </div>
      </div>

      <div className="grid grid-cols-2 lg:grid-cols-5 gap-3">
        <KpiCard label="Total Requests" value={s.totalRequests.toLocaleString()} icon={FileStack} />
        <KpiCard label="Attacks Detected" value={s.totalAttacks.toLocaleString()} icon={ShieldAlert} tone="critical" />
        <KpiCard label="Unique Attackers" value={s.uniqueAttackerIps} icon={Users} tone="warning" />
        <KpiCard label="High/Critical" value={highCritical} icon={AlertOctagon} tone="critical" />
        <KpiCard label="Brute Force" value={bruteForceCount} icon={KeyRound} tone="warning" />
      </div>

      {criticalCount > 0 && (
        <div className="rounded-xl border border-[var(--color-critical)]/25 bg-[var(--color-critical-glow)] px-4 py-3">
          <div className="flex items-center gap-2">
            <AlertOctagon size={15} className="text-[var(--color-critical)]" />
            <span className="text-[13px] font-semibold text-[var(--color-critical)]">
              {criticalCount} critical threat{criticalCount !== 1 ? "s" : ""} detected
            </span>
            <span className="text-[12px] text-[var(--color-text-dim)]">
              — review findings immediately
            </span>
          </div>
        </div>
      )}

      <Panel title="Attacks per Hour">
        <AttackTimelineChart timeline={s.timeline} />
      </Panel>

      <div className="grid lg:grid-cols-2 gap-5">
        <Panel title="Attack Distribution">
          <AttackDistributionChart byType={s.byType} />
        </Panel>
        <Panel title="Severity Distribution">
          <SeverityDistribution breakdown={s.severityBreakdown} />
        </Panel>
      </div>

      <div className="grid lg:grid-cols-2 gap-5">
        <Panel title="Top Threats">
          {s.topAttackers.length === 0 ? (
            <div className="text-[12.5px] text-[var(--color-text-faint)] text-center py-8">No threats detected.</div>
          ) : (
            <div className="overflow-x-auto">
              <table className="w-full text-[12.5px]">
                <thead>
                  <tr className="text-left text-[var(--color-text-faint)] text-[10.5px] uppercase tracking-wide border-b border-[var(--color-border)]">
                    <th className="pb-2 pr-3">IP Address</th>
                    <th className="pb-2 pr-3">Attacks</th>
                    <th className="pb-2 pr-3">Top Attack</th>
                    <th className="pb-2 pr-3">Severity</th>
                    <th className="pb-2">Country</th>
                  </tr>
                </thead>
                <tbody>
                  {s.topAttackers.slice(0, 6).map((a) => (
                    <tr key={a.ip} className="border-b border-[var(--color-border-soft)] last:border-none hover:bg-[var(--color-surface-2)]">
                      <td className="py-2.5 pr-3 font-mono font-medium">{a.ip}</td>
                      <td className="py-2.5 pr-3">{a.count}</td>
                      <td className="py-2.5 pr-3 text-[var(--color-text-dim)] capitalize">{a.topAttack?.replace(/_/g, " ")}</td>
                      <td className="py-2.5 pr-3"><SeverityBadge severity={a.severity} /></td>
                      <td className="py-2.5 text-[var(--color-text-dim)]">{a.country}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </Panel>

        <Panel title="Recent Findings">
          {s.recentFindings.length === 0 ? (
            <div className="text-[12.5px] text-[var(--color-text-faint)] text-center py-8">Nothing flagged.</div>
          ) : (
            <div className="space-y-2 max-h-[280px] overflow-y-auto pr-1">
              {s.recentFindings.slice(0, 8).map((f, i) => (
                <div key={i} className="flex items-start justify-between gap-3 pb-2 border-b border-[var(--color-border-soft)] last:border-none">
                  <div className="min-w-0">
                    <div className="flex items-center gap-2 mb-0.5">
                      <SeverityBadge severity={f.severity} />
                      <span className="text-[11.5px] font-mono text-[var(--color-text-dim)]">{f.ip}</span>
                    </div>
                    <div className="text-[11.5px] font-mono text-[var(--color-text-faint)] truncate">
                      {f.method} {f.path}
                    </div>
                  </div>
                  <span className="text-[10.5px] font-mono text-[var(--color-text-faint)] shrink-0">{f.timestamp?.slice(11, 19)}</span>
                </div>
              ))}
            </div>
          )}
        </Panel>
      </div>
    </div>
  );
}
