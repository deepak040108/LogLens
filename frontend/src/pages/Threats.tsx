import { useEffect, useMemo, useState } from "react";
import { useJob } from "../context/JobContext";
import { getThreats } from "../lib/api";
import type { ThreatEvent } from "../types";
import EmptyJobState from "../components/EmptyJobState";
import SeverityBadge from "../components/SeverityBadge";
import ThreatDetailModal from "../components/ThreatDetailModal";

export default function Threats() {
  const { job, isDone } = useJob();
  const [events, setEvents] = useState<ThreatEvent[]>([]);
  const [severity, setSeverity] = useState("");
  const [attackType, setAttackType] = useState("");
  const [ipFilter, setIpFilter] = useState("");
  const [selected, setSelected] = useState<ThreatEvent | null>(null);
  const [loading, setLoading] = useState(false);

  useEffect(() => {
    if (!job || job.status !== "completed") return;
    setLoading(true);
    getThreats(job.job_id, {
      severity: severity || undefined,
      attack_type: attackType || undefined,
      ip: ipFilter || undefined,
    })
      .then((r) => setEvents(r.events))
      .finally(() => setLoading(false));
  }, [job, severity, attackType, ipFilter]);

  const attackTypes = useMemo(() => {
    if (!job?.summary) return [];
    return job.summary.byType.map((t) => t.attack_type);
  }, [job]);

  const countryFor = (ip: string) => job?.summary?.topAttackers.find((a) => a.ip === ip)?.country;

  if (!isDone || !job?.summary) {
    return (
      <div>
        <h1 className="text-xl font-bold mb-5">Threats</h1>
        <EmptyJobState />
      </div>
    );
  }

  return (
    <div>
      <h1 className="text-xl font-bold mb-1">Threats</h1>
      <p className="text-[13px] text-[var(--color-text-dim)] mb-5">
        {events.length} event{events.length !== 1 ? "s" : ""} matching current filters
      </p>

      <div className="flex flex-wrap gap-2 mb-5">
        <select
          value={severity}
          onChange={(e) => setSeverity(e.target.value)}
          className="bg-[var(--color-surface)] border border-[var(--color-border)] rounded-lg px-3 py-2 text-[12.5px]"
        >
          <option value="">All severities</option>
          <option value="critical">Critical</option>
          <option value="high">High</option>
          <option value="medium">Medium</option>
          <option value="low">Low</option>
        </select>
        <select
          value={attackType}
          onChange={(e) => setAttackType(e.target.value)}
          className="bg-[var(--color-surface)] border border-[var(--color-border)] rounded-lg px-3 py-2 text-[12.5px]"
        >
          <option value="">All attack types</option>
          {attackTypes.map((t) => (
            <option key={t} value={t}>
              {t.replace(/_/g, " ")}
            </option>
          ))}
        </select>
        <input
          value={ipFilter}
          onChange={(e) => setIpFilter(e.target.value)}
          placeholder="Filter by IP…"
          className="bg-[var(--color-surface)] border border-[var(--color-border)] rounded-lg px-3 py-2 text-[12.5px] font-mono w-40"
        />
      </div>

      <div className="rounded-xl border border-[var(--color-border)] bg-[var(--color-surface)] overflow-hidden">
        <div className="overflow-x-auto">
          <table className="w-full text-[12.5px]">
            <thead>
              <tr className="text-left text-[var(--color-text-faint)] text-[10.5px] uppercase tracking-wide border-b border-[var(--color-border)]">
                <th className="px-4 py-3">Severity</th>
                <th className="px-4 py-3">Attack Type</th>
                <th className="px-4 py-3">IP</th>
                <th className="px-4 py-3">Request</th>
                <th className="px-4 py-3">Status</th>
                <th className="px-4 py-3">Timestamp</th>
              </tr>
            </thead>
            <tbody>
              {loading && (
                <tr>
                  <td colSpan={6} className="px-4 py-8 text-center text-[var(--color-text-faint)]">
                    Loading…
                  </td>
                </tr>
              )}
              {!loading && events.length === 0 && (
                <tr>
                  <td colSpan={6} className="px-4 py-8 text-center text-[var(--color-text-faint)]">
                    No events match these filters.
                  </td>
                </tr>
              )}
              {!loading &&
                events.map((e, i) => (
                  <tr
                    key={i}
                    onClick={() => setSelected(e)}
                    className="border-b border-[var(--color-border-soft)] last:border-none hover:bg-[var(--color-surface-2)] cursor-pointer"
                  >
                    <td className="px-4 py-2.5">
                      <SeverityBadge severity={e.severity} />
                    </td>
                    <td className="px-4 py-2.5 capitalize">{e.attack_type.replace(/_/g, " ")}</td>
                    <td className="px-4 py-2.5 font-mono">{e.ip}</td>
                    <td className="px-4 py-2.5 font-mono text-[var(--color-text-dim)] max-w-xs truncate">
                      {e.method} {e.path}
                    </td>
                    <td className="px-4 py-2.5 font-mono">{e.status}</td>
                    <td className="px-4 py-2.5 font-mono text-[var(--color-text-faint)]">{e.timestamp?.slice(11, 19)}</td>
                  </tr>
                ))}
            </tbody>
          </table>
        </div>
      </div>

      {selected && <ThreatDetailModal event={selected} country={countryFor(selected.ip)} onClose={() => setSelected(null)} />}
    </div>
  );
}
