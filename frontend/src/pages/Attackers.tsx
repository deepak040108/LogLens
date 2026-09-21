import { useMemo, useState } from "react";
import { useNavigate } from "react-router-dom";
import { ArrowUpDown } from "lucide-react";
import { useJob } from "../context/JobContext";
import EmptyJobState from "../components/EmptyJobState";
import SeverityBadge from "../components/SeverityBadge";
import type { AttackerRow } from "../types";

type SortKey = "count" | "lastSeen" | "ip";

export default function Attackers() {
  const { job, isDone } = useJob();
  const navigate = useNavigate();
  const [sortKey, setSortKey] = useState<SortKey>("count");
  const [sortDesc, setSortDesc] = useState(true);

  const rows = useMemo(() => {
    const list = job?.summary?.topAttackers ?? [];
    const sorted = [...list].sort((a: AttackerRow, b: AttackerRow) => {
      const av = a[sortKey] ?? "";
      const bv = b[sortKey] ?? "";
      if (av < bv) return sortDesc ? 1 : -1;
      if (av > bv) return sortDesc ? -1 : 1;
      return 0;
    });
    return sorted;
  }, [job, sortKey, sortDesc]);

  if (!isDone || !job?.summary) {
    return (
      <div>
        <h1 className="text-xl font-bold mb-5">Attackers</h1>
        <EmptyJobState />
      </div>
    );
  }

  const toggleSort = (key: SortKey) => {
    if (sortKey === key) setSortDesc(!sortDesc);
    else {
      setSortKey(key);
      setSortDesc(true);
    }
  };

  const Th = ({ label, sortable, k }: { label: string; sortable?: boolean; k?: SortKey }) => (
    <th
      className={`px-4 py-3 text-left ${sortable ? "cursor-pointer select-none hover:text-[var(--color-text)]" : ""}`}
      onClick={sortable && k ? () => toggleSort(k) : undefined}
    >
      <span className="flex items-center gap-1">
        {label}
        {sortable && <ArrowUpDown size={11} />}
      </span>
    </th>
  );

  return (
    <div>
      <h1 className="text-xl font-bold mb-1">Attackers</h1>
      <p className="text-[13px] text-[var(--color-text-dim)] mb-5">{rows.length} unique attacker IPs identified</p>

      <div className="rounded-xl border border-[var(--color-border)] bg-[var(--color-surface)]/80 overflow-hidden">
        <div className="overflow-x-auto">
          <table className="w-full text-[12.5px]">
            <thead>
              <tr className="text-[var(--color-text-faint)] text-[10.5px] uppercase tracking-wide border-b border-[var(--color-border)]">
                <Th label="IP Address" sortable k="ip" />
                <Th label="Attack Count" sortable k="count" />
                <Th label="Top Attack" />
                <Th label="Severity" />
                <Th label="Country" />
                <Th label="City" />
                <Th label="ASN" />
                <Th label="Last Seen" sortable k="lastSeen" />
              </tr>
            </thead>
            <tbody>
              {rows.map((a) => (
                <tr
                  key={a.ip}
                  onClick={() => navigate(`/app/attackers/${a.ip}`)}
                  className="border-b border-[var(--color-border-soft)] last:border-none hover:bg-[var(--color-surface-2)] cursor-pointer"
                >
                  <td className="px-4 py-3 font-mono font-semibold">{a.ip}</td>
                  <td className="px-4 py-3">{a.count} attacks</td>
                  <td className="px-4 py-3 capitalize text-[var(--color-text-dim)]">{a.topAttack?.replace(/_/g, " ")}</td>
                  <td className="px-4 py-3">
                    <SeverityBadge severity={a.severity} />
                  </td>
                  <td className="px-4 py-3 text-[var(--color-text-dim)]">{a.country}</td>
                  <td className="px-4 py-3 text-[var(--color-text-dim)]">{a.city || "—"}</td>
                  <td className="px-4 py-3 text-[var(--color-text-dim)] text-[11.5px]">{a.asn ? `AS${a.asn}` : "—"}</td>
                  <td className="px-4 py-3 font-mono text-[var(--color-text-faint)]">{a.lastSeen?.slice(0, 19).replace("T", " ")}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
}
