import { useMemo, useState } from "react";
import { useJob } from "../context/JobContext";
import EmptyJobState from "../components/EmptyJobState";
import Panel from "../components/Panel";
import AttackTimelineChart from "../components/AttackTimelineChart";

const RANGES = [
  { key: "all", label: "All time" },
  { key: "12", label: "Last 12 hours of activity" },
  { key: "6", label: "Last 6 hours of activity" },
];

export default function TimelinePage() {
  const { job, isDone } = useJob();
  const [range, setRange] = useState("all");

  const timeline = useMemo(() => {
    const full = job?.summary?.timeline ?? [];
    if (range === "all") return full;
    const n = parseInt(range, 10);
    return full.slice(-n);
  }, [job, range]);

  if (!isDone || !job?.summary) {
    return (
      <div>
        <h1 className="text-xl font-bold mb-5">Timeline</h1>
        <EmptyJobState />
      </div>
    );
  }

  return (
    <div>
      <div className="flex items-center justify-between mb-5">
        <div>
          <h1 className="text-xl font-bold">Timeline</h1>
          <p className="text-[13px] text-[var(--color-text-dim)] mt-1">{timeline.reduce((s, t) => s + t.count, 0)} attacks shown</p>
        </div>
        <select
          value={range}
          onChange={(e) => setRange(e.target.value)}
          className="bg-[var(--color-surface)] border border-[var(--color-border)] rounded-lg px-3 py-2 text-[12.5px]"
        >
          {RANGES.map((r) => (
            <option key={r.key} value={r.key}>
              {r.label}
            </option>
          ))}
        </select>
      </div>
      <Panel title="Attacks per Hour">
        <AttackTimelineChart timeline={timeline} />
      </Panel>
    </div>
  );
}
