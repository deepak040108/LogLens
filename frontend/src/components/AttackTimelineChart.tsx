import { Area, AreaChart, CartesianGrid, ResponsiveContainer, Tooltip, XAxis, YAxis } from "recharts";
import type { TimelineEntry } from "../types";

function formatHourLabel(hourKey: string) {
  const [date, hour] = hourKey.split("T");
  const [, m, d] = date.split("-");
  const months = ["", "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"];
  return `${d} ${months[parseInt(m, 10)]} ${hour}:00`;
}

export default function AttackTimelineChart({ timeline }: { timeline: TimelineEntry[] }) {
  const data = timeline.map((t) => ({ ...t, label: formatHourLabel(t.hour) }));
  return (
    <ResponsiveContainer width="100%" height={240}>
      <AreaChart data={data}>
        <defs>
          <linearGradient id="attackGradient" x1="0" y1="0" x2="0" y2="1">
            <stop offset="0%" stopColor="#3b82f6" stopOpacity={0.35} />
            <stop offset="100%" stopColor="#3b82f6" stopOpacity={0} />
          </linearGradient>
        </defs>
        <CartesianGrid stroke="#232a35" vertical={false} />
        <XAxis dataKey="label" tick={{ fill: "#8b93a1", fontSize: 11 }} axisLine={{ stroke: "#232a35" }} tickLine={false} />
        <YAxis tick={{ fill: "#8b93a1", fontSize: 11 }} axisLine={false} tickLine={false} allowDecimals={false} />
        <Tooltip
          contentStyle={{ background: "#171c25", border: "1px solid #232a35", borderRadius: 8, fontSize: 12 }}
          labelStyle={{ color: "#e8ebef" }}
        />
        <Area type="monotone" dataKey="count" name="Attacks" stroke="#3b82f6" strokeWidth={2} fill="url(#attackGradient)" />
      </AreaChart>
    </ResponsiveContainer>
  );
}
