import { Bar, BarChart, CartesianGrid, ResponsiveContainer, Tooltip, XAxis, YAxis } from "recharts";
import type { AttackTypeEntry } from "../types";

const LABELS: Record<string, string> = {
  sql_injection: "SQL Injection",
  xss: "XSS",
  directory_traversal: "Directory Traversal",
  brute_force: "Brute Force",
  recon: "Reconnaissance",
  command_injection: "Command Injection / RCE",
  log4shell: "Log4Shell",
};

export default function AttackDistributionChart({ byType }: { byType: AttackTypeEntry[] }) {
  const data = byType.map((t) => ({ ...t, label: LABELS[t.attack_type] ?? t.attack_type }));
  return (
    <ResponsiveContainer width="100%" height={240}>
      <BarChart data={data} layout="vertical" margin={{ left: 12 }}>
        <CartesianGrid stroke="#232a35" horizontal={false} />
        <XAxis type="number" tick={{ fill: "#8b93a1", fontSize: 11 }} axisLine={{ stroke: "#232a35" }} tickLine={false} allowDecimals={false} />
        <YAxis type="category" dataKey="label" tick={{ fill: "#8b93a1", fontSize: 11 }} axisLine={false} tickLine={false} width={140} />
        <Tooltip
          contentStyle={{ background: "#171c25", border: "1px solid #232a35", borderRadius: 8, fontSize: 12 }}
          labelStyle={{ color: "#e8ebef" }}
          cursor={{ fill: "rgba(59,130,246,0.06)" }}
        />
        <Bar dataKey="count" name="Attacks" fill="#3b82f6" radius={[0, 4, 4, 0]} />
      </BarChart>
    </ResponsiveContainer>
  );
}
