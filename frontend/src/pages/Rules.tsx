import { useEffect, useState } from "react";
import { getRules, setRuleStatus } from "../lib/api";
import type { Rule } from "../types";
import SeverityBadge from "../components/SeverityBadge";

export default function Rules() {
  const [rules, setRules] = useState<Rule[]>([]);
  const [loading, setLoading] = useState(true);
  const [toggling, setToggling] = useState<string | null>(null);

  const load = () => {
    setLoading(true);
    getRules()
      .then((r) => setRules(r.rules))
      .finally(() => setLoading(false));
  };

  useEffect(load, []);

  const toggle = async (rule: Rule) => {
    setToggling(rule.rule);
    const next = rule.status === "enabled" ? "disabled" : "enabled";
    try {
      await setRuleStatus(rule.rule, next);
      setRules((prev) => prev.map((r) => (r.rule === rule.rule ? { ...r, status: next } : r)));
    } finally {
      setToggling(null);
    }
  };

  return (
    <div>
      <h1 className="text-xl font-bold mb-1">Detection Rules</h1>
      <p className="text-[13px] text-[var(--color-text-dim)] mb-6">
        Active signature categories. Disabling a rule here takes effect on the next analysis — it genuinely stops the
        matching regex from running, it isn't a display-only toggle.
      </p>

      <div className="rounded-xl border border-[var(--color-border)] bg-[var(--color-surface)]/80 overflow-hidden">
        <table className="w-full text-[13px]">
          <thead>
            <tr className="text-left text-[var(--color-text-faint)] text-[10.5px] uppercase tracking-wide border-b border-[var(--color-border)]">
              <th className="px-4 py-3">Rule</th>
              <th className="px-4 py-3">Attack Type</th>
              <th className="px-4 py-3">Severity</th>
              <th className="px-4 py-3">Pattern Count</th>
              <th className="px-4 py-3">Status</th>
            </tr>
          </thead>
          <tbody>
            {loading && (
              <tr>
                <td colSpan={5} className="px-4 py-8 text-center text-[var(--color-text-faint)]">
                  Loading…
                </td>
              </tr>
            )}
            {!loading &&
              rules.map((r) => (
                <tr key={r.rule} className="border-b border-[var(--color-border-soft)] last:border-none">
                  <td className="px-4 py-3 font-medium capitalize">{r.rule.replace(/_/g, " ")}</td>
                  <td className="px-4 py-3 text-[var(--color-text-dim)]">{r.description}</td>
                  <td className="px-4 py-3">
                    <SeverityBadge severity={r.severity} />
                  </td>
                  <td className="px-4 py-3 font-mono">{r.patternCount} patterns</td>
                  <td className="px-4 py-3">
                    <button
                      onClick={() => toggle(r)}
                      disabled={toggling === r.rule}
                      className={`px-3 py-1 rounded-full text-[11px] font-semibold border transition-colors disabled:opacity-50 ${
                        r.status === "enabled"
                          ? "border-[var(--color-safe)]/30 bg-[var(--color-safe-glow)] text-[var(--color-safe)]"
                          : "border-[var(--color-border)] text-[var(--color-text-faint)]"
                      }`}
                    >
                      {r.status === "enabled" ? "Enabled" : "Disabled"}
                    </button>
                  </td>
                </tr>
              ))}
          </tbody>
        </table>
      </div>
    </div>
  );
}
