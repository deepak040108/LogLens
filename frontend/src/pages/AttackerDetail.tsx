import { useParams, useNavigate } from "react-router-dom";
import { ArrowLeft, Shield, AlertTriangle, Globe2, Target, MapPin, Building2 } from "lucide-react";
import { useJob } from "../context/JobContext";
import EmptyJobState from "../components/EmptyJobState";
import SeverityBadge from "../components/SeverityBadge";
import type { EnhancedAttacker } from "../types";

const LABELS: Record<string, string> = {
  sql_injection: "SQL Injection",
  xss: "XSS",
  directory_traversal: "Directory Traversal",
  brute_force: "Brute Force",
  recon: "Reconnaissance",
  command_injection: "Command Injection / RCE",
  log4shell: "Log4Shell",
};

function ThreatScoreCard({ attacker }: { attacker: EnhancedAttacker }) {
  const score = attacker.threatScore;
  if (!score) return null;

  const scoreColor =
    score.score >= 80
      ? "text-[var(--color-critical)]"
      : score.score >= 50
        ? "text-[var(--color-warning)]"
        : "text-[var(--color-safe)]";

  const scoreBg =
    score.score >= 80
      ? "bg-[var(--color-critical-glow)] border-[var(--color-critical)]/30"
      : score.score >= 50
        ? "bg-[var(--color-warning-glow)] border-[var(--color-warning)]/30"
        : "bg-[var(--color-safe-glow)] border-[var(--color-safe)]/30";

  return (
    <div className="rounded-xl border border-[var(--color-border)] bg-[var(--color-surface)] p-5">
      <div className="flex items-center gap-2 mb-4">
        <Shield size={16} className="text-[var(--color-primary)]" />
        <h3 className="text-[12.5px] font-semibold uppercase tracking-wide text-[var(--color-text-dim)]">Threat Score</h3>
      </div>
      <div className="flex items-start gap-6">
        <div className={`w-20 h-20 rounded-xl border flex flex-col items-center justify-center shrink-0 ${scoreBg}`}>
          <span className={`text-2xl font-bold font-mono ${scoreColor}`}>{score.score}</span>
          <span className="text-[10px] uppercase tracking-wide text-[var(--color-text-faint)]">/100</span>
        </div>
        <div className="flex-1 min-w-0">
          <div className="flex items-center gap-2 mb-2">
            <span className={`text-[13px] font-semibold ${scoreColor}`}>{score.level}</span>
            <span className="text-[12px] text-[var(--color-text-dim)]">— {score.summary}</span>
          </div>
          {score.contributors.length > 0 && (
            <div className="space-y-1.5">
              {score.contributors.map((c, i) => (
                <div key={i} className="flex items-center justify-between text-[12px]">
                  <span className="text-[var(--color-text-dim)]">{c.factor}</span>
                  <div className="flex items-center gap-2">
                    <span className="text-[var(--color-text-faint)] text-[11px]">{c.detail}</span>
                    <span className="font-mono text-[var(--color-warning)]">+{c.points}</span>
                  </div>
                </div>
              ))}
            </div>
          )}
        </div>
      </div>
    </div>
  );
}

function EvidenceCard({ attacker }: { attacker: EnhancedAttacker }) {
  const reasons: string[] = [];
  if (attacker.count > 10) reasons.push(`High request volume: ${attacker.count} attacks detected`);
  if (attacker.severity === "critical" || attacker.severity === "high")
    reasons.push(`Severity classification: ${attacker.severity}`);
  if (attacker.attackHistory.length > 2)
    reasons.push(`Multi-vector attack pattern: ${attacker.attackHistory.length} distinct attack types`);
  const bruteForce = attacker.attackHistory.find((h) => h.attack_type === "brute_force");
  if (bruteForce && bruteForce.count > 5) reasons.push(`Brute force activity: ${bruteForce.count} login attempts`);

  if (reasons.length === 0) {
    reasons.push("Pattern matching triggered based on signature detection");
  }

  return (
    <div className="rounded-xl border border-[var(--color-border)] bg-[var(--color-surface)] p-5">
      <div className="flex items-center gap-2 mb-4">
        <AlertTriangle size={16} className="text-[var(--color-warning)]" />
        <h3 className="text-[12.5px] font-semibold uppercase tracking-wide text-[var(--color-text-dim)]">Why is this IP suspicious?</h3>
      </div>
      <ul className="space-y-2">
        {reasons.map((r, i) => (
          <li key={i} className="flex items-start gap-2 text-[12.5px]">
            <span className="w-1.5 h-1.5 rounded-full bg-[var(--color-warning)] mt-1.5 shrink-0" />
            <span className="text-[var(--color-text-dim)]">{r}</span>
          </li>
        ))}
      </ul>
    </div>
  );
}

export default function AttackerDetail() {
  const { ip } = useParams<{ ip: string }>();
  const { job, isDone } = useJob();
  const navigate = useNavigate();

  if (!isDone || !job?.summary) {
    return <EmptyJobState />;
  }

  const attacker = job.summary.topAttackers.find((a) => a.ip === ip) as EnhancedAttacker | undefined;
  if (!attacker) {
    return (
      <div>
        <button onClick={() => navigate("/app/attackers")} className="flex items-center gap-1.5 text-[13px] text-[var(--color-text-dim)] mb-4">
          <ArrowLeft size={15} /> Back to Attackers
        </button>
        <div className="text-[13.5px] text-[var(--color-text-dim)]">No record found for {ip}.</div>
      </div>
    );
  }

  const maxCount = Math.max(...attacker.attackHistory.map((h) => h.count), 1);

  return (
    <div className="max-w-4xl">
      <button onClick={() => navigate("/app/attackers")} className="flex items-center gap-1.5 text-[13px] text-[var(--color-text-dim)] mb-5 hover:text-[var(--color-text)]">
        <ArrowLeft size={15} /> Back to Attackers
      </button>

      <div className="flex items-center justify-between mb-6">
        <div>
          <h1 className="text-2xl font-mono font-bold">{attacker.ip}</h1>
          <div className="flex items-center gap-3 mt-1.5 flex-wrap">
            <div className="flex items-center gap-1.5 text-[13px] text-[var(--color-text-dim)]">
              <Globe2 size={13} />
              {attacker.country}
            </div>
            {attacker.geoAvailable && attacker.countryCode && (
              <span className="text-[12px] font-mono text-[var(--color-text-faint)] bg-[var(--color-surface-2)] px-1.5 py-0.5 rounded">
                {attacker.countryCode}
              </span>
            )}
            {attacker.city && (
              <div className="flex items-center gap-1 text-[12.5px] text-[var(--color-text-dim)]">
                <MapPin size={12} />
                {attacker.city}{attacker.region ? `, ${attacker.region}` : ""}
              </div>
            )}
            {attacker.organization && (
              <div className="flex items-center gap-1 text-[12.5px] text-[var(--color-text-dim)]">
                <Building2 size={12} />
                {attacker.asn ? `AS${attacker.asn}` : ""} {attacker.organization}
              </div>
            )}
          </div>
        </div>
        <SeverityBadge severity={attacker.severity} />
      </div>

      <div className="grid grid-cols-2 sm:grid-cols-4 gap-3 mb-5">
        {[
          { label: "Total Attacks", value: attacker.count },
          { label: "First Seen", value: attacker.firstSeen?.slice(0, 19).replace("T", " ") ?? "—" },
          { label: "Last Seen", value: attacker.lastSeen?.slice(0, 19).replace("T", " ") ?? "—" },
          { label: "Most Common", value: LABELS[attacker.topAttack ?? ""] ?? attacker.topAttack ?? "—" },
        ].map((f) => (
          <div key={f.label} className="rounded-xl border border-[var(--color-border)] bg-[var(--color-surface)] p-4">
            <div className="text-[10.5px] uppercase tracking-wide text-[var(--color-text-faint)] mb-1">{f.label}</div>
            <div className="text-[13.5px] font-mono">{f.value}</div>
          </div>
        ))}
      </div>

      <div className="space-y-5">
        <ThreatScoreCard attacker={attacker} />
        <EvidenceCard attacker={attacker} />

        <div className="rounded-xl border border-[var(--color-border)] bg-[var(--color-surface)] p-5">
          <div className="flex items-center gap-2 mb-4">
            <Target size={16} className="text-[var(--color-primary)]" />
            <h3 className="text-[12.5px] font-semibold uppercase tracking-wide text-[var(--color-text-dim)]">Attack History</h3>
          </div>
          <div className="space-y-3">
            {attacker.attackHistory.map((h) => (
              <div key={h.attack_type}>
                <div className="flex items-center justify-between mb-1.5 text-[12.5px]">
                  <span className="capitalize">{LABELS[h.attack_type] ?? h.attack_type.replace(/_/g, " ")}</span>
                  <span className="font-mono text-[var(--color-text-dim)]">{h.count}</span>
                </div>
                <div className="h-1.5 rounded-full bg-[var(--color-surface-2)] overflow-hidden">
                  <div
                    className={`h-full rounded-full ${
                      h.attack_type === "brute_force"
                        ? "bg-[var(--color-warning)]"
                        : ["sql_injection", "command_injection", "log4shell"].includes(h.attack_type)
                          ? "bg-[var(--color-critical)]"
                          : "bg-[var(--color-primary)]"
                    }`}
                    style={{ width: `${(h.count / maxCount) * 100}%` }}
                  />
                </div>
              </div>
            ))}
          </div>
        </div>

        {attacker.targetedEndpoints && attacker.targetedEndpoints.length > 0 && (
          <div className="rounded-xl border border-[var(--color-border)] bg-[var(--color-surface)] p-5">
            <h3 className="text-[12.5px] font-semibold uppercase tracking-wide text-[var(--color-text-dim)] mb-4">Top Targeted Endpoints</h3>
            <div className="space-y-2">
              {attacker.targetedEndpoints.slice(0, 5).map((ep, i) => (
                <div key={i} className="flex items-center justify-between text-[12.5px] py-1.5 border-b border-[var(--color-border-soft)] last:border-none">
                  <span className="font-mono text-[var(--color-text-dim)] truncate">{ep.path}</span>
                  <span className="font-mono text-[var(--color-text-faint)] shrink-0 ml-3">{ep.count}×</span>
                </div>
              ))}
            </div>
          </div>
        )}
      </div>
    </div>
  );
}
