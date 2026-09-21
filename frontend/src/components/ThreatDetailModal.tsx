import { X } from "lucide-react";
import { useNavigate } from "react-router-dom";
import type { ThreatEvent, EnhancedFinding } from "../types";
import SeverityBadge from "./SeverityBadge";

interface Props {
  event: ThreatEvent & Partial<EnhancedFinding>;
  country?: string;
  onClose: () => void;
}

function Field({ label, value }: { label: string; value: React.ReactNode }) {
  return (
    <div>
      <div className="text-[10.5px] uppercase tracking-wide text-[var(--color-text-faint)] mb-0.5">{label}</div>
      <div className="text-[13px] font-mono break-all">{value ?? "—"}</div>
    </div>
  );
}

export default function ThreatDetailModal({ event, country, onClose }: Props) {
  const navigate = useNavigate();
  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/60 backdrop-blur-sm" onClick={onClose}>
      <div
        className="w-full max-w-xl rounded-xl border border-[var(--color-border)] bg-[var(--color-surface)] shadow-2xl max-h-[85vh] overflow-y-auto"
        onClick={(e) => e.stopPropagation()}
      >
        <div className="flex items-center justify-between px-5 h-14 border-b border-[var(--color-border)]">
          <div className="flex items-center gap-2">
            <SeverityBadge severity={event.severity} />
            <span className="text-[13px] font-semibold capitalize">{event.attack_type.replace(/_/g, " ")}</span>
          </div>
          <button onClick={onClose} className="text-[var(--color-text-dim)] hover:text-[var(--color-text)]">
            <X size={18} />
          </button>
        </div>

        <div className="p-5 space-y-5">
          <div className="grid grid-cols-2 gap-4">
            <Field label="IP Address" value={event.ip} />
            <Field label="Country" value={country || "Location unavailable"} />
            <Field label="Timestamp" value={event.timestamp?.replace("T", " ")} />
            <Field label="HTTP Method" value={event.method} />
            <Field label="Status Code" value={event.status} />
            <Field label="User Agent" value={event.userAgent} />
          </div>

          <Field label="Request Path" value={event.path} />

          {event.rule_id && (
            <div className="flex gap-4">
              <Field label="Rule ID" value={event.rule_id} />
              {event.confidence && <Field label="Confidence" value={event.confidence} />}
            </div>
          )}

          <div className="rounded-lg border border-[var(--color-primary)]/25 bg-[var(--color-primary-glow)] p-4">
            <div className="text-[10.5px] uppercase tracking-wide text-[var(--color-primary)] font-semibold mb-1.5">
              Detection Reason
            </div>
            <div className="text-[12.5px] mb-2">
              <span className="text-[var(--color-text-dim)]">Matched signature: </span>
              <span className="font-mono">{event.matched_signature}</span>
            </div>
            <p className="text-[12.5px] text-[var(--color-text-dim)] leading-relaxed">{event.reason}</p>
          </div>

          {event.recommendation && (
            <div className="rounded-lg border border-[var(--color-warning)]/25 bg-[var(--color-warning-glow)] p-4">
              <div className="text-[10.5px] uppercase tracking-wide text-[var(--color-warning)] font-semibold mb-1.5">
                Recommendation
              </div>
              <p className="text-[12.5px] text-[var(--color-text-dim)] leading-relaxed">{event.recommendation}</p>
            </div>
          )}

          {event.all_matches.length > 1 && (
            <div>
              <div className="text-[10.5px] uppercase tracking-wide text-[var(--color-text-faint)] mb-2">
                All Matched Signatures ({event.all_matches.length})
              </div>
              <div className="space-y-1.5">
                {event.all_matches.map((m, i) => (
                  <div key={i} className="flex items-center gap-2 text-[12px]">
                    <SeverityBadge severity={m.severity} />
                    <span className="font-mono text-[var(--color-text-dim)]">{m.matched_signature}</span>
                  </div>
                ))}
              </div>
            </div>
          )}

          <button
            onClick={() => {
              onClose();
              navigate(`/app/attackers/${event.ip}`);
            }}
            className="w-full py-2.5 rounded-lg border border-[var(--color-border)] text-[13px] font-medium hover:bg-[var(--color-surface-2)] transition-colors"
          >
            View Attacker →
          </button>
        </div>
      </div>
    </div>
  );
}
