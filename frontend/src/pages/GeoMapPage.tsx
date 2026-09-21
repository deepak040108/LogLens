import { useMemo, useState } from "react";
import { MapPinOff } from "lucide-react";
import { useJob } from "../context/JobContext";
import EmptyJobState from "../components/EmptyJobState";
import Panel from "../components/Panel";
import WorldMap from "../components/WorldMap";
import SeverityBadge from "../components/SeverityBadge";

export default function GeoMapPage() {
  const { job, isDone } = useJob();
  const [selectedCountry, setSelectedCountry] = useState<string | null>(null);

  const filteredAttackers = useMemo(() => {
    const list = job?.summary?.topAttackers ?? [];
    if (!selectedCountry) return list;
    return list.filter((a) => a.countryCode === selectedCountry);
  }, [job, selectedCountry]);

  if (!isDone || !job?.summary) {
    return (
      <div>
        <h1 className="text-xl font-bold mb-5">Geo Map</h1>
        <EmptyJobState />
      </div>
    );
  }

  const s = job.summary;

  if (!s.geoipAvailable) {
    return (
      <div>
        <h1 className="text-xl font-bold mb-5">Geo Map</h1>
        <div className="rounded-xl border border-[var(--color-warning)]/30 bg-[var(--color-warning-glow)] p-8 text-center">
          <MapPinOff size={26} className="text-[var(--color-warning)] mx-auto mb-3" strokeWidth={2} />
          <div className="font-semibold text-[var(--color-warning)] mb-1.5">Location unavailable</div>
          <p className="text-[13px] text-[var(--color-text-dim)] max-w-md mx-auto">
            No MaxMind GeoLite2 database is configured on this server, so attacker locations cannot be resolved.
            LogLens never fabricates geographic data — see Settings for how to enable real GeoIP lookups.
          </p>
        </div>
      </div>
    );
  }

  return (
    <div>
      <div className="flex items-center justify-between mb-5">
        <div>
          <h1 className="text-xl font-bold">Geo Map</h1>
          <p className="text-[13px] text-[var(--color-text-dim)] mt-1">
            {s.byCountry.length} countries · click a marker to filter attackers below
          </p>
        </div>
        {selectedCountry && (
          <button
            onClick={() => setSelectedCountry(null)}
            className="text-[12.5px] text-[var(--color-primary)] hover:underline"
          >
            Clear filter ({selectedCountry})
          </button>
        )}
      </div>

      <Panel title="Attacking IPs by Location">
        <WorldMap byCountry={s.byCountry} selectedCountry={selectedCountry} onSelectCountry={setSelectedCountry} />
      </Panel>

      <div className="mt-5">
        <Panel title={selectedCountry ? `Attackers from ${selectedCountry}` : "All Attackers"}>
          {filteredAttackers.length === 0 ? (
            <div className="text-[12.5px] text-[var(--color-text-faint)] text-center py-8">No attackers in this selection.</div>
          ) : (
            <table className="w-full text-[12.5px]">
              <thead>
                <tr className="text-left text-[var(--color-text-faint)] text-[10.5px] uppercase tracking-wide border-b border-[var(--color-border)]">
                  <th className="pb-2 pr-3">IP</th>
                  <th className="pb-2 pr-3">Country</th>
                  <th className="pb-2 pr-3">City</th>
                  <th className="pb-2 pr-3">ASN / Org</th>
                  <th className="pb-2 pr-3">Attacks</th>
                  <th className="pb-2">Severity</th>
                </tr>
              </thead>
              <tbody>
                {filteredAttackers.map((a) => (
                  <tr key={a.ip} className="border-b border-[var(--color-border-soft)] last:border-none">
                    <td className="py-2.5 pr-3 font-mono font-medium">{a.ip}</td>
                    <td className="py-2.5 pr-3 text-[var(--color-text-dim)]">{a.country}</td>
                    <td className="py-2.5 pr-3 text-[var(--color-text-dim)]">
                      {a.city || "—"}{a.region ? `, ${a.region}` : ""}
                    </td>
                    <td className="py-2.5 pr-3 text-[var(--color-text-dim)]">
                      {a.asn ? `AS${a.asn}` : "—"}{a.organization ? ` (${a.organization})` : ""}
                    </td>
                    <td className="py-2.5 pr-3">{a.count}</td>
                    <td className="py-2.5">
                      <SeverityBadge severity={a.severity} />
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
        </Panel>
      </div>
    </div>
  );
}
