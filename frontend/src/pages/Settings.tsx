import { useEffect, useState } from "react";
import { CheckCircle2, XCircle, Shield, Lock } from "lucide-react";
import { getSettings, type Settings as SettingsType } from "../lib/api";
import Panel from "../components/Panel";

export default function Settings() {
  const [settings, setSettings] = useState<SettingsType | null>(null);

  useEffect(() => {
    getSettings().then(setSettings);
  }, []);

  if (!settings) return <div className="text-[13px] text-[var(--color-text-dim)]">Loading…</div>;

  return (
    <div className="max-w-2xl space-y-5">
      <h1 className="text-xl font-bold">Settings</h1>

      <Panel title="Security Configuration">
        <div className="space-y-3">
          <div className="flex items-center justify-between text-[13px]">
            <div className="flex items-center gap-2">
              <Lock size={14} className="text-[var(--color-primary)]" />
              <span className="text-[var(--color-text-dim)]">Authentication</span>
            </div>
            <span className="font-mono text-[var(--color-safe)] flex items-center gap-1">
              <CheckCircle2 size={13} /> Enabled
            </span>
          </div>
          <div className="flex items-center justify-between text-[13px]">
            <div className="flex items-center gap-2">
              <Shield size={14} className="text-[var(--color-primary)]" />
              <span className="text-[var(--color-text-dim)]">JWT Token Expiry</span>
            </div>
            <span className="font-mono">24 hours</span>
          </div>
        </div>
      </Panel>

      <Panel title="GeoIP">
        <div className="space-y-3 mb-3">
          <div className="flex items-center justify-between text-[13px]">
            <span className="text-[var(--color-text-dim)]">Country database</span>
            <span className="font-mono flex items-center gap-1">
              {settings.geoipAvailable ? (
                <><CheckCircle2 size={13} className="text-[var(--color-safe)]" /> Loaded</>
              ) : (
                <><XCircle size={13} className="text-[var(--color-warning)]" /> Not found</>
              )}
            </span>
          </div>
          <div className="flex items-center justify-between text-[13px]">
            <span className="text-[var(--color-text-dim)]">City database (coordinates)</span>
            <span className="font-mono flex items-center gap-1">
              {settings.geoipCityAvailable ? (
                <><CheckCircle2 size={13} className="text-[var(--color-safe)]" /> Loaded</>
              ) : (
                <><XCircle size={13} className="text-[var(--color-warning)]" /> Not found</>
              )}
            </span>
          </div>
          <div className="flex items-center justify-between text-[13px]">
            <span className="text-[var(--color-text-dim)]">ASN database (ISP info)</span>
            <span className="font-mono flex items-center gap-1">
              {settings.geoipAsnAvailable ? (
                <><CheckCircle2 size={13} className="text-[var(--color-safe)]" /> Loaded</>
              ) : (
                <><XCircle size={13} className="text-[var(--color-warning)]" /> Not found</>
              )}
            </span>
          </div>
        </div>
        <p className="text-[12px] text-[var(--color-text-dim)] leading-relaxed">
          To enable: create a free MaxMind account, download the <code className="font-mono text-[11.5px] bg-[var(--color-surface-2)] px-1.5 py-0.5 rounded">.mmdb</code> files,
          and place them in <code className="font-mono text-[11.5px] bg-[var(--color-surface-2)] px-1.5 py-0.5 rounded">backend/geoip/</code>, then restart.
          City database adds latitude/longitude for map plotting. ASN database adds ISP/organization info.
        </p>
      </Panel>

      <Panel title="Brute Force Detection">
        <dl className="space-y-3 text-[13px]">
          <div className="flex justify-between">
            <dt className="text-[var(--color-text-dim)]">Threshold</dt>
            <dd className="font-mono">{settings.bruteForceThreshold} failed attempts</dd>
          </div>
          <div className="flex justify-between">
            <dt className="text-[var(--color-text-dim)]">Rolling window</dt>
            <dd className="font-mono">{settings.bruteForceWindowSeconds / 60} minutes</dd>
          </div>
        </dl>
        <p className="text-[11.5px] text-[var(--color-text-faint)] mt-3">
          Configured via <code className="font-mono">LOGLENS_BRUTE_FORCE_THRESHOLD</code> /{" "}
          <code className="font-mono">LOGLENS_BRUTE_FORCE_WINDOW_SECONDS</code> environment variables.
        </p>
      </Panel>

      <Panel title="Upload Limits">
        <dl className="space-y-3 text-[13px]">
          <div className="flex justify-between">
            <dt className="text-[var(--color-text-dim)]">Max file size</dt>
            <dd className="font-mono">{Math.round(settings.maxUploadBytes / (1024 * 1024 * 1024))}GB</dd>
          </div>
          <div className="flex justify-between">
            <dt className="text-[var(--color-text-dim)]">Allowed extensions</dt>
            <dd className="font-mono">{settings.allowedExtensions.join(", ")}</dd>
          </div>
          <div className="flex justify-between">
            <dt className="text-[var(--color-text-dim)]">Chunk size</dt>
            <dd className="font-mono">{settings.chunkSize.toLocaleString()} lines</dd>
          </div>
        </dl>
      </Panel>

      <Panel title="Job Queue">
        <div className="flex justify-between text-[13px]">
          <dt className="text-[var(--color-text-dim)]">Backend</dt>
          <dd className="font-mono">{settings.jobQueueBackend === "thread" ? "In-process (dev fallback)" : settings.jobQueueBackend}</dd>
        </div>
      </Panel>
    </div>
  );
}
