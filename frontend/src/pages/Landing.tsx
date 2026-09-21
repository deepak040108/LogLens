import { useNavigate } from "react-router-dom";
import { ShieldCheck, Rss, ShieldAlert, MapPin, LineChart, FileDown, FlaskConical } from "lucide-react";
import { useJob } from "../context/JobContext";

const CAPABILITIES = [
  { icon: Rss, label: "Stream large log files", desc: "Chunked processing keeps memory flat even on multi-GB logs." },
  { icon: ShieldAlert, label: "Detect common web attacks", desc: "SQLi, XSS, traversal, command injection, Log4Shell, recon." },
  { icon: ShieldCheck, label: "Identify suspicious IPs", desc: "Behavioral brute-force detection, not just regex." },
  { icon: LineChart, label: "Analyze attack timelines", desc: "See exactly when the activity happened, hour by hour." },
  { icon: MapPin, label: "Visualize geographic origins", desc: "Real MaxMind GeoIP — never a fabricated country." },
  { icon: FileDown, label: "Export security reports", desc: "JSON, CSV, and PDF reports available." },
];

const PIPELINE = ["Upload", "Parse", "Detect", "Analyze", "Visualize"];

export default function Landing() {
  const navigate = useNavigate();
  const { startDemo } = useJob();

  return (
    <div className="min-h-screen bg-[var(--color-bg)] text-[var(--color-text)]">
      <header className="border-b border-[var(--color-border)]">
        <div className="max-w-6xl mx-auto px-6 h-16 flex items-center justify-between">
          <div className="flex items-center gap-2">
            <div className="w-8 h-8 rounded-lg bg-[var(--color-primary)]/15 border border-[var(--color-primary)]/30 flex items-center justify-center">
              <ShieldCheck size={17} className="text-[var(--color-primary)]" strokeWidth={2.25} />
            </div>
            <span className="font-semibold text-[15px]">LogLens</span>
          </div>

        </div>
      </header>

      <section className="max-w-4xl mx-auto px-6 pt-24 pb-20 text-center">
        <h1 className="text-4xl sm:text-5xl font-extrabold tracking-tight leading-tight">
          See Every Threat. <span className="text-[var(--color-primary)]">Understand Every Attack.</span>
        </h1>
        <p className="text-[var(--color-text-dim)] text-lg mt-5 max-w-2xl mx-auto">
          Lightweight Web Log Threat Detection &amp; Investigation Platform. Transform massive Apache and Nginx server logs into actionable security intelligence.
        </p>
        <div className="flex items-center justify-center gap-3 mt-9">
          <button
            onClick={() => {
              startDemo();
              navigate("/app/analyzer");
            }}
            className="px-6 py-3 rounded-lg bg-[var(--color-primary)] text-white font-semibold text-[14px] flex items-center gap-2 hover:opacity-90 transition-opacity"
          >
            <FlaskConical size={15} strokeWidth={2} />
            Load Demo Log
          </button>
          <button
            onClick={() => navigate("/app")}
            className="px-6 py-3 rounded-lg border border-[var(--color-border)] font-medium text-[14px] flex items-center gap-2 hover:bg-[var(--color-surface-2)] transition-colors"
          >
            Analyze Your Logs
          </button>
        </div>
      </section>

      <section className="max-w-5xl mx-auto px-6 pb-20">
        <div className="grid sm:grid-cols-2 lg:grid-cols-3 gap-4">
          {CAPABILITIES.map(({ icon: Icon, label, desc }) => (
            <div key={label} className="rounded-xl border border-[var(--color-border)] bg-[var(--color-surface)]/60 p-5">
              <div className="w-9 h-9 rounded-lg bg-[var(--color-primary)]/12 flex items-center justify-center mb-3">
                <Icon size={17} className="text-[var(--color-primary)]" strokeWidth={2} />
              </div>
              <div className="font-medium text-[13.5px] mb-1">{label}</div>
              <div className="text-[12px] text-[var(--color-text-dim)] leading-relaxed">{desc}</div>
            </div>
          ))}
        </div>
      </section>

      <section className="max-w-4xl mx-auto px-6 pb-24">
        <div className="rounded-xl border border-[var(--color-border)] bg-[var(--color-surface)]/60 p-8">
          <div className="flex items-center justify-center gap-2 flex-wrap">
            {PIPELINE.map((step, i) => (
              <div key={step} className="flex items-center gap-2">
                <div className="px-4 py-2 rounded-lg border border-[var(--color-primary)]/30 bg-[var(--color-primary)]/10 text-[var(--color-primary)] text-[13px] font-medium font-mono">
                  {step}
                </div>
                {i < PIPELINE.length - 1 && (
                  <span className="text-[var(--color-text-faint)] text-[13px]">→</span>
                )}
              </div>
            ))}
          </div>
        </div>
      </section>
    </div>
  );
}
