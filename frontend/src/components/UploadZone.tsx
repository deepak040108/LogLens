import { useCallback, useRef, useState } from "react";
import { UploadCloud, FlaskConical } from "lucide-react";
import { useJob } from "../context/JobContext";

export default function UploadZone() {
  const { startUpload, startDemo, isBusy } = useJob();
  const [dragging, setDragging] = useState(false);
  const fileInputRef = useRef<HTMLInputElement>(null);

  const onDrop = useCallback(
    (e: React.DragEvent) => {
      e.preventDefault();
      setDragging(false);
      const file = e.dataTransfer.files?.[0];
      if (file) startUpload(file);
    },
    [startUpload]
  );

  return (
    <div
      onDragOver={(e) => {
        e.preventDefault();
        setDragging(true);
      }}
      onDragLeave={() => setDragging(false)}
      onDrop={onDrop}
      className={`rounded-2xl border-2 border-dashed p-14 text-center transition-colors ${
        dragging ? "border-[var(--color-primary)] bg-[var(--color-primary-glow)]" : "border-[var(--color-border)] bg-[var(--color-surface)]/60"
      }`}
    >
      <div className="w-12 h-12 mx-auto rounded-xl bg-[var(--color-primary)]/12 flex items-center justify-center mb-4">
        <UploadCloud size={22} className="text-[var(--color-primary)]" strokeWidth={2} />
      </div>
      <h2 className="text-[15px] font-medium mb-1.5">Drag &amp; drop your Apache/Nginx .log file here</h2>
      <p className="text-[12.5px] text-[var(--color-text-dim)] mb-6">
        Apache Common Log Format &amp; Nginx Common Log Format supported · processed server-side in streamed chunks
      </p>
      <div className="flex justify-center gap-3">
        <button
          onClick={() => fileInputRef.current?.click()}
          disabled={isBusy}
          className="px-4 py-2.5 rounded-lg bg-[var(--color-primary)] text-white text-[13px] font-semibold hover:opacity-90 disabled:opacity-40 transition-opacity"
        >
          Browse Files
        </button>
        <button
          onClick={startDemo}
          disabled={isBusy}
          className="px-4 py-2.5 rounded-lg border border-[var(--color-border)] text-[13px] font-medium flex items-center gap-2 hover:bg-[var(--color-surface-2)] disabled:opacity-40 transition-colors"
        >
          <FlaskConical size={14} strokeWidth={2} />
          Load Demo Log
        </button>
      </div>
      <input
        ref={fileInputRef}
        type="file"
        accept=".log,.txt"
        className="hidden"
        onChange={(e) => e.target.files?.[0] && startUpload(e.target.files[0])}
      />
    </div>
  );
}
