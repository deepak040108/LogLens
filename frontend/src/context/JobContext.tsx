import { createContext, useCallback, useContext, useRef, useState, type ReactNode } from "react";
import { getJob, loadDemoLog, uploadLogFile } from "../lib/api";
import type { Job } from "../types";

interface JobContextValue {
  job: Job | null;
  error: string | null;
  isBusy: boolean;
  isDone: boolean;
  startUpload: (file: File) => Promise<void>;
  startDemo: () => Promise<void>;
  reset: () => void;
}

const JobContext = createContext<JobContextValue | null>(null);

const POLL_INTERVAL_MS = 700;

// One job is "the currently analyzed file" for the whole app -- every
// page (Dashboard, Threats, Attackers, Timeline, Geo Map, Reports)
// reads from this same context so their numbers can never drift from
// each other, and so navigating between pages doesn't lose the
// in-progress or completed analysis.
export function JobProvider({ children }: { children: ReactNode }) {
  const [job, setJob] = useState<Job | null>(null);
  const [error, setError] = useState<string | null>(null);
  const pollRef = useRef<number | null>(null);

  const pollJob = useCallback((jobId: string) => {
    if (pollRef.current) window.clearInterval(pollRef.current);
    pollRef.current = window.setInterval(async () => {
      try {
        const data = await getJob(jobId);
        setJob(data);
        if (data.status === "completed" || data.status === "failed") {
          if (pollRef.current) window.clearInterval(pollRef.current);
        }
      } catch (e) {
        setError(e instanceof Error ? e.message : "Lost connection to the LogLens backend.");
        if (pollRef.current) window.clearInterval(pollRef.current);
      }
    }, POLL_INTERVAL_MS);
  }, []);

  const begin = useCallback(
    (jobId: string, status: string) => {
      setJob({
        job_id: jobId,
        status: status as Job["status"],
        total_lines: 0,
        processed_lines: 0,
        malformed_lines: 0,
        progress: 0,
        error: null,
        summary: null,
      });
      pollJob(jobId);
    },
    [pollJob]
  );

  const startUpload = useCallback(
    async (file: File) => {
      setError(null);
      try {
        const { job_id, status } = await uploadLogFile(file);
        begin(job_id, status);
      } catch (e) {
        setError(e instanceof Error ? e.message : "Upload failed");
      }
    },
    [begin]
  );

  const startDemo = useCallback(async () => {
    setError(null);
    try {
      const { job_id, status } = await loadDemoLog();
      begin(job_id, status);
    } catch (e) {
      setError(e instanceof Error ? e.message : "Could not load demo log");
    }
  }, [begin]);

  const reset = useCallback(() => {
    if (pollRef.current) window.clearInterval(pollRef.current);
    setJob(null);
    setError(null);
  }, []);

  const isBusy = job !== null && (job.status === "queued" || job.status === "processing");
  const isDone = job !== null && job.status === "completed";

  return (
    <JobContext.Provider value={{ job, error, isBusy, isDone, startUpload, startDemo, reset }}>
      {children}
    </JobContext.Provider>
  );
}

export function useJob() {
  const ctx = useContext(JobContext);
  if (!ctx) throw new Error("useJob must be used within a JobProvider");
  return ctx;
}
