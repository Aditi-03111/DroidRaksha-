// DroidRaksha — API client
import type { AnalysisResult, DashboardStats } from "./types";

const API_BASE = process.env.NEXT_PUBLIC_API_URL ?? "http://localhost:8000";

async function request<T>(path: string, init?: RequestInit): Promise<T> {
  const res = await fetch(`${API_BASE}${path}`, {
    ...init,
    headers: {
      ...(init?.headers ?? {}),
    },
  });
  if (!res.ok) {
    const body = await res.json().catch(() => ({}));
    throw new Error(body?.detail ?? `HTTP ${res.status}`);
  }
  return res.json() as Promise<T>;
}

/** Upload an APK file and get back the full analysis result. */
export async function uploadApk(file: File): Promise<AnalysisResult> {
  const fd = new FormData();
  fd.append("file", file);
  return request<AnalysisResult>("/upload", { method: "POST", body: fd });
}

/** Fetch a previously-run analysis by ID. */
export async function getAnalysis(id: string): Promise<AnalysisResult> {
  return request<AnalysisResult>(`/analysis/${id}`);
}

/** Get dashboard stats. */
export async function getStats(): Promise<DashboardStats> {
  return request<DashboardStats>("/stats");
}

/** Download the PDF forensic report for an analysis. */
export function getReportUrl(id: string): string {
  return `${API_BASE}/report/${id}`;
}
