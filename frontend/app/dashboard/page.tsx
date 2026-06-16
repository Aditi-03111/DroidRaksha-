"use client";

import { useEffect, useState, useCallback } from "react";
import { useRouter } from "next/navigation";
import Link from "next/link";
import {
  Shield, ShieldAlert, ShieldCheck, Activity, BarChart3,
  FileSearch, AlertTriangle, Wifi, Globe, Zap, Clock,
  ChevronRight, RefreshCw, TrendingUp, Users, Radio,
} from "lucide-react";
import { getStats, uploadApk } from "@/lib/api";
import type { DashboardStats } from "@/lib/types";
import DropZone from "@/components/DropZone";
import AnalysisProgress from "@/components/AnalysisProgress";

// ── Colour helpers ──────────────────────────────────────────────────────────

const RISK_COLORS: Record<string, string> = {
  CRITICAL: "text-red-400",
  HIGH:     "text-orange-400",
  MEDIUM:   "text-yellow-400",
  LOW:      "text-green-400",
  SAFE:     "text-cyan-400",
};

const RISK_BG: Record<string, string> = {
  CRITICAL: "bg-red-500/10 border-red-500/30",
  HIGH:     "bg-orange-500/10 border-orange-500/30",
  MEDIUM:   "bg-yellow-500/10 border-yellow-500/30",
  LOW:      "bg-green-500/10 border-green-500/30",
  SAFE:     "bg-cyan-500/10 border-cyan-500/30",
};

const FAMILY_COLORS: Record<string, string> = {
  BankingTrojan:  "#f43f5e",
  Ransomware:     "#fb923c",
  Spyware:        "#a78bfa",
  RAT:            "#60a5fa",
  Dropper:        "#f59e0b",
  Adware:         "#34d399",
  SMSMalware:     "#ec4899",
  Riskware:       "#94a3b8",
  Benign:         "#22d3ee",
  Unknown:        "#475569",
};

// ── Mini Donut Chart (pure CSS/SVG, no library) ────────────────────────────

function DonutChart({ data }: { data: Record<string, number> }) {
  const entries = Object.entries(data).filter(([, v]) => v > 0);
  const total   = entries.reduce((s, [, v]) => s + v, 0);
  if (total === 0) return <p className="text-slate-500 text-xs text-center py-6">No data yet</p>;

  const R = 60, STROKE = 18, C = 2 * Math.PI * R;
  let offset = 0;

  return (
    <div className="flex flex-col items-center gap-4">
      <svg viewBox="0 0 160 160" className="w-40 h-40">
        <circle cx="80" cy="80" r={R} fill="none" stroke="#1e293b" strokeWidth={STROKE} />
        {entries.map(([label, val]) => {
          const pct  = val / total;
          const dash = pct * C;
          const gap  = C - dash;
          const rot  = offset * 360 - 90;
          offset += pct;
          return (
            <circle
              key={label}
              cx="80" cy="80" r={R}
              fill="none"
              stroke={FAMILY_COLORS[label] ?? "#64748b"}
              strokeWidth={STROKE}
              strokeDasharray={`${dash} ${gap}`}
              strokeDashoffset={0}
              transform={`rotate(${rot} 80 80)`}
              className="transition-all duration-700"
            />
          );
        })}
        <text x="80" y="76" textAnchor="middle" className="fill-slate-100" fontSize="20" fontWeight="bold">{total}</text>
        <text x="80" y="94" textAnchor="middle" className="fill-slate-500" fontSize="9">total</text>
      </svg>

      <div className="grid grid-cols-2 gap-x-4 gap-y-1.5 w-full">
        {entries.map(([label, val]) => (
          <div key={label} className="flex items-center gap-1.5">
            <div className="w-2 h-2 rounded-full shrink-0" style={{ background: FAMILY_COLORS[label] ?? "#64748b" }} />
            <span className="text-xs text-slate-400 truncate">{label}</span>
            <span className="text-xs text-slate-500 ml-auto font-mono">{val}</span>
          </div>
        ))}
      </div>
    </div>
  );
}

// ── Risk Bar Chart ──────────────────────────────────────────────────────────

function RiskBars({ stats }: { stats: DashboardStats }) {
  const bars = [
    { label: "Critical", value: stats.critical_count ?? 0, color: "#f43f5e" },
    { label: "High",     value: stats.high_count    ?? 0, color: "#fb923c" },
    { label: "Medium",   value: stats.medium_count  ?? 0, color: "#fbbf24" },
    { label: "Low",      value: stats.low_count     ?? 0, color: "#34d399" },
    { label: "Safe",     value: stats.safe_count    ?? 0, color: "#22d3ee" },
  ];
  const max = Math.max(...bars.map(b => b.value), 1);

  return (
    <div className="space-y-3 pt-2">
      {bars.map(b => (
        <div key={b.label} className="flex items-center gap-3">
          <span className="text-xs text-slate-400 w-14 shrink-0">{b.label}</span>
          <div className="flex-1 h-2.5 bg-slate-800 rounded-full overflow-hidden">
            <div
              className="h-full rounded-full transition-all duration-1000"
              style={{ width: `${(b.value / max) * 100}%`, background: b.color }}
            />
          </div>
          <span className="text-xs font-mono text-slate-400 w-6 text-right">{b.value}</span>
        </div>
      ))}
    </div>
  );
}

// ── Stat Card ───────────────────────────────────────────────────────────────

function StatCard({
  icon, label, value, sub, pulse = false,
}: {
  icon: React.ReactNode; label: string; value: string | number;
  sub?: string; pulse?: boolean;
}) {
  return (
    <div className="rounded-xl bg-slate-900/60 border border-slate-700/40 p-4 flex flex-col gap-2 hover:border-slate-600/60 transition-colors">
      <div className="flex items-center justify-between">
        <div className="w-9 h-9 rounded-lg bg-slate-800/80 flex items-center justify-center">
          {icon}
        </div>
        {pulse && <span className="flex h-2 w-2"><span className="animate-ping absolute inline-flex h-2 w-2 rounded-full bg-red-400 opacity-75" /><span className="relative inline-flex rounded-full h-2 w-2 bg-red-500" /></span>}
      </div>
      <p className="text-2xl font-bold font-mono text-slate-100">{value}</p>
      <div>
        <p className="text-xs font-medium text-slate-300">{label}</p>
        {sub && <p className="text-xs text-slate-500">{sub}</p>}
      </div>
    </div>
  );
}

// ── Recent Scans Table ─────────────────────────────────────────────────────

interface RecentScan {
  id: string; filename: string; package_name: string;
  risk_score: number; risk_level: string; created_at: string;
}

function RecentScansTable({ scans }: { scans: RecentScan[] }) {
  if (!scans.length) {
    return (
      <div className="text-center py-12 text-slate-500">
        <FileSearch className="w-10 h-10 mx-auto mb-3 opacity-30" />
        <p className="text-sm">No scans yet — upload your first APK above!</p>
      </div>
    );
  }

  return (
    <div className="overflow-x-auto">
      <table className="w-full text-sm">
        <thead>
          <tr className="border-b border-slate-800">
            <th className="text-left py-3 px-2 text-slate-500 font-medium text-xs uppercase tracking-wider">APK / Package</th>
            <th className="text-center py-3 px-2 text-slate-500 font-medium text-xs uppercase tracking-wider">Score</th>
            <th className="text-center py-3 px-2 text-slate-500 font-medium text-xs uppercase tracking-wider">Risk</th>
            <th className="text-right py-3 px-2 text-slate-500 font-medium text-xs uppercase tracking-wider">Scanned</th>
            <th className="py-3 px-2" />
          </tr>
        </thead>
        <tbody>
          {scans.map((s) => (
            <tr key={s.id} className="border-b border-slate-800/50 hover:bg-slate-800/30 transition-colors group">
              <td className="py-3 px-2">
                <p className="text-slate-200 font-medium truncate max-w-xs">{s.filename}</p>
                <p className="text-xs text-slate-500 font-mono truncate max-w-xs">{s.package_name}</p>
              </td>
              <td className="py-3 px-2 text-center">
                <span className={`text-lg font-bold font-mono ${
                  s.risk_score >= 70 ? "text-red-400" :
                  s.risk_score >= 40 ? "text-orange-400" :
                  s.risk_score >= 20 ? "text-yellow-400" : "text-green-400"
                }`}>{s.risk_score}</span>
              </td>
              <td className="py-3 px-2 text-center">
                <span className={`text-xs font-bold px-2 py-1 rounded-full border ${RISK_BG[s.risk_level] ?? "bg-slate-800 border-slate-700"} ${RISK_COLORS[s.risk_level] ?? "text-slate-400"}`}>
                  {s.risk_level}
                </span>
              </td>
              <td className="py-3 px-2 text-right text-xs text-slate-500 font-mono whitespace-nowrap">
                {new Date(s.created_at).toLocaleString("en-IN", { dateStyle: "short", timeStyle: "short" })}
              </td>
              <td className="py-3 px-2">
                <Link
                  href={`/results/${s.id}`}
                  className="opacity-0 group-hover:opacity-100 transition-opacity flex items-center gap-1 text-xs text-indigo-400 hover:text-indigo-300"
                >
                  View <ChevronRight className="w-3 h-3" />
                </Link>
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

// ── Threat Activity Feed ────────────────────────────────────────────────────

function ThreatFeed({ scans }: { scans: RecentScan[] }) {
  const critical = scans.filter(s => s.risk_level === "CRITICAL" || s.risk_level === "HIGH");
  if (!critical.length) {
    return (
      <div className="text-center py-8 text-slate-500 text-xs">
        <ShieldCheck className="w-8 h-8 mx-auto mb-2 text-green-500/40" />
        No critical threats in recent history
      </div>
    );
  }
  return (
    <div className="space-y-2">
      {critical.slice(0, 6).map(s => (
        <Link key={s.id} href={`/results/${s.id}`}
          className="flex items-start gap-3 p-3 rounded-lg hover:bg-slate-800/50 transition-colors group"
        >
          <div className={`mt-0.5 w-2 h-2 rounded-full shrink-0 ${s.risk_level === "CRITICAL" ? "bg-red-500" : "bg-orange-500"} animate-pulse`} />
          <div className="flex-1 min-w-0">
            <p className="text-sm text-slate-200 truncate font-medium group-hover:text-indigo-300 transition-colors">
              {s.filename}
            </p>
            <p className="text-xs text-slate-500 font-mono truncate">{s.package_name}</p>
          </div>
          <span className={`shrink-0 text-xs font-bold ${RISK_COLORS[s.risk_level]}`}>{s.risk_score}</span>
        </Link>
      ))}
    </div>
  );
}

// ── Upload State ─────────────────────────────────────────────────────────────

type UploadState =
  | { phase: "idle" }
  | { phase: "uploading" }
  | { phase: "progress"; jobId: string }
  | { phase: "error"; msg: string };

// ── Main Dashboard ──────────────────────────────────────────────────────────

export default function DashboardPage() {
  const router = useRouter();
  const [stats, setStats]       = useState<DashboardStats | null>(null);
  const [loading, setLoading]   = useState(true);
  const [refreshing, setRefreshing] = useState(false);
  const [uploadState, setUploadState] = useState<UploadState>({ phase: "idle" });

  const fetchStats = async (showRefresh = false) => {
    if (showRefresh) setRefreshing(true);
    try {
      const data = await getStats();
      setStats(data);
    } finally {
      setLoading(false);
      setRefreshing(false);
    }
  };

  useEffect(() => { fetchStats(); }, []);

  const handleUpload = async (file: File) => {
    setUploadState({ phase: "uploading" });
    try {
      const res = await uploadApk(file);
      if (res.status === "complete" && res.result) {
        router.push(`/results/${res.result.id}`);
        return;
      }
      setUploadState({ phase: "progress", jobId: res.job_id });
    } catch (err: unknown) {
      setUploadState({ phase: "error", msg: err instanceof Error ? err.message : "Upload failed" });
    }
  };

  const handleComplete = useCallback((id: string) => {
    router.push(`/results/${id}`);
  }, [router]);

  const handleError = useCallback((msg: string) => {
    setUploadState({ phase: "error", msg });
  }, []);

  const isUploading = uploadState.phase === "uploading" || uploadState.phase === "progress";
  const recentScans: RecentScan[] = stats?.recent_analyses ?? [];
  const familyData  = (stats as Record<string, unknown>)?.family_breakdown as Record<string, number> ?? {};

  return (
    <div className="min-h-screen p-6 md:p-10 max-w-[1400px] mx-auto space-y-8">

      {/* Background */}
      <div className="fixed inset-0 bg-[linear-gradient(to_right,#1f2937_1px,transparent_1px),linear-gradient(to_bottom,#1f2937_1px,transparent_1px)] bg-[size:4rem_4rem] [mask-image:radial-gradient(ellipse_80%_60%_at_50%_0%,#000_70%,transparent_100%)] -z-10 opacity-20 pointer-events-none" />

      {/* ── Header ── */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
        <div className="flex items-center gap-3">
          <div className="w-10 h-10 rounded-xl bg-indigo-500/10 border border-indigo-500/20 flex items-center justify-center">
            <Shield className="w-5 h-5 text-indigo-400" />
          </div>
          <div>
            <h1 className="text-2xl font-bold text-slate-100">
              Droid<span className="bg-gradient-to-r from-indigo-400 to-cyan-400 bg-clip-text text-transparent">Raksha</span>
            </h1>
            <p className="text-xs text-slate-500">Threat Intelligence Dashboard</p>
          </div>
        </div>

        <div className="flex items-center gap-3">
          <button
            onClick={() => fetchStats(true)}
            disabled={refreshing}
            className="flex items-center gap-2 text-xs text-slate-400 hover:text-slate-200 bg-slate-800/60 hover:bg-slate-800 border border-slate-700/40 px-3 py-2 rounded-lg transition-all"
          >
            <RefreshCw className={`w-3.5 h-3.5 ${refreshing ? "animate-spin" : ""}`} />
            Refresh
          </button>
          <Link
            href="/"
            className="text-xs bg-indigo-600 hover:bg-indigo-500 text-white px-4 py-2 rounded-lg transition-colors font-medium"
          >
            + New Scan
          </Link>
        </div>
      </div>

      {/* ── Upload in-dashboard ── */}
      {uploadState.phase === "progress" ? (
        <div className="rounded-2xl bg-slate-900/60 border border-slate-700/40 p-6">
          <AnalysisProgress
            jobId={uploadState.jobId}
            onComplete={handleComplete}
            onError={handleError}
          />
        </div>
      ) : (
        <div className="rounded-2xl bg-slate-900/40 border border-dashed border-slate-700/60 p-5">
          <DropZone onUpload={handleUpload} isLoading={isUploading} compact />
          {uploadState.phase === "error" && (
            <p className="text-center text-xs text-red-400 mt-2">{uploadState.msg}</p>
          )}
        </div>
      )}

      {loading ? (
        <div className="flex flex-col items-center justify-center py-20 gap-4">
          <div className="w-10 h-10 rounded-full border-2 border-indigo-500/20 border-t-indigo-500 animate-spin" />
          <p className="text-slate-500 text-sm">Loading dashboard…</p>
        </div>
      ) : stats ? (
        <>
          {/* ── KPI Cards ── */}
          <div className="grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-6 gap-4">
            <StatCard
              icon={<Activity className="w-4 h-4 text-indigo-400" />}
              label="Total Scans" value={stats.total_analyzed ?? 0}
              sub="all time"
            />
            <StatCard
              icon={<ShieldAlert className="w-4 h-4 text-red-400" />}
              label="Critical Threats"
              value={(stats.critical_count ?? 0) + (stats.high_count ?? 0)}
              sub="CRITICAL + HIGH"
              pulse={(stats.critical_count ?? 0) > 0}
            />
            <StatCard
              icon={<Globe className="w-4 h-4 text-orange-400" />}
              label="India Targeted"
              value={(stats as Record<string, unknown>).india_targeted as number ?? 0}
              sub="UPI / banking threats"
            />
            <StatCard
              icon={<ShieldCheck className="w-4 h-4 text-green-400" />}
              label="Safe Apps" value={stats.safe_count ?? 0}
              sub="risk score < 20"
            />
            <StatCard
              icon={<Wifi className="w-4 h-4 text-cyan-400" />}
              label="PCAP Scans"
              value={(stats as Record<string, unknown>).pcap_scans as number ?? 0}
              sub="network captures"
            />
            <StatCard
              icon={<Zap className="w-4 h-4 text-yellow-400" />}
              label="YARA Rules" value={50}
              sub="active signatures"
            />
          </div>

          {/* ── Main Grid ── */}
          <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">

            {/* Left: Family Donut */}
            <div className="rounded-2xl bg-slate-900/60 border border-slate-700/40 p-5">
              <div className="flex items-center gap-2 mb-5">
                <BarChart3 className="w-4 h-4 text-indigo-400" />
                <h2 className="text-sm font-semibold text-slate-200">Malware Family Breakdown</h2>
              </div>
              <DonutChart data={familyData} />
            </div>

            {/* Middle: Risk Distribution */}
            <div className="rounded-2xl bg-slate-900/60 border border-slate-700/40 p-5">
              <div className="flex items-center gap-2 mb-5">
                <TrendingUp className="w-4 h-4 text-orange-400" />
                <h2 className="text-sm font-semibold text-slate-200">Risk Distribution</h2>
              </div>
              <RiskBars stats={stats} />

              {/* Mini summary */}
              <div className="mt-6 pt-4 border-t border-slate-800 grid grid-cols-2 gap-3">
                <div className="text-center">
                  <p className="text-xl font-bold font-mono text-red-400">
                    {stats.threats_detected ?? 0}
                  </p>
                  <p className="text-xs text-slate-500">Threats detected</p>
                </div>
                <div className="text-center">
                  <p className="text-xl font-bold font-mono text-green-400">
                    {stats.total_analyzed
                      ? Math.round(((stats.safe_count ?? 0) / stats.total_analyzed) * 100)
                      : 0}%
                  </p>
                  <p className="text-xs text-slate-500">Clean rate</p>
                </div>
              </div>
            </div>

            {/* Right: Threat Feed */}
            <div className="rounded-2xl bg-slate-900/60 border border-slate-700/40 p-5">
              <div className="flex items-center gap-2 mb-4">
                <Radio className="w-4 h-4 text-red-400" />
                <h2 className="text-sm font-semibold text-slate-200">Live Threat Feed</h2>
                <span className="ml-auto text-xs text-slate-500">Recent high-risk</span>
              </div>
              <ThreatFeed scans={recentScans} />
            </div>
          </div>

          {/* ── Recent Scans Table ── */}
          <div className="rounded-2xl bg-slate-900/60 border border-slate-700/40 p-5">
            <div className="flex items-center justify-between mb-5">
              <div className="flex items-center gap-2">
                <Clock className="w-4 h-4 text-slate-400" />
                <h2 className="text-sm font-semibold text-slate-200">Recent Analyses</h2>
                <span className="text-xs text-slate-600">— last 10</span>
              </div>
              <span className="text-xs text-slate-500">{stats.total_analyzed ?? 0} total scans</span>
            </div>
            <RecentScansTable scans={recentScans} />
          </div>

          {/* ── Footer ── */}
          <div className="flex flex-col sm:flex-row items-center justify-between gap-2 text-xs text-slate-600 pb-4">
            <p>Powered by Androguard · XGBoost + MalBERT · LangChain · Gemini Flash · YARA 50+ rules</p>
            <div className="flex items-center gap-3">
              <Users className="w-3 h-3" />
              <span>PHAPGUYZ · DroidRaksha v2.0</span>
            </div>
          </div>
        </>
      ) : (
        <div className="text-center py-20 text-slate-500">
          <AlertTriangle className="w-10 h-10 mx-auto mb-3 opacity-30" />
          <p>Failed to load dashboard stats.</p>
        </div>
      )}
    </div>
  );
}
