"use client";

import { useEffect, useState } from "react";
import { useRouter } from "next/navigation";
import Image from "next/image";
import { Shield, ShieldAlert, ShieldCheck, Zap, BarChart3, Activity } from "lucide-react";
import DropZone from "@/components/DropZone";
import AnalysisLoader from "@/components/AnalysisLoader";
import { getStats, uploadApk } from "@/lib/api";
import type { DashboardStats } from "@/lib/types";

export default function Home() {
  const router = useRouter();
  const [stats, setStats] = useState<DashboardStats | null>(null);
  const [isLoading, setIsLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    getStats()
      .then(setStats)
      .catch((err) => console.error("Failed to fetch stats:", err));
  }, []);

  const handleUpload = async (file: File) => {
    setIsLoading(true);
    setError(null);
    try {
      const result = await uploadApk(file);
      // Redirect to the results page on success
      router.push(`/results/${result.id}`);
    } catch (err: any) {
      console.error("Upload failed:", err);
      setError(err.message || "Analysis failed. Please try again.");
      setIsLoading(false);
    }
  };

  return (
    <div className="min-h-screen flex flex-col items-center justify-center p-6 md:p-12 gap-12">
      {/* Background grid effect */}
      <div className="absolute inset-0 bg-[linear-gradient(to_right,#1f2937_1px,transparent_1px),linear-gradient(to_bottom,#1f2937_1px,transparent_1px)] bg-[size:4rem_4rem] [mask-image:radial-gradient(ellipse_60%_50%_at_50%_0%,#000_70%,transparent_100%)] -z-10 opacity-30" />

      {/* Header */}
      <div className="text-center space-y-4 max-w-3xl animate-fade-in-up">
        <div className="inline-flex items-center gap-2 bg-indigo-500/10 text-indigo-400 px-4 py-1.5 rounded-full text-sm font-semibold border border-indigo-500/20 mb-2">
          <Shield className="w-4 h-4" />
          India's APK Threat Intelligence
        </div>
        <h1 className="text-4xl md:text-6xl font-bold tracking-tight">
          Droid<span className="gradient-text">Raksha</span>
        </h1>
        <p className="text-slate-400 text-lg md:text-xl max-w-2xl mx-auto">
          Advanced static analysis platform designed to detect Android malware, banking trojans, and UPI fraud apps targeting the Indian ecosystem.
        </p>
      </div>

      {/* Stats Grid */}
      {stats && (
        <div className="grid grid-cols-2 md:grid-cols-4 gap-4 w-full max-w-4xl animate-fade-in-up delay-100">
          <StatCard
            icon={<Activity className="text-indigo-400" />}
            label="Total Scans"
            value={stats.total_analyses}
          />
          <StatCard
            icon={<ShieldAlert className="text-rose-400" />}
            label="Critical Threats"
            value={stats.critical_count + stats.high_count}
          />
          <StatCard
            icon={<ShieldCheck className="text-cyan-400" />}
            label="Safe Apps"
            value={stats.safe_count}
          />
          <StatCard
            icon={<BarChart3 className="text-yellow-400" />}
            label="Avg Risk Score"
            value={`${Math.round(stats.avg_risk_score)}/100`}
          />
        </div>
      )}

      {/* Main Action Area */}
      <div className="w-full max-w-2xl card-surface p-8 rounded-2xl animate-fade-in-up delay-200 glass relative overflow-hidden">
        {/* Decorative background glow */}
        <div className="absolute -top-24 -left-24 w-48 h-48 bg-indigo-500/20 rounded-full blur-3xl -z-10" />
        <div className="absolute -bottom-24 -right-24 w-48 h-48 bg-cyan-500/20 rounded-full blur-3xl -z-10" />

        {isLoading ? (
          <AnalysisLoader />
        ) : (
          <div className="space-y-6">
            <div className="text-center">
              <h2 className="text-xl font-semibold text-slate-100">Upload APK for Analysis</h2>
              <p className="text-sm text-slate-400 mt-1">
                Your file will be scanned against 50+ YARA rules and analyzed by AI.
              </p>
            </div>
            
            <DropZone onUpload={handleUpload} isLoading={isLoading} />

            {error && (
              <div className="p-3 rounded-lg bg-rose-500/10 border border-rose-500/20 text-rose-400 text-sm text-center">
                {error}
              </div>
            )}
          </div>
        )}
      </div>

      {/* Footer / Tech Info */}
      <div className="flex flex-col items-center gap-2 text-xs text-slate-600 animate-fade-in-up delay-300">
        <p>Powered by Androguard, YARA, and Anthropic Claude</p>
        <div className="flex gap-4">
          <span>v1.0.0</span>
          <span>•</span>
          <span>Confidential & Secure</span>
        </div>
      </div>
    </div>
  );
}

function StatCard({ icon, label, value }: { icon: React.ReactNode; label: string; value: string | number }) {
  return (
    <div className="card-surface p-4 rounded-xl flex flex-col items-center justify-center text-center gap-1 hover:border-white/10 transition-colors">
      <div className="w-8 h-8 rounded-full bg-slate-800 flex items-center justify-center mb-1">
        {icon}
      </div>
      <p className="text-2xl font-bold font-mono text-slate-100">{value}</p>
      <p className="text-xs text-slate-500">{label}</p>
    </div>
  );
}
