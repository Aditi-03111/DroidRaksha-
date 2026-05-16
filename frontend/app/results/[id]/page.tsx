"use client";

import { useEffect, useState } from "react";
import { useParams, useRouter } from "next/navigation";
import { ArrowLeft, Download, FileCode, Shield, RefreshCcw } from "lucide-react";
import Link from "next/link";

import { getAnalysis, getReportUrl } from "@/lib/api";
import type { AnalysisResult } from "@/lib/types";

import RiskScoreCard from "@/components/RiskScoreCard";
import AIExplanation from "@/components/AIExplanation";
import PermissionTable from "@/components/PermissionTable";
import StringsTable from "@/components/StringsTable";
import CertificateCard from "@/components/CertificateCard";
import MitreTable from "@/components/MitreTable";

export default function ResultsPage() {
  const { id } = useParams() as { id: string };
  const router = useRouter();
  
  const [result, setResult] = useState<AnalysisResult | null>(null);
  const [isLoading, setIsLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    if (!id) return;

    setIsLoading(true);
    getAnalysis(id)
      .then((data) => {
        setResult(data);
        setIsLoading(false);
      })
      .catch((err) => {
        console.error("Failed to load analysis:", err);
        setError(err.message || "Failed to load analysis result.");
        setIsLoading(false);
      });
  }, [id]);

  if (isLoading) {
    return (
      <div className="min-h-screen flex flex-col items-center justify-center gap-4">
        <div className="relative w-16 h-16">
          <div className="absolute inset-0 rounded-full border-2 border-indigo-500/20 animate-spin-slow border-t-indigo-500" />
          <Shield className="absolute inset-0 m-auto w-6 h-6 text-indigo-400 animate-pulse" />
        </div>
        <p className="text-slate-400 text-sm font-medium">Retrieving analysis results...</p>
      </div>
    );
  }

  if (error || !result) {
    return (
      <div className="min-h-screen flex flex-col items-center justify-center gap-4">
        <div className="w-12 h-12 rounded-full bg-rose-500/10 flex items-center justify-center">
          <Shield className="w-6 h-6 text-rose-400" />
        </div>
        <h2 className="text-xl font-semibold text-slate-100">Error Loading Results</h2>
        <p className="text-slate-400 text-sm max-w-md text-center">{error || "Analysis not found."}</p>
        <Link
          href="/"
          className="mt-2 inline-flex items-center gap-2 bg-slate-800 hover:bg-slate-700 text-slate-200 px-4 py-2 rounded-lg text-sm transition-colors"
        >
          <ArrowLeft className="w-4 h-4" /> Back to Dashboard
        </Link>
      </div>
    );
  }

  return (
    <div className="min-h-screen p-6 md:p-12 max-w-7xl mx-auto space-y-8">
      {/* Navigation & Actions */}
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4">
        <div className="flex items-center gap-3">
          <Link
            href="/"
            className="w-10 h-10 rounded-full bg-slate-800/50 flex items-center justify-center hover:bg-slate-700 transition-colors border border-white/5"
          >
            <ArrowLeft className="w-4 h-4 text-slate-300" />
          </Link>
          <div>
            <div className="flex items-center gap-2">
              <h1 className="text-2xl font-bold text-slate-100 truncate max-w-md">
                {result.filename}
              </h1>
              <span className={`text-xs font-bold px-2 py-0.5 rounded-full risk-badge-${result.risk.risk_level.toLowerCase()}`}>
                {result.risk.risk_level}
              </span>
            </div>
            <p className="text-xs font-mono text-slate-500 mt-0.5 break-all">
              SHA-256: {result.hashes.sha256}
            </p>
          </div>
        </div>

        <div className="flex items-center gap-3">
          <a
            href={getReportUrl(result.id)}
            target="_blank"
            rel="noopener noreferrer"
            className="inline-flex items-center gap-2 bg-indigo-500 hover:bg-indigo-600 text-white px-4 py-2.5 rounded-lg text-sm font-medium transition-colors shadow-lg shadow-indigo-500/20"
          >
            <Download className="w-4 h-4" /> Download Report
          </a>
        </div>
      </div>

      {/* Grid Layout */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Left Column - Risk & AI */}
        <div className="lg:col-span-1 space-y-6">
          <RiskScoreCard risk={result.risk} />
          <AIExplanation
            narrative={result.ai_narrative}
            recommendations={result.ai_recommendations}
          />
          <CertificateCard cert={result.certificate} />
        </div>

        {/* Right Column - Technical Details */}
        <div className="lg:col-span-2 space-y-6">
          {/* File Info Card */}
          <div className="card-surface p-6 rounded-2xl grid grid-cols-2 md:grid-cols-4 gap-4">
            <InfoItem label="Package Name" value={result.manifest.package_name} />
            <InfoItem label="Version" value={`${result.manifest.version_name} (${result.manifest.version_code})`} />
            <InfoItem label="Target SDK" value={result.manifest.target_sdk.toString()} />
            <InfoItem label="File Size" value={`${(result.hashes.file_size / 1024 / 1024).toFixed(2)} MB`} />
          </div>

          <MitreTable tactics={result.mitre} />
          <PermissionTable
            permissions={result.manifest.permissions}
            dangerousCombos={result.manifest.dangerous_combos}
          />
          <StringsTable strings={result.strings} />
        </div>
      </div>
    </div>
  );
}

function InfoItem({ label, value }: { label: string; value: string }) {
  return (
    <div className="space-y-1">
      <p className="text-xs text-slate-500 uppercase tracking-wider">{label}</p>
      <p className="text-sm font-medium text-slate-200 truncate" title={value}>{value}</p>
    </div>
  );
}
