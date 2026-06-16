"use client";

import { useEffect, useState } from "react";
import { useParams } from "next/navigation";
import { ArrowLeft, Shield } from "lucide-react";
import Link from "next/link";

import { getAnalysis } from "@/lib/api";
import type { AnalysisResult } from "@/lib/types";

import RiskScoreCard from "@/components/RiskScoreCard";
import AIExplanation from "@/components/AIExplanation";
import PermissionTable from "@/components/PermissionTable";
import StringsTable from "@/components/StringsTable";
import CertificateCard from "@/components/CertificateCard";
import MitreTable from "@/components/MitreTable";
import ExportButton from "@/components/ExportButton";
import APKFileTree from "@/components/APKFileTree";
import ManifestViewer from "@/components/ManifestViewer";
import MalwareFamilyBadge from "@/components/MalwareFamilyBadge";

export default function ResultsPage() {
  const { id } = useParams() as { id: string };

  const [result, setResult] = useState<AnalysisResult | null>(null);
  const [isLoading, setIsLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [activeTab, setActiveTab] = useState<"overview" | "filetree" | "manifest" | "ml">("overview");

  useEffect(() => {
    if (!id) return;
    setIsLoading(true);
    getAnalysis(id)
      .then((data) => { setResult(data); setIsLoading(false); })
      .catch((err) => { setError(err.message || "Failed to load analysis result."); setIsLoading(false); });
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
        <Link href="/" className="mt-2 inline-flex items-center gap-2 bg-slate-800 hover:bg-slate-700 text-slate-200 px-4 py-2 rounded-lg text-sm transition-colors">
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
          <Link href="/" className="w-10 h-10 rounded-full bg-slate-800/50 flex items-center justify-center hover:bg-slate-700 transition-colors border border-white/5">
            <ArrowLeft className="w-4 h-4 text-slate-300" />
          </Link>
          <div>
            <div className="flex items-center gap-2">
              <h1 className="text-2xl font-bold text-slate-100 truncate max-w-md">{result.filename}</h1>
              <span className={`text-xs font-bold px-2 py-0.5 rounded-full risk-badge-${result.risk.risk_level.toLowerCase()}`}>
                {result.risk.risk_level}
              </span>
            </div>
            <p className="text-xs font-mono text-slate-500 mt-0.5 break-all">
              SHA-256: {result.hashes.sha256}
            </p>
          </div>
        </div>
        <ExportButton
          analysisId={result.id}
          packageName={result.manifest?.package_name}
          sha256={result.hashes?.sha256}
        />
      </div>

      {/* Tab Navigation */}
      <div className="flex gap-1 bg-slate-900/60 rounded-xl p-1 border border-slate-700/40 w-fit overflow-x-auto">
        {(["overview", "filetree", "manifest", "ml"] as const).map((tab) => (
          <button
            key={tab}
            id={`tab-${tab}`}
            onClick={() => setActiveTab(tab)}
            className={`px-4 py-2 rounded-lg text-sm font-medium transition-all whitespace-nowrap ${
              activeTab === tab
                ? "bg-indigo-600 text-white shadow-lg shadow-indigo-500/20"
                : "text-slate-400 hover:text-slate-200 hover:bg-slate-800/60"
            }`}
          >
            {tab === "overview" ? "📊 Analysis"
              : tab === "filetree" ? "🌳 File Tree"
              : tab === "manifest" ? "📋 Manifest"
              : "🧠 ML Intelligence"}
          </button>
        ))}
      </div>

      {/* Tab Content */}
      {activeTab === "overview" && (
        <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
          <div className="lg:col-span-1 space-y-6">
            <RiskScoreCard risk={result.risk} />
            {result.ml_classification && (
              <MalwareFamilyBadge
                mlClassification={result.ml_classification}
                xgboost={result.xgboost}
                malbert={result.malbert}
                anomaly={result.anomaly}
                agentVerdict={result.agent_verdict}
              />
            )}
            <AIExplanation narrative={result.ai_narrative} recommendations={result.ai_recommendations} />
            <CertificateCard cert={result.certificate} />
          </div>
          <div className="lg:col-span-2 space-y-6">
            <div className="card-surface p-6 rounded-2xl grid grid-cols-2 md:grid-cols-4 gap-4">
              <InfoItem label="Package Name" value={result.manifest.package_name} />
              <InfoItem label="Version" value={`${result.manifest.version_name} (${result.manifest.version_code})`} />
              <InfoItem label="Target SDK" value={result.manifest.target_sdk.toString()} />
              <InfoItem label="File Size" value={`${(result.hashes.file_size / 1024 / 1024).toFixed(2)} MB`} />
            </div>
            <MitreTable tactics={result.mitre} />
            <PermissionTable permissions={result.manifest.permissions} dangerousCombos={result.manifest.dangerous_combos} />
            <StringsTable strings={result.strings} />
          </div>
        </div>
      )}

      {activeTab === "filetree" && (
        <div className="space-y-4">
          <p className="text-sm text-slate-400">
            Decoded APK file structure. Suspicious entries (hidden DEX payloads, native .so in assets, encrypted binaries) are highlighted in red.
          </p>
          <APKFileTree analysisId={result.id} />
        </div>
      )}

      {activeTab === "manifest" && (
        <div className="space-y-4">
          <p className="text-sm text-slate-400">
            Decoded <code className="font-mono text-indigo-400">AndroidManifest.xml</code> with syntax highlighting.
            Dangerous permissions and components are highlighted in red.
          </p>
          <ManifestViewer analysisId={result.id} />
        </div>
      )}

      {activeTab === "ml" && (
        <div className="space-y-6">
          <p className="text-sm text-slate-400">
            Full ML Intelligence Layer results — XGBoost (CICMalDroid 2020), MalBERT zero-shot,
            Isolation Forest anomaly detection, and LangChain court-grade verdict.
          </p>
          <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
            <MalwareFamilyBadge
              mlClassification={result.ml_classification}
              xgboost={result.xgboost}
              malbert={result.malbert}
              anomaly={result.anomaly}
              agentVerdict={result.agent_verdict}
            />

            {/* Court Narrative */}
            {result.agent_verdict?.court_narrative && (
              <div className="card-surface rounded-2xl p-6 space-y-4">
                <div className="flex items-center gap-2">
                  <span className="text-lg">⚖️</span>
                  <h3 className="font-semibold text-slate-200">Court-Grade Verdict</h3>
                  <span className="ml-auto text-xs text-slate-500">
                    Confidence: <span className="text-indigo-400 font-mono">{result.agent_verdict.verdict_confidence}%</span>
                  </span>
                </div>
                <div className="text-sm text-slate-300 leading-relaxed whitespace-pre-wrap">
                  {result.agent_verdict.court_narrative}
                </div>
                {result.agent_verdict.ioc_summary && (
                  <div className="p-3 rounded-xl bg-rose-500/10 border border-rose-500/20">
                    <p className="text-xs font-semibold text-rose-400 mb-1">IOC Summary</p>
                    <p className="text-xs text-slate-300">{result.agent_verdict.ioc_summary}</p>
                  </div>
                )}
              </div>
            )}

            {/* XGBoost Class Probabilities */}
            {result.xgboost?.available && (
              <div className="card-surface rounded-2xl p-6 space-y-4">
                <h3 className="font-semibold text-slate-200 flex items-center gap-2">
                  <span>⚡</span> XGBoost Class Probabilities
                  <span className="text-xs text-slate-500 font-normal ml-auto">MalDroid 2020 · {result.xgboost.inference_ms}ms</span>
                </h3>
                {Object.entries(result.xgboost.class_probs)
                  .sort(([, a], [, b]) => b - a)
                  .map(([cls, prob]) => (
                    <div key={cls} className="flex items-center gap-3">
                      <span className="text-xs text-slate-400 w-28 shrink-0">{cls}</span>
                      <div className="flex-1 h-2 bg-slate-800 rounded-full overflow-hidden">
                        <div
                          className="h-full rounded-full transition-all duration-700"
                          style={{ width: `${prob * 100}%`, background: prob > 0.5 ? "#f43f5e" : prob > 0.2 ? "#f97316" : "#22d3ee" }}
                        />
                      </div>
                      <span className="text-xs font-mono text-slate-400 w-10 text-right">{(prob * 100).toFixed(1)}%</span>
                    </div>
                  ))}
              </div>
            )}

            {/* MalBERT all scores */}
            {result.malbert?.available && (
              <div className="card-surface rounded-2xl p-6 space-y-4">
                <h3 className="font-semibold text-slate-200 flex items-center gap-2">
                  <span>🧠</span> MalBERT Zero-Shot Scores
                  <span className="text-xs text-slate-500 font-normal ml-auto">{result.malbert.inference_ms}ms</span>
                </h3>
                {Object.entries(result.malbert.all_scores)
                  .sort(([, a], [, b]) => b - a)
                  .map(([cls, score]) => (
                    <div key={cls} className="flex items-center gap-3">
                      <span className="text-xs text-slate-400 w-36 shrink-0 capitalize">{cls}</span>
                      <div className="flex-1 h-2 bg-slate-800 rounded-full overflow-hidden">
                        <div
                          className="h-full rounded-full transition-all duration-700"
                          style={{ width: `${score * 100}%`, background: score > 0.5 ? "#f43f5e" : score > 0.2 ? "#f97316" : "#22d3ee" }}
                        />
                      </div>
                      <span className="text-xs font-mono text-slate-400 w-10 text-right">{(score * 100).toFixed(1)}%</span>
                    </div>
                  ))}
              </div>
            )}
          </div>
        </div>
      )}
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
