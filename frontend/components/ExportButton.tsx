"use client";
import { useState } from "react";
import { Download, FileJson, FileText, Loader2, CheckCircle2 } from "lucide-react";

interface ExportButtonProps {
  analysisId: string;
  packageName?: string;
  sha256?: string;
}

type ExportState = "idle" | "loading" | "done" | "error";

export default function ExportButton({ analysisId, packageName = "Unknown", sha256 }: ExportButtonProps) {
  const [pdfState, setPdfState] = useState<ExportState>("idle");
  const [jsonState, setJsonState] = useState<ExportState>("idle");

  const downloadPDF = async () => {
    if (pdfState === "loading") return;
    setPdfState("loading");
    try {
      const identifier = sha256 || analysisId;
      const res = await fetch(`${process.env.NEXT_PUBLIC_API_URL || "http://localhost:8000"}/api/report/${identifier}`);
      if (!res.ok) throw new Error("Failed to generate report");
      const blob = await res.blob();
      const url = URL.createObjectURL(blob);
      const a = document.createElement("a");
      a.href = url;
      a.download = `DroidRaksha_Report_${packageName.replace(/\./g, "_")}.pdf`;
      a.click();
      URL.revokeObjectURL(url);
      setPdfState("done");
      setTimeout(() => setPdfState("idle"), 3000);
    } catch {
      setPdfState("error");
      setTimeout(() => setPdfState("idle"), 3000);
    }
  };

  const downloadJSON = async () => {
    if (jsonState === "loading") return;
    setJsonState("loading");
    try {
      const res = await fetch(`${process.env.NEXT_PUBLIC_API_URL || "http://localhost:8000"}/api/analysis/${analysisId}`);
      if (!res.ok) throw new Error("Failed to fetch analysis data");
      const data = await res.json();
      const blob = new Blob([JSON.stringify(data, null, 2)], { type: "application/json" });
      const url = URL.createObjectURL(blob);
      const a = document.createElement("a");
      a.href = url;
      a.download = `DroidRaksha_${packageName.replace(/\./g, "_")}_${analysisId.slice(0, 8)}.json`;
      a.click();
      URL.revokeObjectURL(url);
      setJsonState("done");
      setTimeout(() => setJsonState("idle"), 3000);
    } catch {
      setJsonState("error");
      setTimeout(() => setJsonState("idle"), 3000);
    }
  };

  const btnClass = (state: ExportState, color: string) => `
    flex items-center gap-2 px-4 py-2 rounded-lg text-sm font-semibold
    border transition-all duration-200 select-none cursor-pointer
    ${state === "loading" ? "opacity-60 cursor-not-allowed" : ""}
    ${state === "done" ? `border-green-500/40 bg-green-500/10 text-green-400` : ""}
    ${state === "error" ? "border-rose-500/40 bg-rose-500/10 text-rose-400" : ""}
    ${state === "idle" ? `border-${color}-500/30 bg-${color}-500/10 text-${color}-400 hover:bg-${color}-500/20 hover:border-${color}-500/50` : ""}
  `;

  return (
    <div className="flex items-center gap-3 flex-wrap">
      {/* PDF Export */}
      <button
        id="export-pdf-btn"
        onClick={downloadPDF}
        disabled={pdfState === "loading"}
        className={btnClass(pdfState, "rose")}
        title="Download forensic PDF report"
      >
        {pdfState === "loading" ? (
          <Loader2 className="w-4 h-4 animate-spin" />
        ) : pdfState === "done" ? (
          <CheckCircle2 className="w-4 h-4" />
        ) : (
          <FileText className="w-4 h-4" />
        )}
        {pdfState === "loading" ? "Generating…" : pdfState === "done" ? "Downloaded!" : pdfState === "error" ? "Failed" : "Export PDF"}
      </button>

      {/* JSON Export */}
      <button
        id="export-json-btn"
        onClick={downloadJSON}
        disabled={jsonState === "loading"}
        className={btnClass(jsonState, "indigo")}
        title="Download raw JSON analysis"
      >
        {jsonState === "loading" ? (
          <Loader2 className="w-4 h-4 animate-spin" />
        ) : jsonState === "done" ? (
          <CheckCircle2 className="w-4 h-4" />
        ) : (
          <FileJson className="w-4 h-4" />
        )}
        {jsonState === "loading" ? "Exporting…" : jsonState === "done" ? "Downloaded!" : jsonState === "error" ? "Failed" : "Export JSON"}
      </button>

      {/* Share link */}
      <button
        id="share-report-btn"
        onClick={() => {
          navigator.clipboard.writeText(`${window.location.origin}/report/${sha256 || analysisId}`);
        }}
        className="flex items-center gap-2 px-4 py-2 rounded-lg text-sm font-semibold border border-slate-600/40 bg-slate-800/60 text-slate-300 hover:bg-slate-700/60 hover:text-slate-100 transition-all duration-200"
        title="Copy shareable report link"
      >
        <Download className="w-4 h-4" />
        Copy Link
      </button>
    </div>
  );
}
