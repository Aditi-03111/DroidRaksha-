"use client";
import { useCallback, useState } from "react";
import { Shield, Upload, FileWarning, Loader2, Zap } from "lucide-react";

interface DropZoneProps {
  onUpload: (file: File) => void;
  isLoading: boolean;
  compact?: boolean;
}

export default function DropZone({ onUpload, isLoading, compact = false }: DropZoneProps) {
  const [isDragging, setIsDragging] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const validate = (file: File) => {
    if (!file.name.toLowerCase().endsWith(".apk")) {
      setError("Only .apk files are accepted");
      return false;
    }
    if (file.size > 700 * 1024 * 1024) {
      setError("File size must be under 700 MB");
      return false;
    }
    setError(null);
    return true;
  };

  const handleDrop = useCallback(
    (e: React.DragEvent) => {
      e.preventDefault();
      setIsDragging(false);
      const file = e.dataTransfer.files[0];
      if (file && validate(file)) onUpload(file);
    },
    [onUpload]
  );

  const handleChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0];
    if (file && validate(file)) onUpload(file);
  };

  return (
    <div className="w-full max-w-2xl mx-auto">
      <label
        htmlFor="apk-upload"
        onDragEnter={() => setIsDragging(true)}
        onDragLeave={() => setIsDragging(false)}
        onDragOver={(e) => e.preventDefault()}
        onDrop={handleDrop}
        className={`
          relative flex flex-col items-center justify-center gap-4
          rounded-2xl border-2 border-dashed cursor-pointer
          transition-all duration-300 group select-none
          ${compact ? "p-5" : "p-12"}
          ${isLoading ? "pointer-events-none opacity-60" : ""}
          ${isDragging
            ? "border-indigo-400 bg-indigo-500/10 scale-[1.01]"
            : "border-slate-700 bg-slate-900/50 hover:border-indigo-500/60 hover:bg-indigo-500/5"
          }
        `}
      >
        {/* Animated corner accents */}
        <span className="absolute top-3 left-3 w-4 h-4 border-t-2 border-l-2 border-indigo-500 rounded-tl-md opacity-60" />
        <span className="absolute top-3 right-3 w-4 h-4 border-t-2 border-r-2 border-indigo-500 rounded-tr-md opacity-60" />
        <span className="absolute bottom-3 left-3 w-4 h-4 border-b-2 border-l-2 border-indigo-500 rounded-bl-md opacity-60" />
        <span className="absolute bottom-3 right-3 w-4 h-4 border-b-2 border-r-2 border-indigo-500 rounded-br-md opacity-60" />

        {isLoading ? (
          <>
            <div className="relative">
              <div className="w-16 h-16 rounded-full border-2 border-indigo-500/30 animate-spin-slow border-t-indigo-500" />
              <Shield className="absolute inset-0 m-auto w-7 h-7 text-indigo-400" />
            </div>
            <p className="text-slate-300 text-sm font-medium animate-pulse">
              Scanning APK with AI engines...
            </p>
          </>
        ) : (
          <>
            <div
              className={`w-16 h-16 rounded-2xl flex items-center justify-center transition-all duration-300
                ${isDragging ? "bg-indigo-500/30 scale-110" : "bg-indigo-500/10 group-hover:bg-indigo-500/20"}`}
            >
              <Upload
                className={`w-7 h-7 transition-colors ${isDragging ? "text-indigo-300" : "text-indigo-400"}`}
              />
            </div>

            <div className="text-center">
              <p className="text-slate-200 font-semibold text-base">
                {isDragging ? "Release to scan" : "Drop your APK here"}
              </p>
              <p className="text-slate-400 text-sm mt-1">
                or{" "}
                <span className="text-indigo-400 underline underline-offset-2">
                  browse to upload
                </span>
                {" "}— max 700 MB
              </p>
            </div>

            {!compact && (
              <div className="flex items-center gap-4 text-xs text-slate-500">
                <span className="flex items-center gap-1.5">
                  <Zap className="w-3 h-3 text-yellow-500" />
                  AI Narrative
                </span>
                <span className="w-1 h-1 rounded-full bg-slate-600" />
                <span className="flex items-center gap-1.5">
                  <Shield className="w-3 h-3 text-indigo-400" />
                  YARA Rules
                </span>
                <span className="w-1 h-1 rounded-full bg-slate-600" />
                <span className="flex items-center gap-1.5">
                  <FileWarning className="w-3 h-3 text-rose-400" />
                  MITRE ATT&CK
                </span>
              </div>
            )}
          </>
        )}

        <input
          id="apk-upload"
          type="file"
          accept=".apk"
          className="hidden"
          disabled={isLoading}
          onChange={handleChange}
        />
      </label>

      {error && (
        <p className="mt-3 text-center text-sm text-rose-400 flex items-center justify-center gap-1.5">
          <FileWarning className="w-4 h-4" />
          {error}
        </p>
      )}
    </div>
  );
}
