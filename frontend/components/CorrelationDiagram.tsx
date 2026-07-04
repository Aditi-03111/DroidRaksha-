"use client";

import { GitCompareArrows } from "lucide-react";
import type { CorrelationFinding, CorrelationResult } from "@/lib/types";

interface Props {
  correlation?: CorrelationResult | null;
}

const shorten = (value: string, max = 24) => {
  if (value.length <= max) return value;
  return `${value.slice(0, max - 3)}...`;
};

const firstValue = (items: CorrelationFinding[] | undefined, fallback: string) => {
  return items?.find((item) => item.value)?.value ?? fallback;
};

export default function CorrelationDiagram({ correlation }: Props) {
  const matches = correlation?.matches ?? [];
  const threatIntelOverlaps = correlation?.threat_intel_overlaps ?? [];
  const hiddenRuntimeIndicators = correlation?.hidden_runtime_indicators ?? [];

  const matched = firstValue(matches, "evil-c2.com");
  const staticOnly =
    threatIntelOverlaps.find((item) => !matches.some((match) => match.value === item.value))?.value ??
    matches[1]?.value ??
    "flixfox-api.net";
  const runtimeOnly = firstValue(hiddenRuntimeIndicators, "185.220.x.x");
  const score = correlation?.available ? correlation.score : null;
  const severity = correlation?.available ? correlation.severity : "DEMO";

  return (
    <div className="bg-surface-raised border border-border p-5 corner-brackets space-y-4 overflow-hidden">
      <div className="flex flex-wrap items-center justify-between gap-3 border-b border-border pb-3">
        <div className="flex items-center gap-2 text-secondary font-mono text-sm uppercase">
          <GitCompareArrows className="w-4 h-4 text-primary" />
          Evidence Correlation Visual
        </div>
        <span className="text-[0.6rem] px-2 py-0.5 border border-[#22c55e]/40 bg-[rgba(34,197,94,0.08)] text-[#86efac] font-mono uppercase">
          {score === null ? "Judge View" : `${severity} · ${score}/100`}
        </span>
      </div>

      <div className="w-full overflow-x-auto">
        <svg
          viewBox="0 0 1120 520"
          role="img"
          aria-label="Static and dynamic IOC correlation outcomes"
          className="min-w-[760px] w-full h-auto"
        >
          <defs>
            <marker id="arrowStatic" markerWidth="10" markerHeight="10" refX="8" refY="5" orient="auto">
              <path d="M 0 0 L 10 5 L 0 10 z" fill="#3b82f6" />
            </marker>
            <marker id="arrowDynamic" markerWidth="10" markerHeight="10" refX="8" refY="5" orient="auto">
              <path d="M 0 0 L 10 5 L 0 10 z" fill="#10b981" />
            </marker>
            <marker id="arrowStaticOnly" markerWidth="10" markerHeight="10" refX="8" refY="5" orient="auto">
              <path d="M 0 0 L 10 5 L 0 10 z" fill="#c47a00" />
            </marker>
            <marker id="arrowRuntimeOnly" markerWidth="10" markerHeight="10" refX="8" refY="5" orient="auto">
              <path d="M 0 0 L 10 5 L 0 10 z" fill="#ef4444" />
            </marker>
          </defs>

          <text x="150" y="42" textAnchor="middle" fill="#cbd5c0" fontSize="20" fontWeight="700">
            Detection source
          </text>
          <text x="560" y="42" textAnchor="middle" fill="#cbd5c0" fontSize="20" fontWeight="700">
            Indicator (IOC)
          </text>
          <text x="940" y="42" textAnchor="middle" fill="#cbd5c0" fontSize="20" fontWeight="700">
            Correlation outcome
          </text>

          <line x1="280" y1="160" x2="435" y2="125" stroke="#3b82f6" strokeWidth="3" markerEnd="url(#arrowStatic)" />
          <line x1="280" y1="160" x2="435" y2="270" stroke="#3b82f6" strokeWidth="3" markerEnd="url(#arrowStatic)" />
          <line x1="280" y1="405" x2="435" y2="125" stroke="#10b981" strokeWidth="3" markerEnd="url(#arrowDynamic)" />
          <line x1="280" y1="405" x2="435" y2="390" stroke="#10b981" strokeWidth="3" markerEnd="url(#arrowDynamic)" />
          <line x1="685" y1="125" x2="815" y2="125" stroke="#65a30d" strokeWidth="3" markerEnd="url(#arrowDynamic)" />
          <line x1="685" y1="270" x2="815" y2="270" stroke="#c47a00" strokeWidth="3" markerEnd="url(#arrowStaticOnly)" />
          <line x1="685" y1="390" x2="815" y2="390" stroke="#ef4444" strokeWidth="3" markerEnd="url(#arrowRuntimeOnly)" />

          <g>
            <rect x="30" y="105" width="250" height="90" rx="10" fill="#124f86" stroke="#60a5fa" strokeWidth="1.5" />
            <text x="155" y="148" textAnchor="middle" fill="#dbeafe" fontSize="23" fontWeight="800">
              Static analysis
            </text>
            <text x="155" y="180" textAnchor="middle" fill="#9cc8ff" fontSize="19" fontWeight="600">
              Code-level IOCs
            </text>
          </g>

          <g>
            <rect x="30" y="360" width="250" height="90" rx="10" fill="#075f4f" stroke="#34d399" strokeWidth="1.5" />
            <text x="155" y="402" textAnchor="middle" fill="#bbf7d0" fontSize="23" fontWeight="800">
              Dynamic analysis
            </text>
            <text x="155" y="434" textAnchor="middle" fill="#6ee7b7" fontSize="19" fontWeight="600">
              Runtime IOCs
            </text>
          </g>

          <g>
            <rect x="435" y="88" width="250" height="74" rx="12" fill="#42433f" stroke="#8a8a84" strokeWidth="1.3" />
            <text x="560" y="133" textAnchor="middle" fill="#e7e5df" fontSize="23" fontWeight="800">
              {shorten(matched)}
            </text>
          </g>

          <g>
            <rect x="435" y="233" width="250" height="74" rx="12" fill="#42433f" stroke="#8a8a84" strokeWidth="1.3" />
            <text x="560" y="278" textAnchor="middle" fill="#e7e5df" fontSize="23" fontWeight="800">
              {shorten(staticOnly)}
            </text>
          </g>

          <g>
            <rect x="435" y="353" width="250" height="74" rx="12" fill="#42433f" stroke="#8a8a84" strokeWidth="1.3" />
            <text x="560" y="398" textAnchor="middle" fill="#e7e5df" fontSize="23" fontWeight="800">
              {shorten(runtimeOnly)}
            </text>
          </g>

          <g>
            <rect x="815" y="88" width="250" height="74" rx="12" fill="#1c5304" stroke="#65a30d" strokeWidth="1.5" />
            <text x="940" y="133" textAnchor="middle" fill="#d9f99d" fontSize="23" fontWeight="800">
              Matched
            </text>
          </g>

          <g>
            <rect x="815" y="233" width="250" height="74" rx="12" fill="#713f06" stroke="#c47a00" strokeWidth="1.5" />
            <text x="940" y="278" textAnchor="middle" fill="#fed7aa" fontSize="23" fontWeight="800">
              Static-only
            </text>
          </g>

          <g>
            <rect x="815" y="353" width="250" height="74" rx="12" fill="#842323" stroke="#f87171" strokeWidth="1.5" />
            <text x="940" y="398" textAnchor="middle" fill="#fecaca" fontSize="23" fontWeight="800">
              Runtime-only
            </text>
          </g>

          <g>
            <line x1="220" y1="480" x2="260" y2="480" stroke="#3b82f6" strokeWidth="3" />
            <text x="275" y="487" fill="#d8d5cd" fontSize="18" fontWeight="700">
              From static analysis
            </text>
            <line x1="615" y1="480" x2="655" y2="480" stroke="#10b981" strokeWidth="3" />
            <text x="670" y="487" fill="#d8d5cd" fontSize="18" fontWeight="700">
              From dynamic analysis
            </text>
          </g>
        </svg>
      </div>

      <p className="text-[0.65rem] font-mono text-muted uppercase tracking-widest leading-relaxed">
        A matched IOC ties static code evidence to runtime behavior; static-only and runtime-only indicators show where the investigation needs deeper review.
      </p>
    </div>
  );
}
