"use client";
import { useState, useEffect, useCallback, useRef } from "react";
import { ChevronRight, ChevronDown, Folder, FolderOpen, File, AlertTriangle, Package, List, GitBranch, Network } from "lucide-react";

interface TreeNode {
  name: string;
  path: string;
  type: "file" | "dir";
  size?: number;
  ext?: string;
  suspicious?: boolean;
  warning?: string;
  children?: TreeNode[];
}

interface FileTreeStats {
  total_files: number;
  total_size_bytes: number;
  dex_count: number;
  dex_files: string[];
  native_libs: number;
  suspicious_count: number;
  suspicious_files: string[];
}

interface FileTreeData {
  tree: TreeNode[];
  stats: FileTreeStats;
  error?: string | null;
}

const EXT_ICONS: Record<string, { icon: string; color: string }> = {
  ".dex": { icon: "⚙️", color: "text-blue-400" },
  ".so":  { icon: "🔧", color: "text-orange-400" },
  ".xml": { icon: "📋", color: "text-green-400" },
  ".png": { icon: "🖼️", color: "text-purple-400" },
  ".jpg": { icon: "🖼️", color: "text-purple-400" },
  ".json":{ icon: "📄", color: "text-yellow-400" },
  ".jar": { icon: "☕", color: "text-red-400" },
  ".bin": { icon: "💾", color: "text-rose-400" },
  ".enc": { icon: "🔒", color: "text-rose-500" },
  ".dat": { icon: "📦", color: "text-slate-200" },
};

function formatBytes(b: number) {
  if (b < 1024) return `${b} B`;
  if (b < 1024 * 1024) return `${(b / 1024).toFixed(1)} KB`;
  return `${(b / 1024 / 1024).toFixed(2)} MB`;
}

/* ─── List View (existing) ───────────────────────────────────────────── */

function TreeNodeView({
  node,
  depth = 0,
}: {
  node: TreeNode;
  depth?: number;
}) {
  const [open, setOpen] = useState(depth < 2);
  const isDir = node.type === "dir";
  const extInfo = node.ext ? EXT_ICONS[node.ext] : null;

  return (
    <div className={`select-none ${depth > 0 ? "ml-4" : ""}`}>
      <div
        className={`
          flex items-center gap-1.5 py-[3px] px-2 rounded-md cursor-pointer group
          transition-colors text-sm
          ${node.suspicious
            ? "bg-rose-500/8 hover:bg-rose-500/15 text-rose-300"
            : "hover:bg-slate-700/40 text-slate-300"
          }
        `}
        onClick={() => isDir && setOpen((o) => !o)}
      >
        {depth > 0 && (
          <span className="text-slate-300 select-none" style={{ marginLeft: `${(depth - 1) * 12}px` }} />
        )}

        {isDir ? (
          <span className="text-slate-300 w-3.5 flex-shrink-0">
            {open ? <ChevronDown className="w-3 h-3" /> : <ChevronRight className="w-3 h-3" />}
          </span>
        ) : (
          <span className="w-3.5 flex-shrink-0" />
        )}

        {isDir ? (
          open ? (
            <FolderOpen className="w-3.5 h-3.5 text-yellow-400 flex-shrink-0" />
          ) : (
            <Folder className="w-3.5 h-3.5 text-yellow-500 flex-shrink-0" />
          )
        ) : extInfo ? (
          <span className={`text-[11px] leading-none ${extInfo.color}`}>{extInfo.icon}</span>
        ) : (
          <File className="w-3 h-3 text-slate-300 flex-shrink-0" />
        )}

        <span className={`truncate font-mono text-xs ${node.suspicious ? "text-rose-300 font-semibold" : ""}`}>
          {node.name}
        </span>

        {node.size != null && (
          <span className="ml-auto text-[10px] text-slate-200 flex-shrink-0">
            {formatBytes(node.size)}
          </span>
        )}

        {node.suspicious && (
          <span className="ml-1 flex-shrink-0" title={node.warning}>
            <AlertTriangle className="w-3 h-3 text-rose-400" />
          </span>
        )}
      </div>

      {node.suspicious && node.warning && (
        <div className="ml-8 mb-1 text-[11px] text-rose-400/80 bg-rose-500/5 border border-rose-500/15 rounded px-2 py-1">
          ⚠️ {node.warning}
        </div>
      )}

      {isDir && open && node.children && node.children.length > 0 && (
        <div>
          {node.children.map((child) => (
            <TreeNodeView key={child.path} node={child} depth={depth + 1} />
          ))}
        </div>
      )}
    </div>
  );
}

/* ─── Flowchart View (Horizontal Interactive Tree) ────────────────────── */

function FlowchartNode({ node, depth = 0 }: { node: TreeNode; depth?: number }) {
  // Auto-expand the first couple of levels
  const [expanded, setExpanded] = useState(depth < 1);
  const isDir = node.type === "dir";
  const hasChildren = isDir && node.children && node.children.length > 0;
  const extInfo = node.ext ? EXT_ICONS[node.ext] : null;

  return (
    <div className="flex items-center">
      {/* Node Card */}
      <div 
        className={`
          flex items-center gap-2 px-3 py-2 rounded-lg border text-xs font-mono whitespace-nowrap
          transition-all duration-300 relative z-10 select-none
          ${node.suspicious 
            ? "bg-[rgba(244,63,94,0.1)] border-[#f43f5e] text-[#fda4af] shadow-[0_0_10px_rgba(244,63,94,0.2)]" 
            : "bg-slate-800/80 border-slate-700/60 text-slate-200 hover:border-slate-500"
          }
          ${hasChildren ? "cursor-pointer hover:bg-slate-700/80" : ""}
        `}
        onClick={() => hasChildren && setExpanded(!expanded)}
      >
        {isDir ? (
          <FolderOpen className={`w-3.5 h-3.5 ${node.suspicious ? "text-[#f43f5e]" : "text-yellow-400"}`} />
        ) : extInfo ? (
          <span className={`text-[11px] leading-none ${extInfo.color}`}>{extInfo.icon}</span>
        ) : (
          <File className="w-3 h-3 text-slate-400" />
        )}
        
        <span className={node.suspicious ? "font-bold" : ""}>{node.name}</span>
        
        {hasChildren && (
          <span className="ml-2 text-[0.6rem] bg-black/30 px-1.5 py-0.5 rounded text-slate-400">
            {node.children!.length}
          </span>
        )}

        {node.suspicious && (
          <AlertTriangle className="w-3 h-3 text-[#f43f5e] ml-1" />
        )}
      </div>
      
      {/* Connecting lines and children */}
      {hasChildren && expanded && (
        <div className="flex items-center">
          {/* Horizontal line from parent */}
          <div className="w-6 h-px bg-slate-600"></div>
          
          {/* Vertical spine and children list */}
          <div className="flex flex-col relative py-2 gap-3 border-l border-slate-600 pl-6 ml-[-1px]">
            {node.children!.map((child, idx) => (
              <div key={child.path} className="relative flex items-center">
                {/* Horizontal line to child */}
                <div className="absolute w-6 h-px bg-slate-600 left-[-24px] top-1/2 -translate-y-1/2"></div>
                
                {/* Hide the vertical border overflow for first/last items */}
                {idx === 0 && <div className="absolute w-px bg-[rgba(15,23,42,1)] left-[-1px] top-0 bottom-1/2 z-0"></div>}
                {idx === node.children!.length - 1 && <div className="absolute w-px bg-[rgba(15,23,42,1)] left-[-1px] top-1/2 bottom-0 z-0"></div>}
                
                <FlowchartNode node={child} depth={depth + 1} />
              </div>
            ))}
          </div>
        </div>
      )}
    </div>
  );
}

function FlowchartView({ tree }: { tree: TreeNode[] }) {
  // Wrap the top-level files in a single root node if there are many
  const rootNode: TreeNode = {
    name: "APK Root",
    path: "/",
    type: "dir",
    children: tree,
    suspicious: tree.some(n => n.suspicious)
  };

  return (
    <div className="p-6 overflow-auto min-h-[400px] max-h-[600px] scrollbar-thin scrollbar-track-transparent scrollbar-thumb-slate-700 bg-[rgba(15,23,42,0.6)]">
      <div className="min-w-max pb-8">
        <FlowchartNode node={rootNode} depth={0} />
      </div>
    </div>
  );
}

/* ─── Main Component ─────────────────────────────────────────────────── */

interface APKFileTreeProps {
  analysisId: string;
}

export default function APKFileTree({ analysisId }: APKFileTreeProps) {
  const [data, setData] = useState<FileTreeData | null>(null);
  const [loading, setLoading] = useState(true);
  const [search, setSearch] = useState("");
  const [viewMode, setViewMode] = useState<"list" | "flowchart">("list");

  const fetchTree = useCallback(async () => {
    try {
      const res = await fetch(
        `${process.env.NEXT_PUBLIC_API_URL || "http://localhost:8000"}/api/analysis/${analysisId}/filetree`
      );
      if (res.ok) setData(await res.json());
    } catch {
      setData({ tree: [], stats: {} as FileTreeStats, error: "Failed to load file tree" });
    } finally {
      setLoading(false);
    }
  }, [analysisId]);

  useEffect(() => { fetchTree(); }, [fetchTree]);

  if (loading) {
    return (
      <div className="rounded-2xl border border-slate-700/40 bg-slate-900/60 p-6 animate-pulse">
        <div className="h-4 w-48 bg-slate-700/50 rounded mb-4" />
        <div className="space-y-2">
          {[...Array(8)].map((_, i) => (
            <div key={i} className="h-3 rounded bg-slate-800" style={{ width: `${60 + i * 5}%` }} />
          ))}
        </div>
      </div>
    );
  }

  if (!data || data.error) {
    return (
      <div className="rounded-2xl border border-slate-700/40 bg-slate-900/60 p-6 text-center text-slate-300 text-sm">
        <Package className="w-8 h-8 mx-auto mb-2 text-slate-200" />
        {data?.error || "File tree unavailable"}
      </div>
    );
  }

  const stats = data.stats;

  return (
    <div className="rounded-2xl border border-slate-700/40 bg-slate-900/60 overflow-hidden">
      {/* Header */}
      <div className="border-b border-slate-700/40 px-5 py-4 flex items-center justify-between gap-3 flex-wrap">
        <div className="flex items-center gap-2">
          <Folder className="w-4 h-4 text-yellow-400" />
          <span className="font-semibold text-slate-100 text-sm">APK File Structure</span>
          {stats.suspicious_count > 0 && (
            <span className="px-2 py-0.5 rounded-full text-[10px] font-bold bg-rose-500/15 text-rose-400 border border-rose-500/25">
              ⚠️ {stats.suspicious_count} suspicious
            </span>
          )}
        </div>
        <div className="flex items-center gap-4">
          {/* View toggle */}
          <div className="flex items-center bg-slate-800/80 border border-slate-700/50 rounded-lg overflow-hidden">
            <button
              onClick={() => setViewMode("list")}
              className={`flex items-center gap-1.5 px-3 py-1.5 text-[0.65rem] font-mono uppercase tracking-wider transition-all ${
                viewMode === "list"
                  ? "bg-white/10 text-white"
                  : "text-slate-400 hover:text-slate-200"
              }`}
            >
              <List className="w-3 h-3" />
              List
            </button>
            <button
              onClick={() => setViewMode("flowchart")}
              className={`flex items-center gap-1.5 px-3 py-1.5 text-[0.65rem] font-mono uppercase tracking-wider transition-all ${
                viewMode === "flowchart"
                  ? "bg-white/10 text-white"
                  : "text-slate-400 hover:text-slate-200"
              }`}
            >
              <Network className="w-3 h-3" />
              Flowchart
            </button>
          </div>
          <div className="flex items-center gap-3 text-xs text-slate-300">
            <span><span className="text-slate-300 font-semibold">{stats.total_files}</span> files</span>
            <span className="text-slate-300">·</span>
            <span><span className="text-blue-400 font-semibold">{stats.dex_count}</span> DEX</span>
            <span className="text-slate-300">·</span>
            <span><span className="text-orange-400 font-semibold">{stats.native_libs}</span> .so libs</span>
            <span className="text-slate-300">·</span>
            <span>{formatBytes(stats.total_size_bytes || 0)}</span>
          </div>
        </div>
      </div>

      {/* Suspicious files summary */}
      {stats.suspicious_count > 0 && (
        <div className="mx-4 mt-4 rounded-lg border border-rose-500/20 bg-rose-500/5 p-3">
          <div className="flex items-center gap-2 text-rose-400 text-xs font-semibold mb-1.5">
            <AlertTriangle className="w-3.5 h-3.5" />
            Suspicious Entries Detected
          </div>
          <div className="flex flex-wrap gap-1.5">
            {stats.suspicious_files?.map((f) => (
              <code key={f} className="text-[10px] bg-rose-500/10 text-rose-300 px-2 py-0.5 rounded font-mono">
                {f}
              </code>
            ))}
          </div>
        </div>
      )}

      {/* View content */}
      {viewMode === "list" ? (
        <>
          {/* Search */}
          <div className="px-4 pt-3 pb-2">
            <input
              type="text"
              placeholder="Filter files…"
              value={search}
              onChange={(e) => setSearch(e.target.value)}
              className="w-full px-3 py-1.5 rounded-lg text-xs bg-slate-800/80 border border-slate-700/50 text-slate-300 placeholder-slate-600 outline-none focus:border-indigo-500/40"
            />
          </div>

          {/* Tree */}
          <div className="px-3 pb-4 max-h-96 overflow-y-auto scrollbar-thin scrollbar-track-transparent scrollbar-thumb-slate-700">
            {data.tree.length === 0 ? (
              <p className="text-center text-slate-200 text-xs py-8">No files found</p>
            ) : (
              data.tree.map((node) => (
                <TreeNodeView key={node.path} node={node} depth={0} />
              ))
            )}
          </div>
        </>
      ) : (
        <FlowchartView tree={data.tree} />
      )}
    </div>
  );
}
