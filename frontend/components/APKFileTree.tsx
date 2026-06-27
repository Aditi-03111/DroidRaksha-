"use client";
import { useState, useEffect, useCallback, useRef } from "react";
import { ChevronRight, ChevronDown, Folder, FolderOpen, File, AlertTriangle, Package, List, GitBranch } from "lucide-react";

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

const EXT_COLORS: Record<string, string> = {
  ".dex": "#60a5fa",
  ".so":  "#fb923c",
  ".xml": "#4ade80",
  ".png": "#c084fc",
  ".jpg": "#c084fc",
  ".json": "#facc15",
  ".jar": "#f87171",
  ".bin": "#fb7185",
  ".enc": "#f43f5e",
  ".dat": "#e2e8f0",
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

/* ─── Graph View (new visual tree) ───────────────────────────────────── */

interface GraphNode {
  id: string;
  name: string;
  x: number;
  y: number;
  parentId: string | null;
  isDir: boolean;
  suspicious: boolean;
  ext?: string;
  depth: number;
  childCount: number;
}

function flattenTree(nodes: TreeNode[], parentId: string | null = null, depth = 0): GraphNode[] {
  const result: GraphNode[] = [];
  for (const node of nodes) {
    const id = node.path;
    result.push({
      id,
      name: node.name,
      x: 0,
      y: 0,
      parentId,
      isDir: node.type === "dir",
      suspicious: !!node.suspicious,
      ext: node.ext,
      depth,
      childCount: node.children?.length ?? 0,
    });
    if (node.children && depth < 3) {
      result.push(...flattenTree(node.children, id, depth + 1));
    }
  }
  return result;
}

function GraphView({ tree }: { tree: TreeNode[] }) {
  const canvasRef = useRef<HTMLCanvasElement>(null);
  const containerRef = useRef<HTMLDivElement>(null);
  const [hoveredNode, setHoveredNode] = useState<GraphNode | null>(null);
  const [graphNodes, setGraphNodes] = useState<GraphNode[]>([]);
  const [dimensions, setDimensions] = useState({ w: 800, h: 600 });

  useEffect(() => {
    if (!containerRef.current) return;
    const rect = containerRef.current.getBoundingClientRect();
    setDimensions({ w: rect.width, h: Math.max(500, rect.width * 0.65) });
  }, []);

  useEffect(() => {
    const flat = flattenTree(tree);
    const { w, h } = dimensions;
    const cx = w / 2;
    const cy = h / 2;

    // Layout: root at center, children in concentric rings
    const byDepth: Record<number, GraphNode[]> = {};
    for (const n of flat) {
      (byDepth[n.depth] ??= []).push(n);
    }

    // Root node
    const roots = byDepth[0] || [];
    const rootNode: GraphNode = {
      id: "__root__",
      name: "APK",
      x: cx,
      y: cy,
      parentId: null,
      isDir: true,
      suspicious: false,
      depth: -1,
      childCount: roots.length,
    };

    const positioned: GraphNode[] = [rootNode];

    // Position depth-0 nodes in a ring around center
    const ringRadii = [0, Math.min(w, h) * 0.18, Math.min(w, h) * 0.32, Math.min(w, h) * 0.44];

    for (const [depthStr, nodes] of Object.entries(byDepth)) {
      const depth = parseInt(depthStr);
      const radius = ringRadii[depth + 1] || ringRadii[ringRadii.length - 1];

      // Group children by parent
      const parentGroups: Record<string, GraphNode[]> = {};
      for (const n of nodes) {
        const pid = n.parentId ?? "__root__";
        (parentGroups[pid] ??= []).push(n);
      }

      // Position each group
      for (const [pid, children] of Object.entries(parentGroups)) {
        const parent = positioned.find((p) => p.id === pid) ?? rootNode;
        const parentAngle = Math.atan2(parent.y - cy, parent.x - cx);
        const spread = Math.min(Math.PI * 2, (children.length * 0.25));
        const startAngle = depth === 0 ? 0 : parentAngle - spread / 2;

        children.forEach((child, i) => {
          const angle = depth === 0
            ? (i / children.length) * Math.PI * 2 - Math.PI / 2
            : startAngle + (i / Math.max(children.length - 1, 1)) * spread;
          const jitter = (Math.random() - 0.5) * 10;
          child.x = cx + Math.cos(angle) * (radius + jitter);
          child.y = cy + Math.sin(angle) * (radius + jitter);
          child.parentId = pid;
          positioned.push(child);
        });
      }
    }

    setGraphNodes(positioned);
  }, [tree, dimensions]);

  // Draw
  useEffect(() => {
    const canvas = canvasRef.current;
    if (!canvas || graphNodes.length === 0) return;
    const ctx = canvas.getContext("2d");
    if (!ctx) return;

    const dpr = window.devicePixelRatio || 1;
    canvas.width = dimensions.w * dpr;
    canvas.height = dimensions.h * dpr;
    ctx.scale(dpr, dpr);

    // Clear
    ctx.clearRect(0, 0, dimensions.w, dimensions.h);

    // Draw concentric ring guides
    const cx = dimensions.w / 2;
    const cy = dimensions.h / 2;
    const ringRadii = [
      Math.min(dimensions.w, dimensions.h) * 0.18,
      Math.min(dimensions.w, dimensions.h) * 0.32,
      Math.min(dimensions.w, dimensions.h) * 0.44,
    ];
    for (const r of ringRadii) {
      ctx.beginPath();
      ctx.arc(cx, cy, r, 0, Math.PI * 2);
      ctx.strokeStyle = "rgba(255,255,255,0.04)";
      ctx.lineWidth = 1;
      ctx.stroke();
    }

    // Draw edges
    for (const node of graphNodes) {
      if (!node.parentId) continue;
      const parent = graphNodes.find((n) => n.id === node.parentId);
      if (!parent) continue;

      ctx.beginPath();
      ctx.moveTo(parent.x, parent.y);
      ctx.lineTo(node.x, node.y);
      ctx.strokeStyle = node.suspicious
        ? "rgba(244, 63, 94, 0.4)"
        : "rgba(148, 163, 184, 0.12)";
      ctx.lineWidth = node.suspicious ? 1.5 : 0.5;
      ctx.stroke();
    }

    // Draw nodes
    for (const node of graphNodes) {
      const isHovered = hoveredNode?.id === node.id;
      const r = node.id === "__root__" ? 10 : node.isDir ? 6 : 4;

      // Glow for suspicious
      if (node.suspicious) {
        ctx.beginPath();
        ctx.arc(node.x, node.y, r + 4, 0, Math.PI * 2);
        const glow = ctx.createRadialGradient(node.x, node.y, r, node.x, node.y, r + 8);
        glow.addColorStop(0, "rgba(244, 63, 94, 0.3)");
        glow.addColorStop(1, "rgba(244, 63, 94, 0)");
        ctx.fillStyle = glow;
        ctx.fill();
      }

      // Node circle
      ctx.beginPath();
      ctx.arc(node.x, node.y, r, 0, Math.PI * 2);

      if (node.id === "__root__") {
        ctx.fillStyle = "#ffffff";
      } else if (node.suspicious) {
        ctx.fillStyle = "#f43f5e";
      } else if (node.isDir) {
        ctx.fillStyle = "#facc15";
      } else {
        ctx.fillStyle = (node.ext && EXT_COLORS[node.ext]) || "#64748b";
      }
      ctx.fill();

      // Border
      if (isHovered) {
        ctx.strokeStyle = "#ffffff";
        ctx.lineWidth = 2;
        ctx.stroke();
      }

      // Label for root, dirs, and hovered
      if (node.id === "__root__" || (node.isDir && node.depth <= 1) || isHovered) {
        ctx.font = `${node.id === "__root__" ? "bold 11px" : "10px"} monospace`;
        ctx.fillStyle = node.suspicious ? "#fda4af" : "#e2e8f0";
        ctx.textAlign = "center";
        ctx.fillText(node.name, node.x, node.y - r - 5);
      }
    }
  }, [graphNodes, hoveredNode, dimensions]);

  // Mouse hover
  const handleMouseMove = useCallback(
    (e: React.MouseEvent<HTMLCanvasElement>) => {
      const canvas = canvasRef.current;
      if (!canvas) return;
      const rect = canvas.getBoundingClientRect();
      const mx = e.clientX - rect.left;
      const my = e.clientY - rect.top;

      let closest: GraphNode | null = null;
      let minDist = 20;
      for (const n of graphNodes) {
        const d = Math.hypot(n.x - mx, n.y - my);
        if (d < minDist) {
          closest = n;
          minDist = d;
        }
      }
      setHoveredNode(closest);
    },
    [graphNodes]
  );

  return (
    <div ref={containerRef} className="relative">
      <canvas
        ref={canvasRef}
        style={{ width: dimensions.w, height: dimensions.h }}
        className="w-full cursor-crosshair"
        onMouseMove={handleMouseMove}
        onMouseLeave={() => setHoveredNode(null)}
      />
      {/* Tooltip */}
      {hoveredNode && hoveredNode.id !== "__root__" && (
        <div
          className="absolute pointer-events-none bg-black/90 border border-[rgba(255,255,255,0.2)] px-3 py-2 text-[0.65rem] font-mono z-20 rounded"
          style={{
            left: Math.min(hoveredNode.x, dimensions.w - 200),
            top: hoveredNode.y + 15,
          }}
        >
          <p className={`font-bold ${hoveredNode.suspicious ? "text-[#f43f5e]" : "text-white"}`}>
            {hoveredNode.name}
          </p>
          <p className="text-[#94a3b8]">
            {hoveredNode.isDir ? `📁 Directory · ${hoveredNode.childCount} items` : `📄 File`}
          </p>
          {hoveredNode.suspicious && (
            <p className="text-[#f43f5e] mt-1">⚠️ Suspicious entry</p>
          )}
        </div>
      )}
      {/* Legend */}
      <div className="absolute bottom-3 right-3 flex gap-3 text-[0.6rem] font-mono text-[#94a3b8] bg-black/50 p-2 rounded">
        <span className="flex items-center gap-1"><span className="w-2 h-2 rounded-full bg-[#facc15]" /> Dir</span>
        <span className="flex items-center gap-1"><span className="w-2 h-2 rounded-full bg-[#60a5fa]" /> DEX</span>
        <span className="flex items-center gap-1"><span className="w-2 h-2 rounded-full bg-[#fb923c]" /> .so</span>
        <span className="flex items-center gap-1"><span className="w-2 h-2 rounded-full bg-[#f43f5e]" /> Suspicious</span>
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
  const [viewMode, setViewMode] = useState<"list" | "graph">("list");

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
              onClick={() => setViewMode("graph")}
              className={`flex items-center gap-1.5 px-3 py-1.5 text-[0.65rem] font-mono uppercase tracking-wider transition-all ${
                viewMode === "graph"
                  ? "bg-white/10 text-white"
                  : "text-slate-400 hover:text-slate-200"
              }`}
            >
              <GitBranch className="w-3 h-3" />
              Graph
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
        <div className="p-2 border-t border-slate-700/40">
          <GraphView tree={data.tree} />
        </div>
      )}
    </div>
  );
}
