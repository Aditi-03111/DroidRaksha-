"use client";
import { useState, useEffect, useCallback, useRef } from "react";
import { ChevronRight, ChevronDown, Folder, FolderOpen, File, AlertTriangle, Package, List, GitBranch, Network, X } from "lucide-react";

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

/* ─── Scattered Dropdown View ────────────────────────────────────────── */

interface ActiveScatteredNode {
  id: string; // path
  node: TreeNode;
  parentId: string | null;
  x: number;
  y: number;
}

function ScatteredView({ tree }: { tree: TreeNode[] }) {
  const containerRef = useRef<HTMLDivElement>(null);
  const [dimensions, setDimensions] = useState({ w: 800, h: 600 });
  const [pan, setPan] = useState({ x: 0, y: 0 });
  const [isDraggingCanvas, setIsDraggingCanvas] = useState(false);
  const dragStart = useRef({ x: 0, y: 0 });

  const rootNode: TreeNode = {
    name: "APK Root",
    path: "/",
    type: "dir",
    children: tree,
    suspicious: tree.some(n => n.suspicious)
  };

  const [activeNodes, setActiveNodes] = useState<ActiveScatteredNode[]>([]);
  const [expandedDropdowns, setExpandedDropdowns] = useState<Set<string>>(new Set(["/"]));

  useEffect(() => {
    if (containerRef.current) {
      const rect = containerRef.current.getBoundingClientRect();
      setDimensions({ w: rect.width, h: 500 });
      // Initialize root in center
      setActiveNodes([
        { id: "/", node: rootNode, parentId: null, x: rect.width / 4, y: 250 }
      ]);
    }
  }, []);

  const handlePointerDownCanvas = (e: React.PointerEvent) => {
    if (e.target !== containerRef.current && (e.target as HTMLElement).tagName !== "svg") return;
    setIsDraggingCanvas(true);
    dragStart.current = { x: e.clientX - pan.x, y: e.clientY - pan.y };
    (e.target as HTMLElement).setPointerCapture(e.pointerId);
  };

  const handlePointerMoveCanvas = (e: React.PointerEvent) => {
    if (!isDraggingCanvas) return;
    setPan({
      x: e.clientX - dragStart.current.x,
      y: e.clientY - dragStart.current.y
    });
  };

  const handlePointerUpCanvas = (e: React.PointerEvent) => {
    setIsDraggingCanvas(false);
    (e.target as HTMLElement).releasePointerCapture(e.pointerId);
  };

  const toggleDropdown = (id: string) => {
    setExpandedDropdowns(prev => {
      const next = new Set(prev);
      if (next.has(id)) next.delete(id);
      else next.add(id);
      return next;
    });
  };

  const spawnChildNode = (child: TreeNode, parentNode: ActiveScatteredNode) => {
    // If already exists, just highlight it or do nothing
    if (activeNodes.find(n => n.id === child.path)) return;

    const angle = (Math.random() - 0.5) * Math.PI; // -90 to +90 deg
    const distance = 250 + Math.random() * 100;
    
    // Spawn to the right of parent with some random scatter
    const newX = parentNode.x + Math.cos(angle * 0.5) * distance;
    const newY = parentNode.y + Math.sin(angle * 0.5) * distance;

    setActiveNodes(prev => [...prev, {
      id: child.path,
      node: child,
      parentId: parentNode.id,
      x: newX,
      y: newY
    }]);
    
    // Auto expand the newly spawned folder dropdown
    setExpandedDropdowns(prev => {
      const next = new Set(prev);
      next.add(child.path);
      return next;
    });
  };

  const removeNode = (id: string) => {
    // recursively remove this node and all descendants
    const getDescendants = (parentId: string, current: string[] = []): string[] => {
      const children = activeNodes.filter(n => n.parentId === parentId);
      children.forEach(c => {
        current.push(c.id);
        getDescendants(c.id, current);
      });
      return current;
    };
    const toRemove = new Set([id, ...getDescendants(id)]);
    setActiveNodes(prev => prev.filter(n => !toRemove.has(n.id)));
  };

  return (
    <div 
      ref={containerRef}
      className={`relative w-full h-[500px] overflow-hidden bg-[rgba(15,23,42,0.8)] border-t border-slate-700/50 ${isDraggingCanvas ? "cursor-grabbing" : "cursor-grab"}`}
      onPointerDown={handlePointerDownCanvas}
      onPointerMove={handlePointerMoveCanvas}
      onPointerUp={handlePointerUpCanvas}
    >
      {/* Background Grid for visual context */}
      <div 
        className="absolute inset-0 pointer-events-none opacity-20"
        style={{
          backgroundImage: "radial-gradient(#475569 1px, transparent 1px)",
          backgroundSize: "30px 30px",
          backgroundPosition: `${pan.x}px ${pan.y}px`
        }}
      />

      {/* SVG for connecting lines */}
      <svg className="absolute inset-0 pointer-events-none z-0" style={{ transform: `translate(${pan.x}px, ${pan.y}px)` }}>
        {activeNodes.map(node => {
          if (!node.parentId) return null;
          const parent = activeNodes.find(n => n.id === node.parentId);
          if (!parent) return null;
          
          // Draw curved line from parent to child
          const startX = parent.x + 100; // approximate center right of parent card
          const startY = parent.y;
          const endX = node.x - 100; // approximate center left of child card
          const endY = node.y;

          return (
            <path
              key={`${node.parentId}-${node.id}`}
              d={`M ${startX} ${startY} C ${startX + 100} ${startY}, ${endX - 100} ${endY}, ${endX} ${endY}`}
              fill="none"
              stroke={node.node.suspicious ? "rgba(244,63,94,0.4)" : "rgba(148,163,184,0.3)"}
              strokeWidth={node.node.suspicious ? 2 : 1.5}
            />
          );
        })}
      </svg>

      {/* Nodes */}
      <div className="absolute inset-0 pointer-events-none" style={{ transform: `translate(${pan.x}px, ${pan.y}px)` }}>
        {activeNodes.map(activeNode => {
          const { id, node, x, y } = activeNode;
          const isExpanded = expandedDropdowns.has(id);

          return (
            <div
              key={id}
              className={`absolute pointer-events-auto flex flex-col items-center select-none shadow-xl`}
              style={{
                left: x,
                top: y,
                transform: "translate(-50%, -50%)",
                width: 260
              }}
            >
              {/* Node Header Card */}
              <div 
                className={`
                  w-full flex items-center justify-between gap-2 px-3 py-2 rounded-lg border text-sm font-mono z-10 cursor-pointer
                  transition-colors backdrop-blur-md
                  ${node.suspicious 
                    ? "bg-rose-950/80 border-rose-500 shadow-[0_0_15px_rgba(244,63,94,0.3)] text-rose-200" 
                    : "bg-slate-800/95 border-slate-600 text-slate-100 hover:border-indigo-400"
                  }
                `}
                onClick={() => toggleDropdown(id)}
              >
                <div className="flex items-center gap-2 truncate">
                  <FolderOpen className={`w-4 h-4 flex-shrink-0 ${node.suspicious ? "text-rose-400" : "text-yellow-400"}`} />
                  <span className="truncate font-semibold">{node.name}</span>
                </div>
                <div className="flex items-center gap-1">
                  {id !== "/" && (
                    <button 
                      onClick={(e) => { e.stopPropagation(); removeNode(id); }}
                      className="p-1 hover:bg-white/10 rounded-full transition-colors text-slate-400 hover:text-white"
                    >
                      <X className="w-3 h-3" />
                    </button>
                  )}
                  <ChevronDown className={`w-4 h-4 transition-transform ${isExpanded ? "rotate-180" : ""}`} />
                </div>
              </div>

              {/* Node Content Dropdown */}
              {isExpanded && node.children && (
                <div className="w-full mt-2 bg-slate-900/95 border border-slate-700/80 rounded-lg overflow-hidden shadow-2xl z-20 max-h-64 overflow-y-auto scrollbar-thin scrollbar-thumb-slate-600 backdrop-blur-xl">
                  {node.children.map((child, idx) => {
                    const isDir = child.type === "dir";
                    const extInfo = child.ext ? EXT_ICONS[child.ext] : null;
                    const isSpawned = isDir && activeNodes.some(n => n.id === child.path);

                    return (
                      <div 
                        key={child.path}
                        className={`
                          flex items-center justify-between px-3 py-2 text-xs font-mono border-b border-slate-800/50 last:border-0
                          ${child.suspicious ? "bg-rose-500/10 hover:bg-rose-500/20" : "hover:bg-slate-800/80"}
                          ${isDir ? "cursor-pointer" : ""}
                        `}
                        onClick={() => {
                          if (isDir) spawnChildNode(child, activeNode);
                        }}
                      >
                        <div className="flex items-center gap-2 truncate">
                          {isDir ? (
                            <Folder className={`w-3.5 h-3.5 flex-shrink-0 ${child.suspicious ? "text-rose-400" : "text-yellow-500"}`} />
                          ) : extInfo ? (
                            <span className={`text-[11px] leading-none ${extInfo.color}`}>{extInfo.icon}</span>
                          ) : (
                            <File className="w-3 h-3 text-slate-400 flex-shrink-0" />
                          )}
                          <span className={`truncate ${child.suspicious ? "text-rose-300 font-bold" : "text-slate-300"} ${isSpawned ? "opacity-50 line-through" : ""}`}>
                            {child.name}
                          </span>
                        </div>
                        
                        <div className="flex items-center gap-2 flex-shrink-0">
                          {child.suspicious && <AlertTriangle className="w-3 h-3 text-rose-500" title={child.warning} />}
                          {!isDir && child.size != null && <span className="text-[9px] text-slate-500">{formatBytes(child.size)}</span>}
                          {isDir && !isSpawned && <ChevronRight className="w-3 h-3 text-slate-500" />}
                        </div>
                      </div>
                    );
                  })}
                  {node.children.length === 0 && (
                    <div className="px-3 py-3 text-xs text-slate-500 text-center italic">Empty directory</div>
                  )}
                </div>
              )}
            </div>
          );
        })}
      </div>
      
      {/* Legend / Info */}
      <div className="absolute bottom-4 left-4 bg-black/50 border border-white/10 px-3 py-2 rounded-lg backdrop-blur-md pointer-events-none">
        <p className="text-xs text-slate-300 font-mono flex items-center gap-2">
          <span className="w-2 h-2 rounded-full bg-blue-500 inline-block animate-pulse"></span>
          Click folders in dropdowns to expand them on canvas
        </p>
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
  const [viewMode, setViewMode] = useState<"list" | "scattered">("scattered");

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
              onClick={() => setViewMode("scattered")}
              className={`flex items-center gap-1.5 px-3 py-1.5 text-[0.65rem] font-mono uppercase tracking-wider transition-all ${
                viewMode === "scattered"
                  ? "bg-white/10 text-white"
                  : "text-slate-400 hover:text-slate-200"
              }`}
            >
              <Network className="w-3 h-3" />
              Scattered
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
        <ScatteredView tree={data.tree} />
      )}
    </div>
  );
}
