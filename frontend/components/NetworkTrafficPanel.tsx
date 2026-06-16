"use client";

import { useState, useRef } from "react";
import {
  Globe, Wifi, AlertTriangle, Shield, Upload,
  ChevronDown, ChevronUp, Activity, Search, Zap,
  Radio, Server, Lock
} from "lucide-react";

// ── Types ──────────────────────────────────────────────────────────────────

interface DnsEntry   { domain: string; count: number; }
interface HttpHost   { host: string; count: number; }
interface RemoteIP   { ip: string; count: number; ports: number[]; first_seen: string; }
interface BeaconAlert {
  ip: string; contact_count: number; avg_interval_sec: number;
  jitter_cv: number; confidence: "HIGH" | "MEDIUM"; description: string;
}
interface DgaSuspect { domain: string; query_count: number; entropy: number; }
interface IocHit     { type: "ip" | "domain"; value: string; reason: string; severity: string; }

interface NetworkSummary {
  total_packets: number; parse_errors: number; unique_remote_ips: number;
  dns_query_count: number; http_host_count: number; tls_sni_count: number;
  beaconing_alerts: number; dga_suspects: number; india_hits: number;
}

interface NetworkData {
  available: boolean; error?: string; pcap_risk: string;
  summary: NetworkSummary; dns_queries: DnsEntry[]; http_hosts: HttpHost[];
  tls_sni: string[]; remote_ips: RemoteIP[]; beaconing_alerts: BeaconAlert[];
  dga_suspects: DgaSuspect[]; india_ioc_hits: IocHit[];
}

interface Props {
  analysisId: string;
  initialNetwork?: NetworkData | null;
}

// ── Helpers ─────────────────────────────────────────────────────────────────

const API_BASE = process.env.NEXT_PUBLIC_API_URL ?? "http://localhost:8000/api";

const riskColor = (risk: string) => ({
  CRITICAL: "text-red-400 bg-red-500/10 border-red-500/30",
  HIGH:     "text-orange-400 bg-orange-500/10 border-orange-500/30",
  MEDIUM:   "text-yellow-400 bg-yellow-500/10 border-yellow-500/30",
  LOW:      "text-green-400 bg-green-500/10 border-green-500/30",
}[risk] ?? "text-slate-400 bg-slate-800 border-slate-700");

const portLabel = (p: number) =>
  ({80:"HTTP",443:"HTTPS",53:"DNS",22:"SSH",21:"FTP",
    8080:"HTTP-Alt",3306:"MySQL",5432:"PG",6379:"Redis",
    4444:"C2?",1337:"C2?",31337:"C2?"})[p] ?? String(p);

// ── Expandable Table ────────────────────────────────────────────────────────

function ExpandableTable({
  title, icon, badge, badgeColor, children, defaultExpanded = true,
}: {
  title: string; icon: React.ReactNode; badge?: string | number;
  badgeColor?: string; children: React.ReactNode; defaultExpanded?: boolean;
}) {
  const [open, setOpen] = useState(defaultExpanded);
  return (
    <div className="rounded-xl border border-slate-700/40 bg-slate-900/60 overflow-hidden">
      <button
        onClick={() => setOpen(!open)}
        className="w-full flex items-center justify-between px-4 py-3 hover:bg-slate-800/40 transition-colors"
      >
        <div className="flex items-center gap-2 text-sm font-semibold text-slate-200">
          {icon}{title}
          {badge !== undefined && (
            <span className={`text-xs px-2 py-0.5 rounded-full font-bold border ${badgeColor ?? "bg-slate-800 text-slate-300 border-slate-700"}`}>
              {badge}
            </span>
          )}
        </div>
        {open ? <ChevronUp className="w-4 h-4 text-slate-500" /> : <ChevronDown className="w-4 h-4 text-slate-500" />}
      </button>
      {open && <div className="px-4 pb-4">{children}</div>}
    </div>
  );
}

// ── PCAP Upload Zone ────────────────────────────────────────────────────────

function PcapUploadZone({ analysisId, onSuccess }: { analysisId: string; onSuccess: (data: NetworkData) => void }) {
  const [dragging, setDragging] = useState(false);
  const [uploading, setUploading] = useState(false);
  const [progress, setProgress] = useState("");
  const [error, setError] = useState<string | null>(null);
  const inputRef = useRef<HTMLInputElement>(null);

  const handleFile = async (file: File) => {
    if (!file.name.match(/\.(pcap|pcapng)$/i)) {
      setError("Only .pcap and .pcapng files are accepted.");
      return;
    }
    setError(null);
    setUploading(true);
    setProgress("Uploading PCAP…");

    try {
      const form = new FormData();
      form.append("file", file);
      form.append("analysis_id", analysisId);

      const res = await fetch(`${API_BASE}/upload/pcap`, { method: "POST", body: form });
      if (!res.ok) {
        const err = await res.json();
        throw new Error(err.detail ?? "Upload failed");
      }
      const data = await res.json();
      setProgress("Analysis complete!");
      onSuccess(data.network as NetworkData);
    } catch (e: unknown) {
      setError(e instanceof Error ? e.message : "Upload failed");
    } finally {
      setUploading(false);
    }
  };

  return (
    <div
      className={`relative rounded-xl border-2 border-dashed p-10 flex flex-col items-center gap-4 transition-all cursor-pointer select-none
        ${dragging ? "border-indigo-500 bg-indigo-500/10" : "border-slate-700 hover:border-indigo-500/50 bg-slate-900/40"}`}
      onDragOver={(e) => { e.preventDefault(); setDragging(true); }}
      onDragLeave={() => setDragging(false)}
      onDrop={(e) => { e.preventDefault(); setDragging(false); const f = e.dataTransfer.files[0]; if (f) handleFile(f); }}
      onClick={() => inputRef.current?.click()}
    >
      <input ref={inputRef} type="file" accept=".pcap,.pcapng" className="hidden"
        onChange={(e) => { const f = e.target.files?.[0]; if (f) handleFile(f); }} />

      <div className="w-14 h-14 rounded-full bg-indigo-500/10 border border-indigo-500/20 flex items-center justify-center">
        {uploading
          ? <Activity className="w-6 h-6 text-indigo-400 animate-pulse" />
          : <Upload className="w-6 h-6 text-indigo-400" />}
      </div>

      <div className="text-center">
        <p className="text-slate-200 font-semibold text-sm">
          {uploading ? progress : "Upload PCAP for Network Analysis"}
        </p>
        <p className="text-slate-500 text-xs mt-1">
          {uploading ? "Analysing packets, detecting beaconing…"
            : "Drag & drop or click — .pcap / .pcapng up to 200 MB"}
        </p>
      </div>

      {error && (
        <div className="w-full bg-red-500/10 border border-red-500/30 rounded-lg px-4 py-2 text-red-400 text-xs text-center">
          {error}
        </div>
      )}
    </div>
  );
}

// ── Main Panel ──────────────────────────────────────────────────────────────

export default function NetworkTrafficPanel({ analysisId, initialNetwork }: Props) {
  const [network, setNetwork] = useState<NetworkData | null>(initialNetwork ?? null);
  const [search, setSearch] = useState("");

  if (!network) {
    return (
      <div className="space-y-4">
        <div className="flex items-center gap-2">
          <Globe className="w-5 h-5 text-indigo-400" />
          <h2 className="text-lg font-bold text-slate-100">Network Traffic Analysis</h2>
        </div>
        <p className="text-slate-400 text-sm">
          Upload a PCAP capture from this device to analyse network behavior,
          detect C2 beaconing, DGA domains, and India IOC matches.
        </p>
        <PcapUploadZone analysisId={analysisId} onSuccess={setNetwork} />
      </div>
    );
  }

  if (!network.available) {
    return (
      <div className="rounded-xl bg-slate-900/60 border border-slate-700/40 p-6 text-center space-y-2">
        <AlertTriangle className="w-8 h-8 text-yellow-400 mx-auto" />
        <p className="text-slate-300 font-medium">PCAP Analysis Unavailable</p>
        <p className="text-slate-500 text-xs">{network.error ?? "Unknown error"}</p>
      </div>
    );
  }

  const { summary, beaconing_alerts, dga_suspects, india_ioc_hits,
          dns_queries, http_hosts, remote_ips, tls_sni } = network;

  const filteredDns = dns_queries.filter(d =>
    !search || d.domain.toLowerCase().includes(search.toLowerCase()));
  const filteredIps = remote_ips.filter(r =>
    !search || r.ip.includes(search));

  return (
    <div className="space-y-5">
      {/* Header */}
      <div className="flex flex-wrap items-center justify-between gap-3">
        <div className="flex items-center gap-2">
          <Globe className="w-5 h-5 text-indigo-400" />
          <h2 className="text-lg font-bold text-slate-100">Network Traffic Analysis</h2>
          <span className={`text-xs font-bold px-2 py-0.5 rounded-full border ${riskColor(network.pcap_risk)}`}>
            {network.pcap_risk}
          </span>
        </div>
        <button
          onClick={() => setNetwork(null)}
          className="text-xs text-slate-500 hover:text-slate-300 underline transition-colors"
        >
          Upload new PCAP
        </button>
      </div>

      {/* Summary Cards */}
      <div className="grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-5 gap-3">
        {[
          { label: "Packets",      value: summary.total_packets.toLocaleString(),  icon: <Wifi className="w-3.5 h-3.5" />,      color: "text-indigo-400" },
          { label: "Remote IPs",   value: summary.unique_remote_ips,               icon: <Server className="w-3.5 h-3.5" />,    color: "text-blue-400" },
          { label: "DNS Queries",  value: summary.dns_query_count,                 icon: <Search className="w-3.5 h-3.5" />,    color: "text-cyan-400" },
          { label: "Beacons",      value: summary.beaconing_alerts,                icon: <Radio className="w-3.5 h-3.5" />,     color: summary.beaconing_alerts > 0 ? "text-red-400" : "text-green-400" },
          { label: "India IOC",    value: summary.india_hits,                      icon: <Shield className="w-3.5 h-3.5" />,    color: summary.india_hits > 0 ? "text-red-400" : "text-green-400" },
        ].map(card => (
          <div key={card.label} className="rounded-xl bg-slate-900/60 border border-slate-700/40 p-3 flex flex-col gap-1">
            <div className={`flex items-center gap-1.5 text-xs font-medium ${card.color}`}>
              {card.icon}{card.label}
            </div>
            <p className="text-xl font-bold text-slate-100">{card.value}</p>
          </div>
        ))}
      </div>

      {/* Beaconing Alerts */}
      {beaconing_alerts.length > 0 && (
        <ExpandableTable
          title="C2 Beaconing Alerts"
          icon={<Radio className="w-4 h-4 text-red-400" />}
          badge={beaconing_alerts.length}
          badgeColor="bg-red-500/10 text-red-400 border-red-500/30"
        >
          <div className="space-y-3 pt-1">
            {beaconing_alerts.map((a, i) => (
              <div key={i} className="rounded-lg bg-red-500/5 border border-red-500/20 p-3 space-y-1">
                <div className="flex items-center justify-between">
                  <span className="font-mono text-sm text-red-300 font-semibold">{a.ip}</span>
                  <span className={`text-xs px-2 py-0.5 rounded-full font-bold border ${
                    a.confidence === "HIGH"
                      ? "bg-red-500/10 text-red-400 border-red-500/30"
                      : "bg-orange-500/10 text-orange-400 border-orange-500/30"
                  }`}>
                    {a.confidence} CONFIDENCE
                  </span>
                </div>
                <p className="text-xs text-slate-400">{a.description}</p>
                <div className="flex gap-4 text-xs text-slate-500 font-mono">
                  <span>Contacts: {a.contact_count}</span>
                  <span>Interval: ~{a.avg_interval_sec}s</span>
                  <span>Jitter CV: {a.jitter_cv}</span>
                </div>
              </div>
            ))}
          </div>
        </ExpandableTable>
      )}

      {/* India IOC Hits */}
      {india_ioc_hits.length > 0 && (
        <ExpandableTable
          title="India IOC Matches"
          icon={<Shield className="w-4 h-4 text-orange-400" />}
          badge={india_ioc_hits.length}
          badgeColor="bg-orange-500/10 text-orange-400 border-orange-500/30"
        >
          <div className="space-y-2 pt-1">
            {india_ioc_hits.map((hit, i) => (
              <div key={i} className="flex items-start justify-between gap-2 rounded-lg bg-orange-500/5 border border-orange-500/20 p-3">
                <div>
                  <span className="font-mono text-sm text-orange-300 font-semibold block">{hit.value}</span>
                  <span className="text-xs text-slate-400">{hit.reason}</span>
                </div>
                <span className={`shrink-0 text-xs px-2 py-0.5 rounded-full font-bold border ${riskColor(hit.severity)}`}>
                  {hit.severity}
                </span>
              </div>
            ))}
          </div>
        </ExpandableTable>
      )}

      {/* DGA Suspects */}
      {dga_suspects.length > 0 && (
        <ExpandableTable
          title="Suspected DGA Domains"
          icon={<Zap className="w-4 h-4 text-yellow-400" />}
          badge={dga_suspects.length}
          badgeColor="bg-yellow-500/10 text-yellow-400 border-yellow-500/30"
        >
          <div className="pt-1 overflow-x-auto">
            <table className="w-full text-xs">
              <thead>
                <tr className="border-b border-slate-700/40">
                  <th className="text-left py-2 text-slate-500 font-medium">Domain</th>
                  <th className="text-right py-2 text-slate-500 font-medium">Queries</th>
                  <th className="text-right py-2 text-slate-500 font-medium">Entropy</th>
                </tr>
              </thead>
              <tbody>
                {dga_suspects.map((d, i) => (
                  <tr key={i} className="border-b border-slate-800/60 hover:bg-slate-800/30">
                    <td className="py-2 font-mono text-yellow-300 break-all">{d.domain}</td>
                    <td className="py-2 text-right text-slate-300">{d.query_count}</td>
                    <td className="py-2 text-right text-orange-400 font-bold">{d.entropy}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </ExpandableTable>
      )}

      {/* Search */}
      <div className="relative">
        <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-slate-500" />
        <input
          type="text"
          placeholder="Filter IPs, domains…"
          value={search}
          onChange={(e) => setSearch(e.target.value)}
          className="w-full pl-9 pr-4 py-2 rounded-lg bg-slate-900/60 border border-slate-700/40 text-sm text-slate-200 placeholder-slate-500 focus:outline-none focus:border-indigo-500/50"
        />
      </div>

      {/* DNS Queries */}
      <ExpandableTable
        title="DNS Queries"
        icon={<Search className="w-4 h-4 text-cyan-400" />}
        badge={summary.dns_query_count}
        defaultExpanded={false}
      >
        <div className="pt-1 max-h-72 overflow-y-auto space-y-0.5 pr-1">
          {filteredDns.slice(0, 100).map((d, i) => (
            <div key={i} className="flex items-center justify-between py-1.5 border-b border-slate-800/40 hover:bg-slate-800/30 rounded px-1">
              <span className="font-mono text-xs text-slate-300 break-all">{d.domain}</span>
              <span className="text-xs text-slate-500 shrink-0 ml-2">{d.count}×</span>
            </div>
          ))}
        </div>
      </ExpandableTable>

      {/* TLS SNI */}
      {tls_sni.length > 0 && (
        <ExpandableTable
          title="TLS / HTTPS Hosts (SNI)"
          icon={<Lock className="w-4 h-4 text-green-400" />}
          badge={tls_sni.length}
          defaultExpanded={false}
        >
          <div className="pt-1 flex flex-wrap gap-2">
            {tls_sni.map((sni, i) => (
              <span key={i} className="font-mono text-xs bg-slate-800 text-slate-300 px-2 py-1 rounded-md border border-slate-700/40">
                {sni}
              </span>
            ))}
          </div>
        </ExpandableTable>
      )}

      {/* HTTP Hosts */}
      {http_hosts.length > 0 && (
        <ExpandableTable
          title="HTTP Hosts"
          icon={<Globe className="w-4 h-4 text-indigo-400" />}
          badge={http_hosts.length}
          defaultExpanded={false}
        >
          <div className="pt-1 max-h-60 overflow-y-auto space-y-0.5 pr-1">
            {http_hosts.map((h, i) => (
              <div key={i} className="flex items-center justify-between py-1.5 border-b border-slate-800/40 hover:bg-slate-800/30 rounded px-1">
                <span className="font-mono text-xs text-slate-300 break-all">{h.host}</span>
                <span className="text-xs text-slate-500 shrink-0 ml-2">{h.count}×</span>
              </div>
            ))}
          </div>
        </ExpandableTable>
      )}

      {/* Remote IPs */}
      <ExpandableTable
        title="Remote IP Connections"
        icon={<Server className="w-4 h-4 text-blue-400" />}
        badge={summary.unique_remote_ips}
        defaultExpanded={false}
      >
        <div className="pt-1 overflow-x-auto">
          <table className="w-full text-xs">
            <thead>
              <tr className="border-b border-slate-700/40">
                <th className="text-left py-2 text-slate-500 font-medium">IP</th>
                <th className="text-right py-2 text-slate-500 font-medium">Packets</th>
                <th className="text-left py-2 pl-4 text-slate-500 font-medium">Ports</th>
                <th className="text-right py-2 text-slate-500 font-medium">First seen</th>
              </tr>
            </thead>
            <tbody>
              {filteredIps.slice(0, 50).map((r, i) => (
                <tr key={i} className="border-b border-slate-800/60 hover:bg-slate-800/30">
                  <td className="py-2 font-mono text-blue-300">{r.ip}</td>
                  <td className="py-2 text-right text-slate-300">{r.count.toLocaleString()}</td>
                  <td className="py-2 pl-4">
                    <div className="flex flex-wrap gap-1">
                      {r.ports.slice(0, 6).map(p => (
                        <span key={p} className={`px-1.5 py-0.5 rounded font-mono text-xs ${
                          [4444,1337,31337].includes(p)
                            ? "bg-red-500/10 text-red-400 border border-red-500/20"
                            : "bg-slate-800 text-slate-400 border border-slate-700/40"
                        }`}>
                          {portLabel(p)}
                        </span>
                      ))}
                      {r.ports.length > 6 && <span className="text-slate-600 text-xs">+{r.ports.length - 6}</span>}
                    </div>
                  </td>
                  <td className="py-2 text-right text-slate-500 font-mono whitespace-nowrap">
                    {r.first_seen.slice(0,10)}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </ExpandableTable>
    </div>
  );
}
