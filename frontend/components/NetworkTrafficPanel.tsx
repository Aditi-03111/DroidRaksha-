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
  CRITICAL: "text-[#f43f5e] bg-[rgba(244,63,94,0.1)] border-[#f43f5e]",
  HIGH:     "text-[#f97316] bg-[rgba(249,115,22,0.1)] border-[#f97316]",
  MEDIUM:   "text-[#eab308] bg-[rgba(234,179,8,0.1)] border-[#eab308]",
  LOW:      "text-[#22c55e] bg-[rgba(34,197,94,0.1)] border-[#22c55e]",
}[risk] ?? "text-[#777] bg-[#111] border-[#222]");

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
    <div className="border border-[#1A1A1A] bg-[#050505] overflow-hidden glass-panel">
      <button
        onClick={() => setOpen(!open)}
        className="w-full flex items-center justify-between px-4 py-3 hover:bg-[#111] transition-colors border-b border-transparent data-[open=true]:border-[#1A1A1A]"
        data-open={open}
      >
        <div className="flex items-center gap-3 text-xs font-mono uppercase tracking-widest text-white">
          {icon}{title}
          {badge !== undefined && (
            <span className={`text-[0.6rem] px-2 py-0.5 font-bold border ${badgeColor ?? "bg-black text-[#555] border-[#222]"}`}>
              {badge}
            </span>
          )}
        </div>
        {open ? <ChevronUp className="w-4 h-4 text-[#555]" /> : <ChevronDown className="w-4 h-4 text-[#555]" />}
      </button>
      {open && <div className="px-4 pb-4 pt-2 bg-black/50">{children}</div>}
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
    setProgress("[ UPLOADING PCAP ]");

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
      setProgress("[ ANALYSIS COMPLETE ]");
      onSuccess(data.network as NetworkData);
    } catch (e: unknown) {
      setError(e instanceof Error ? e.message : "Upload failed");
    } finally {
      setUploading(false);
    }
  };

  return (
    <div
      className={`relative border border-dashed p-10 flex flex-col items-center gap-4 transition-all cursor-pointer select-none corner-brackets
        ${dragging ? "border-[#0052FF] bg-[rgba(0,82,255,0.05)]" : "border-[#1A1A1A] hover:border-[#0052FF] bg-[#050505]"}`}
      onDragOver={(e) => { e.preventDefault(); setDragging(true); }}
      onDragLeave={() => setDragging(false)}
      onDrop={(e) => { e.preventDefault(); setDragging(false); const f = e.dataTransfer.files[0]; if (f) handleFile(f); }}
      onClick={() => inputRef.current?.click()}
    >
      <input ref={inputRef} type="file" accept=".pcap,.pcapng" className="hidden"
        onChange={(e) => { const f = e.target.files?.[0]; if (f) handleFile(f); }} />

      <div className="w-12 h-12 bg-black border border-[#1A1A1A] flex items-center justify-center">
        {uploading
          ? <Activity className="w-5 h-5 text-[#0052FF] animate-pulse" />
          : <Upload className="w-5 h-5 text-[#777]" />}
      </div>

      <div className="text-center font-mono">
        <p className="text-white font-semibold text-xs uppercase tracking-widest mb-1">
          {uploading ? progress : "[ UPLOAD PCAP FOR NETWORK ANALYSIS ]"}
        </p>
        <p className="text-[#555] text-[0.65rem] uppercase tracking-widest">
          {uploading ? "Analyzing packets, detecting beaconing…"
            : "Drag & drop or click — .pcap / .pcapng up to 200 MB"}
        </p>
      </div>

      {error && (
        <div className="w-full bg-[rgba(244,63,94,0.1)] border border-[rgba(244,63,94,0.3)] px-4 py-2 text-[#f43f5e] text-xs font-mono uppercase text-center">
          [ ERR: {error} ]
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
      <div className="space-y-4 glass-panel p-6">
        <div className="flex items-center gap-3">
          <Globe className="w-5 h-5 text-[#0052FF]" />
          <h2 className="text-lg font-bold text-white uppercase font-mono tracking-tight">Network Traffic Analysis</h2>
        </div>
        <p className="text-[#777] text-sm mb-4">
          Upload a PCAP capture from this device to analyze network behavior,
          detect C2 beaconing, DGA domains, and India IOC matches.
        </p>
        <PcapUploadZone analysisId={analysisId} onSuccess={setNetwork} />
      </div>
    );
  }

  if (!network.available) {
    return (
      <div className="glass-panel border border-[#1A1A1A] p-6 text-center space-y-3 bg-[#050505]">
        <AlertTriangle className="w-8 h-8 text-[#eab308] mx-auto" />
        <p className="text-white font-mono uppercase text-sm tracking-widest">[ PCAP Analysis Unavailable ]</p>
        <p className="text-[#555] text-xs font-mono">{network.error ?? "Unknown error"}</p>
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
      <div className="flex flex-wrap items-center justify-between gap-3 p-4 border-b border-[#1A1A1A]">
        <div className="flex items-center gap-3">
          <Globe className="w-5 h-5 text-[#0052FF]" />
          <h2 className="text-lg font-bold text-white uppercase tracking-tight font-mono">Network Traffic Analysis</h2>
          <span className={`text-[0.65rem] font-bold px-3 py-1 border uppercase tracking-widest ${riskColor(network.pcap_risk)}`}>
            {network.pcap_risk}
          </span>
        </div>
        <button
          onClick={() => setNetwork(null)}
          className="text-[0.65rem] font-mono text-[#555] hover:text-white uppercase tracking-widest transition-colors"
        >
          [ UPLOAD NEW PCAP ]
        </button>
      </div>

      {/* Summary Cards */}
      <div className="grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-5 gap-4">
        {[
          { label: "Packets",      value: summary.total_packets.toLocaleString(),  icon: <Wifi className="w-3.5 h-3.5" />,      color: "text-[#0052FF]" },
          { label: "Remote IPs",   value: summary.unique_remote_ips,               icon: <Server className="w-3.5 h-3.5" />,    color: "text-[#0ea5e9]" },
          { label: "DNS Queries",  value: summary.dns_query_count,                 icon: <Search className="w-3.5 h-3.5" />,    color: "text-[#06b6d4]" },
          { label: "Beacons",      value: summary.beaconing_alerts,                icon: <Radio className="w-3.5 h-3.5" />,     color: summary.beaconing_alerts > 0 ? "text-[#f43f5e]" : "text-[#22c55e]" },
          { label: "India IOC",    value: summary.india_hits,                      icon: <Shield className="w-3.5 h-3.5" />,    color: summary.india_hits > 0 ? "text-[#f43f5e]" : "text-[#22c55e]" },
        ].map(card => (
          <div key={card.label} className="bg-[#050505] border border-[#1A1A1A] p-4 flex flex-col gap-2 corner-brackets group hover:border-[#333] transition-colors">
            <div className={`flex items-center gap-2 text-[0.65rem] font-mono uppercase tracking-widest ${card.color}`}>
              {card.icon}{card.label}
            </div>
            <p className="text-2xl font-bold text-white font-mono">{card.value}</p>
          </div>
        ))}
      </div>

      {/* Beaconing Alerts */}
      {beaconing_alerts.length > 0 && (
        <ExpandableTable
          title="C2 Beaconing Alerts"
          icon={<Radio className="w-4 h-4 text-[#f43f5e]" />}
          badge={beaconing_alerts.length}
          badgeColor="bg-[rgba(244,63,94,0.1)] text-[#f43f5e] border-[#f43f5e]"
        >
          <div className="space-y-3 pt-2">
            {beaconing_alerts.map((a, i) => (
              <div key={i} className="bg-[#050505] border border-[#1A1A1A] border-l-2 border-l-[#f43f5e] p-4 space-y-2">
                <div className="flex items-center justify-between">
                  <span className="font-mono text-sm text-[#f43f5e] font-semibold">{a.ip}</span>
                  <span className={`text-[0.65rem] px-2 py-0.5 font-bold border uppercase tracking-widest ${
                    a.confidence === "HIGH"
                      ? "bg-[rgba(244,63,94,0.1)] text-[#f43f5e] border-[#f43f5e]"
                      : "bg-[rgba(249,115,22,0.1)] text-[#f97316] border-[#f97316]"
                  }`}>
                    {a.confidence} CONFIDENCE
                  </span>
                </div>
                <p className="text-xs text-[#777] font-mono">{a.description}</p>
                <div className="flex gap-4 text-[0.65rem] text-[#555] font-mono uppercase tracking-widest border-t border-[#111] pt-2">
                  <span>Contacts: <span className="text-white">{a.contact_count}</span></span>
                  <span>Interval: <span className="text-white">~{a.avg_interval_sec}s</span></span>
                  <span>Jitter CV: <span className="text-white">{a.jitter_cv}</span></span>
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
          icon={<Shield className="w-4 h-4 text-[#f97316]" />}
          badge={india_ioc_hits.length}
          badgeColor="bg-[rgba(249,115,22,0.1)] text-[#f97316] border-[#f97316]"
        >
          <div className="space-y-2 pt-2">
            {india_ioc_hits.map((hit, i) => (
              <div key={i} className="flex items-start justify-between gap-4 bg-[#050505] border border-[#1A1A1A] p-4 border-l-2 border-l-[#f97316]">
                <div>
                  <span className="font-mono text-sm text-[#f97316] font-semibold block mb-1">{hit.value}</span>
                  <span className="text-[0.65rem] text-[#777] font-mono uppercase tracking-widest">{hit.reason}</span>
                </div>
                <span className={`shrink-0 text-[0.6rem] px-2 py-0.5 font-bold border uppercase tracking-widest ${riskColor(hit.severity)}`}>
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
          icon={<Zap className="w-4 h-4 text-[#eab308]" />}
          badge={dga_suspects.length}
          badgeColor="bg-[rgba(234,179,8,0.1)] text-[#eab308] border-[#eab308]"
        >
          <div className="pt-2 overflow-x-auto">
            <table className="w-full text-xs font-mono">
              <thead>
                <tr className="border-b border-[#1A1A1A] text-[0.65rem] uppercase tracking-widest text-[#555]">
                  <th className="text-left py-2 font-medium">Domain</th>
                  <th className="text-right py-2 font-medium">Queries</th>
                  <th className="text-right py-2 font-medium">Entropy</th>
                </tr>
              </thead>
              <tbody>
                {dga_suspects.map((d, i) => (
                  <tr key={i} className="border-b border-[#111] hover:bg-[#111]">
                    <td className="py-2 text-[#eab308] break-all">{d.domain}</td>
                    <td className="py-2 text-right text-white">{d.query_count}</td>
                    <td className="py-2 text-right text-[#f97316] font-bold">{d.entropy}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </ExpandableTable>
      )}

      {/* Search */}
      <div className="relative border border-[#1A1A1A] bg-[#050505]">
        <Search className="absolute left-4 top-1/2 -translate-y-1/2 w-4 h-4 text-[#555]" />
        <input
          type="text"
          placeholder="FILTER IPS, DOMAINS…"
          value={search}
          onChange={(e) => setSearch(e.target.value)}
          className="w-full pl-12 pr-4 py-3 bg-transparent text-[0.65rem] font-mono tracking-widest uppercase text-white placeholder-[#555] focus:outline-none focus:border-[#0052FF]"
        />
      </div>

      {/* DNS Queries */}
      <ExpandableTable
        title="DNS Queries"
        icon={<Search className="w-4 h-4 text-[#06b6d4]" />}
        badge={summary.dns_query_count}
        defaultExpanded={false}
      >
        <div className="pt-2 max-h-72 overflow-y-auto space-y-1 pr-2 custom-scrollbar">
          {filteredDns.slice(0, 100).map((d, i) => (
            <div key={i} className="flex items-center justify-between py-2 border-b border-[#111] hover:bg-[#111] px-2 font-mono">
              <span className="text-[0.65rem] text-[#aaa] break-all">{d.domain}</span>
              <span className="text-[0.65rem] text-[#555] shrink-0 ml-4 border border-[#222] px-1 bg-black">{d.count}×</span>
            </div>
          ))}
        </div>
      </ExpandableTable>

      {/* TLS SNI */}
      {tls_sni.length > 0 && (
        <ExpandableTable
          title="TLS / HTTPS Hosts (SNI)"
          icon={<Lock className="w-4 h-4 text-[#22c55e]" />}
          badge={tls_sni.length}
          defaultExpanded={false}
        >
          <div className="pt-2 flex flex-wrap gap-2">
            {tls_sni.map((sni, i) => (
              <span key={i} className="font-mono text-[0.65rem] bg-[#050505] text-[#aaa] px-2 py-1 border border-[#1A1A1A]">
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
          icon={<Globe className="w-4 h-4 text-[#0052FF]" />}
          badge={http_hosts.length}
          defaultExpanded={false}
        >
          <div className="pt-2 max-h-60 overflow-y-auto space-y-1 pr-2 custom-scrollbar">
            {http_hosts.map((h, i) => (
              <div key={i} className="flex items-center justify-between py-2 border-b border-[#111] hover:bg-[#111] px-2 font-mono">
                <span className="text-[0.65rem] text-[#aaa] break-all">{h.host}</span>
                <span className="text-[0.65rem] text-[#555] shrink-0 ml-4 border border-[#222] px-1 bg-black">{h.count}×</span>
              </div>
            ))}
          </div>
        </ExpandableTable>
      )}

      {/* Remote IPs */}
      <ExpandableTable
        title="Remote IP Connections"
        icon={<Server className="w-4 h-4 text-[#0ea5e9]" />}
        badge={summary.unique_remote_ips}
        defaultExpanded={false}
      >
        <div className="pt-2 overflow-x-auto">
          <table className="w-full text-[0.65rem] font-mono">
            <thead>
              <tr className="border-b border-[#1A1A1A] uppercase tracking-widest text-[#555]">
                <th className="text-left py-2 font-medium">IP</th>
                <th className="text-right py-2 font-medium">Packets</th>
                <th className="text-left py-2 pl-6 font-medium">Ports</th>
                <th className="text-right py-2 font-medium">First seen</th>
              </tr>
            </thead>
            <tbody>
              {filteredIps.slice(0, 50).map((r, i) => (
                <tr key={i} className="border-b border-[#111] hover:bg-[#111]">
                  <td className="py-3 text-[#0ea5e9]">{r.ip}</td>
                  <td className="py-3 text-right text-white">{r.count.toLocaleString()}</td>
                  <td className="py-3 pl-6">
                    <div className="flex flex-wrap gap-1.5">
                      {r.ports.slice(0, 6).map(p => (
                        <span key={p} className={`px-1.5 py-0.5 border uppercase tracking-widest ${
                          [4444,1337,31337].includes(p)
                            ? "bg-[rgba(244,63,94,0.1)] text-[#f43f5e] border-[#f43f5e]"
                            : "bg-black text-[#777] border-[#222]"
                        }`}>
                          {portLabel(p)}
                        </span>
                      ))}
                      {r.ports.length > 6 && <span className="text-[#555] border border-transparent px-1 flex items-center">+{r.ports.length - 6}</span>}
                    </div>
                  </td>
                  <td className="py-3 text-right text-[#555] whitespace-nowrap">
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
