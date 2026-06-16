// DroidRaksha — TypeScript type definitions

export interface HashInfo {
  md5: string;
  sha1: string;
  sha256: string;
  file_size: number;
}

export interface Permission {
  name: string;
  is_dangerous: boolean;
  protection_level: string;
  description?: string;
}

export interface DangerousCombo {
  label: string;
  permissions: string[];
  risk: string;
}

export interface Manifest {
  package_name: string;
  version_name: string;
  version_code: number;
  min_sdk: number;
  target_sdk: number;
  permissions: Permission[];
  dangerous_combos: DangerousCombo[];
  activities: string[];
  services: string[];
  receivers: string[];
  providers: string[];
  error?: string;
}

export interface StringItem {
  value: string;
  context?: string;
  risk?: "high" | "medium" | "low";
}

export interface Strings {
  urls: StringItem[];
  ips: StringItem[];
  emails: StringItem[];
  crypto_keys: StringItem[];
  suspicious_strings: StringItem[];
  base64_strings: string[];
}

export interface Certificate {
  issuer: string;
  subject: string;
  not_before: string;
  not_after: string;
  is_expired: boolean;
  is_self_signed: boolean;
  serial_number: string;
  fingerprint_sha256: string;
  warnings: string[];
  error?: string;
}

export interface YaraMatch {
  rule: string;
  severity: "CRITICAL" | "HIGH" | "MEDIUM" | "LOW";
  tags: string[];
  description?: string;
}

export interface YaraScan {
  matches: YaraMatch[];
  total_matches: number;
  scan_duration_ms?: number;
}

export interface Obfuscation {
  score: number;
  has_dex_classloader: boolean;
  has_reflection: boolean;
  has_string_encryption: boolean;
  has_native_code: boolean;
  class_name_entropy: number;
  short_class_ratio: number;
  indicators: string[];
}

export interface VirusTotal {
  found: boolean;
  detection_count: number;
  total_engines: number;
  malware_families: string[];
  scan_date?: string;
  permalink?: string;
  error?: string;
}

export interface AbuseIPDB {
  flagged_ips: string[];
  max_confidence: number;
  results: Array<{
    ip: string;
    confidence: number;
    country: string;
    usage: string;
  }>;
  error?: string;
}

export interface IndiaIOC {
  is_fake_upi: boolean;
  is_fake_bank: boolean;
  is_loan_scam: boolean;
  risk_flags: string[];
  matched_ips: string[];
  matched_domains: string[];
}

export interface RiskBreakdown {
  permissions: number;
  yara: number;
  certificate: number;
  threat_intel: number;
  obfuscation: number;
  india_ioc: number;
  strings: number;
}

export interface Risk {
  score: number;
  risk_level: "CRITICAL" | "HIGH" | "MEDIUM" | "LOW" | "SAFE";
  breakdown: RiskBreakdown;
  threat_categories: string[];
}

export interface MitreTactic {
  technique_id: string;
  name: string;
  tactic: string;
  evidence: string;
  all_evidence?: string[];
}

// ── P11 ML Intelligence Layer types ─────────────────────────────────────

export type MalwareFamilyLabel =
  | "BankingTrojan" | "RAT" | "Spyware" | "Ransomware" | "Adware"
  | "Dropper" | "SMSStealer" | "FakeApp" | "CryptoMiner"
  | "Stalkerware" | "ClipboardHijacker" | "Unknown";

export interface SHAPFeature {
  feature: string;
  raw_name: string;
  shap_value: number;
  direction: "increases" | "decreases";
}

export interface XGBoostResult {
  label: "Adware" | "Banking" | "SMS_Malware" | "Riskware" | "Benign" | "unavailable" | "error";
  probability: number;
  class_probs: Record<string, number>;
  shap_top5: SHAPFeature[];
  available: boolean;
  inference_ms: number;
}

export interface MalBERTResult {
  label: MalwareFamilyLabel | string;
  raw_label: string;
  confidence: number;
  all_scores: Record<string, number>;
  input_text_preview: string;
  available: boolean;
  inference_ms: number;
}

export interface MLClassification {
  family: MalwareFamilyLabel;
  confidence: number;
  evidence: string[];
  secondary_families: string[];
  is_india_targeted: boolean;
}

export interface AnomalyDetection {
  is_anomalous: boolean;
  anomaly_score: number;
  anomaly_percentile: number;
  zero_day_risk: "CRITICAL" | "HIGH" | "MEDIUM" | "LOW";
  explanation: string;
  model_used: "isolation_forest" | "heuristic";
  available: boolean;
  inference_ms: number;
}

export interface AgentVerdict {
  court_narrative: string;
  ioc_summary: string;
  recommendations: string[];
  reasoning_steps: string[];
  verdict_confidence: number;
  agent_used: string;
  inference_ms?: number;
}

export interface AnalysisResult {
  id: string;
  status: "complete" | "pending" | "error";
  created_at: string;
  filename: string;
  hashes: HashInfo;
  manifest: Manifest;
  strings: Strings;
  certificate: Certificate;
  yara: YaraScan;
  obfuscation: Obfuscation;
  virustotal: VirusTotal;
  abuseipdb: AbuseIPDB;
  india_ioc: IndiaIOC;
  risk: Risk;
  mitre: MitreTactic[];
  // ML Intelligence Layer
  ml_classification?: MLClassification;
  xgboost?: XGBoostResult;
  malbert?: MalBERTResult;
  anomaly?: AnomalyDetection;
  agent_verdict?: AgentVerdict;
  // AI Narrative
  ai_narrative: string;
  ai_recommendations: string[];
  network?: any;
}

export interface DashboardStats {
  total_analyzed: number;
  threats_detected: number;
  india_threats: number;
  critical_count: number;
  high_count: number;
  medium_count: number;
  low_count: number;
  safe_count: number;
  family_breakdown: Record<string, number>;
  india_targeted: number;
  pcap_scans: number;
  recent_analyses: Array<{
    id: string;
    filename: string;
    package_name: string;
    risk_score: number;
    risk_level: string;
    created_at: string;
  }>;
}
