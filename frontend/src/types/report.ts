export type RiskLevel = 'low' | 'medium' | 'high' | 'critical'

export type ScanKind = 'full' | 'discover' | 'host' | 'module'

export interface ScanStatus {
  scan_id: string
  domain: string
  status: 'queued' | 'running' | 'completed' | 'failed' | 'interrupted' | 'error'
  progress: number
  current_module: string | null
  phase?: 'scan' | 'agent'
  kind?: ScanKind
  agent_steps?: AgentScanStep[]
}

export interface ScanRequestPayload {
  domain: string
  company_name?: string
  agent_mode?: boolean
  skip_discovery?: boolean
}

export interface Finding {
  module: string
  finding: string
  risk: RiskLevel
}

export interface Scorecard {
  score: number
  grade: 'A' | 'B' | 'C' | 'D' | 'F'
  overall_risk: RiskLevel
}

// WHOIS
export interface WhoisResult {
  status: string
  registrar: string | null
  creation_date: string | null
  expiration_date: string | null
  updated_date: string | null
  name_servers: string[]
  registrant_country: string | null
  emails: string[]
  dnssec: string | null
  org: string | null
  risk: RiskLevel
  findings: string[]
}

// DNS
export interface DnsResult {
  status: string
  records: Record<string, string[]>
  zone_transfer_vulnerable: boolean
  risk: RiskLevel
  findings: string[]
}

// Subdomains
export interface SubdomainEntry {
  subdomain: string
  ips: string[]
  status: string
  sensitive?: boolean
}

export interface SubdomainsResult {
  status: string
  count: number
  subdomains: SubdomainEntry[]
  crt_sh_count: number
  hackertarget_count: number
  passive_count: number
  brute_force_count: number
  risk: RiskLevel
  findings: string[]
}

// Ports
export interface PortEntry {
  port: number
  service: string
  state: string
  banner: string | null
  risky: boolean
  unauthenticated?: boolean
}

export interface UnauthService {
  port: number
  service: string
  banner: string
}

export interface PortsResult {
  status: string
  ip: string | null
  open_ports: PortEntry[]
  total_open: number
  risky_ports: number
  unauthenticated_services?: UnauthService[]
  risk: RiskLevel
  findings: string[]
}

// SSL
export interface SslResult {
  status: string
  has_ssl: boolean
  subject: Record<string, string>
  issuer: Record<string, string>
  valid_from: string | null
  valid_to: string | null
  days_remaining: number | null
  san: string[]
  cipher: string | null
  protocol: string | null
  self_signed: boolean
  expired: boolean
  deprecated_protocols: string[]
  risk: RiskLevel
  findings: string[]
}

// Headers
export interface HeaderEntry {
  value: string
  description: string
}

export interface MissingHeader {
  header: string
  description: string
  recommended: string
  severity: string
}

export interface HeadersResult {
  status: string
  url: string | null
  status_code: number | null
  headers_present: Record<string, HeaderEntry>
  headers_missing: MissingHeader[]
  leaky_headers: Record<string, string>
  redirects_to_https: boolean
  risk: RiskLevel
  findings: string[]
  score: number
}

// Email
export interface SpfResult {
  exists: boolean
  record: string | null
  multiple_records: boolean
  policy: string | null
  findings: string[]
}

export interface DmarcResult {
  exists: boolean
  record: string | null
  policy: string | null
  pct: number
  rua: string | null
  ruf: string | null
  findings: string[]
}

export interface DkimResult {
  exists: boolean
  selectors_found: { selector: string; record: string }[]
  findings: string[]
}

export interface EmailProviderResult {
  provider: 'google' | 'microsoft' | 'self-hosted' | 'unknown'
  google_workspace: boolean
  microsoft_365: boolean
  mx_records: string[]
  tenant_id: string | null
  tenant_name: string | null
  tenant_region?: string | null
  cloud_instance?: string | null
  realm_type?: 'Managed' | 'Federated' | 'Unknown'
  federation_url?: string | null
  detection_method: string[]
  findings: string[]
}

export interface EmailResult {
  status: string
  spf: SpfResult
  dmarc: DmarcResult
  dkim: DkimResult
  mta_sts: { exists: boolean; record: string | null }
  bimi: { exists: boolean; record: string | null }
  provider: EmailProviderResult
  risk: RiskLevel
  findings: string[]
}

// Tech
export interface TechResult {
  status: string
  technologies: string[]
  server: string | null
  powered_by: string | null
  cookies: { name: string; secure: boolean; httponly: boolean; samesite: string | null }[]
  risk: RiskLevel
  findings: string[]
}

// Frontend Library CVEs
export interface FrontendLibrary {
  name: string
  npm: string
  version: string
  vuln_count: number
}

export interface FrontendCveVuln {
  library: string
  detected_version: string
  cve: string
  cve_ids: string[]
  summary: string
  severity: RiskLevel | 'unknown'
  fixed_versions: string[]
  references: string[]
}

export interface FrontendCveResult {
  status: string
  detected: FrontendLibrary[]
  detected_count: number
  vulnerabilities: FrontendCveVuln[]
  cve_count: number
  critical_count: number
  high_count: number
  risk: RiskLevel
  findings: string[]
}

// Cloud Storage
export interface CloudBucketExposed {
  name: string
  provider: 'aws' | 'gcs' | 'azure'
  url: string
  status: number
  severity: RiskLevel
}
export interface CloudMetadataResult {
  status: string
  candidates_checked: number
  endpoints_probed: number
  s3scanner_used?: boolean
  grayhatwarfare_used?: boolean
  exposed: CloudBucketExposed[]
  existing_private: number
  existing_private_list?: { name: string; provider: string; url?: string }[]
  exposed_count: number
  risk: RiskLevel
  findings: string[]
}

// API Exposure
export interface ApiEndpointFound {
  path: string
  url: string
  label: string
  severity: RiskLevel
  status: number
  content_type: string
}
export interface ApiExposureResult {
  status: string
  paths_checked: number
  found: ApiEndpointFound[]
  found_count: number
  swagger_found: boolean
  graphql_found: boolean
  has_graphql_introspection: boolean
  github_repos?: { name: string; url: string; description?: string; stars?: number }[]
  github_code_hits?: { url: string; repo?: string; path?: string }[]
  postman_collections?: { name: string; url: string; publisher?: string }[]
  postman_workspaces?: { name: string; url: string; publisher?: string }[]
  risk: RiskLevel
  findings: string[]
}

// Wayback Secrets
export interface WaybackSensitiveUrl {
  url: string
  timestamp: string
  label: string
  severity: RiskLevel
}
export interface WaybackSecretFound {
  secret_type: string
  severity: RiskLevel
  url: string
  snippet: string
}
export interface WaybackSecretsResult {
  status: string
  urls_indexed: number
  sensitive_urls: WaybackSensitiveUrl[]
  sensitive_count: number
  indexed_urls?: { url: string; timestamp: string }[]
  secrets_found: WaybackSecretFound[]
  secret_count: number
  snapshots_fetched: number
  risk: RiskLevel
  findings: string[]
}

// Nuclei
export interface NucleiFinding {
  template_id: string
  name: string
  severity: RiskLevel
  description: string
  matched_at: string
  cve_ids: string[]
  tags: string[]
  references: string[]
}
export interface NucleiResult {
  status: string
  findings_detail: NucleiFinding[]
  findings_count: number
  by_severity: Record<string, number>
  risk: RiskLevel
  findings: string[]
}

// Breach / Leaks
export interface BreachEntry {
  name: string
  title: string
  breach_date: string
  pwn_count: number
  data_classes: string[]
  verified: boolean
}

export interface HunterEmail {
  email: string
  confidence: number
  position: string | null
  first_name: string | null
  last_name: string | null
  linkedin: string | null
  sources: string[]
}

export interface BreachResult {
  status: string
  breaches: BreachEntry[]
  breach_count: number
  combo_count: number
  exposed_emails: (string | { name: string; date?: string })[]  // crt.sh; newer backend returns objects
  all_emails: string[]           // merged from all sources
  hunter: {
    checked: boolean
    total: number
    organization: string | null
    emails: HunterEmail[]
    error?: string
  }
  leakcheck: {
    checked: boolean
    found: number
    sources: (string | { name: string; date?: string })[]
    fields: string[]
    error?: string
  }
  public_code_mentions: number
  hibp_checked: boolean
  combo_samples: string[]
  risk: RiskLevel
  findings: string[]
}

// Exposed Files
export interface ExposedFile {
  path: string
  url: string
  status: number
  size: number
  content_type: string | null
  description: string
  severity: string
  snippet: string | null
  confidence?: 'high' | 'medium' | 'confirmed'
}

export interface ExposedFilesBaseline {
  returns_403_for_random: boolean
  returns_200_for_random: boolean
  waf_detected_baseline: boolean
  wall_size: number | null
}

export interface ExposedFilesResult {
  status: string
  exposed: ExposedFile[]
  total: number
  critical_count: number
  high_count: number
  confirmed_count: number
  has_security_txt: boolean
  baseline: ExposedFilesBaseline
  risks_by_severity: Record<string, ExposedFile[]>
  risk: RiskLevel
  findings: string[]
}

// Blacklist / Reputation
export interface BlacklistEntry {
  list: string
  dnsbl: string
  codes: string[]
  details: string | null
}

export interface BlacklistResult {
  status: string
  ip: string | null
  all_ips: string[]
  dnsbl_count: number
  listed_on: BlacklistEntry[]
  listing_count: number
  clean: boolean
  spamhaus_listed: boolean
  barracuda_listed: boolean
  urlhaus: { found: boolean; url_count?: number; urls: { url: string; threat: string | null; date_added: string | null; tags: string[] }[]; checked: boolean }
  threatfox: { found: boolean; ioc_count?: number; iocs: { ioc: string; threat_type: string; malware: string; confidence: number; first_seen: string }[]; checked: boolean }
  risk: RiskLevel
  findings: string[]
}

// CORS
export interface CorsTest {
  tested_origin: string
  acao: string | null
  allow_credentials: boolean
  allow_methods: string | null
  reflected: boolean
  wildcard: boolean
  error?: string
}

export interface CorsResult {
  status: string
  misconfigured: boolean
  reflected_origin: boolean
  allows_null_origin: boolean
  allows_credentials_wildcard: boolean
  wildcard_no_credentials: boolean
  cors_tests: CorsTest[]
  risk: RiskLevel
  findings: string[]
}

// Cookie Security
export interface CookieEntry {
  name: string
  secure: boolean
  httponly: boolean
  samesite: string | null
  path: string
  domain: string | null
}

export interface CookieSecurityResult {
  status: string
  cookies: CookieEntry[]
  insecure_count: number
  missing_httponly: string[]
  missing_secure: string[]
  missing_samesite: string[]
  session_cookies_insecure: string[]
  risk: RiskLevel
  findings: string[]
}

// JS Secrets
export interface SecretFinding {
  type: string
  severity: string
  file: string
  line: number
  snippet: string
  value?: string   // full value — revealed on demand in the UI
}

export interface JsEndpoint {
  path: string
  source: string
}

export interface JsHost {
  host: string
  kind: 'subdomain' | 'internal-env' | 'cloud' | 'third-party'
  source: string
}

export interface JsGuid {
  value: string
  context: string
  source: string
}

export interface JsSourcemap {
  js: string
  map: string
  has_sources_content: boolean
}

export interface JsSecretsResult {
  status: string
  js_files_scanned: string[]
  secrets_found: SecretFinding[]
  secret_count: number
  by_severity: Record<string, number>
  endpoints?: JsEndpoint[]
  hosts?: JsHost[]
  guids?: JsGuid[]
  sourcemaps?: JsSourcemap[]
  risk: RiskLevel
  findings: string[]
}

// Secret Verification
export interface VerifiedSecret {
  type: string
  key: string
  host: string
  verdict: 'valid' | 'invalid' | 'unknown'
  evidence: string
}

export interface JwtAnalysis {
  source: string
  alg: string
  issuer: string
  expires: string
  issues: string[]
}

export interface SecretVerificationResult {
  status: 'ok' | 'skipped' | 'error'
  error?: string
  verified?: VerifiedSecret[]
  jwt_analysis?: JwtAnalysis[]
  valid_count?: number
  risk: RiskLevel
  findings: string[]
}

// WAF / CDN
export interface WafDetected {
  name: string
  category: string
  confidence: number
  signals: string[]
}

export interface WafResult {
  status: string
  detected: WafDetected[]
  waf_found: boolean
  cdn_found: boolean
  waf_names: string[]
  cdn_names: string[]
  server_names: string[]
  risk: RiskLevel
  findings: string[]
}

// Robots / Sitemap
export interface RobotsResult {
  status: string
  robots_found: boolean
  robots_disallowed: string[]
  robots_allowed: string[]
  robots_sitemaps: string[]
  sensitive_in_robots: string[]
  sitemap_found: boolean
  sitemap_url_count: number
  sitemap_urls_sample: string[]
  sensitive_in_sitemap: string[]
  risk: RiskLevel
  findings: string[]
}

// DNSSEC
export interface DnssecResult {
  status: string
  signed: boolean
  validated: boolean
  has_dnskey: boolean
  has_ds: boolean
  has_rrsig: boolean
  has_nsec: boolean
  has_nsec3: boolean
  dnskey_count: number
  ds_records: string[]
  ad_flag: boolean
  risk: RiskLevel
  findings: string[]
}

// Admin Discovery
export interface AdminPath {
  path: string
  url: string
  status: number
  severity: string
  redirect_to: string | null
  content_type: string
  size: number
}

export interface AdminDiscoveryResult {
  status: string
  paths_probed: number
  found: AdminPath[]
  found_count: number
  critical_count: number
  high_count: number
  risk: RiskLevel
  findings: string[]
}

// TLS Audit
export interface TlsAuditResult {
  status: string
  protocol: string | null
  cipher: { name: string | null; bits: number | null; version: string | null }
  supports_tls13: boolean
  supports_tls12: boolean
  supports_tls11: boolean
  supports_tls10: boolean
  deprecated_protocols: string[]
  weak_cipher: boolean
  hsts: {
    header: string | null
    present: boolean
    max_age: number
    include_subdomains: boolean
    preload: boolean
    preload_eligible: boolean
  }
  risk: RiskLevel
  findings: string[]
}

// Companies / Domains / Scheduling
export interface Schedule {
  interval_hours: number
  enabled: boolean
  agent_mode: boolean
  next_run_at: string | null
  discover_enabled: boolean
  discover_interval_hours: number | null
  next_discover_at: string | null
}

export interface AppDeveloperRef {
  store: 'app_store' | 'google_play'
  name: string
}

export interface CompanyDomain {
  id: number
  domain: string
  created_at: string
  last_grade: string | null
  last_scan_at: string | null
  schedule: Schedule | null
  app_developers?: AppDeveloperRef[]
}

export interface Company {
  id: number
  name: string
  created_at: string
  domains: CompanyDomain[]
  assets_count?: number
}

// GET /api/companies/{id}/rating-history — score evolution per domain
export interface RatingPoint {
  domain: string
  scan_id: string
  completed_at: string | null
  score: number | null
  grade: string | null
  overall_risk: RiskLevel | null
}

export interface RatingHistory {
  company_id: number
  company_name: string
  points: RatingPoint[]
}

// Domain discovery by company name
export interface DiscoveredDomain {
  domain: string
  source: 'crt.sh' | 'permutation' | 'grep.app' | 'llm'
  confidence: 'high' | 'medium' | 'low'
  evidence: string
  resolves: boolean
  http_status: number | null
}

export interface DiscoveryResult {
  discovery_id: string
  status: 'running' | 'completed' | 'error'
  company_name?: string
  candidates?: DiscoveredDomain[]
  searched_at?: string
  error?: string
}

// Company asset inventory (attack surface dashboard)
export interface AssetSummary {
  domains: number
  subdomains: number
  ips: number
  endpoints: number
  technologies: number
  admin_panels: number
  exposed_files: number
  open_ports: number
  apps?: number
  neighbors?: number
  new_last_cycle: number
}

export interface AssetBase {
  id?: number
  value: string
  domain: string
  first_seen: string
  last_seen: string
  is_new: boolean
}

export interface SubdomainAsset extends AssetBase {
  ips: string[]
  http_status: number | null
}

export interface IpAsset extends Omit<AssetBase, 'domain'> {
  domains: string[]
  open_ports: { port: number; service: string }[]
}

export interface EndpointAsset extends AssetBase {
  source: string
}

export interface TechnologyAsset extends AssetBase {
  category: string
}

export interface AdminPanelAsset extends AssetBase {
  http_status: number | null
}

export interface ExposedFileAsset extends AssetBase {
  risk: RiskLevel
}

export interface PortAsset extends AssetBase {
  ip: string
  port: number
  service: string
}

export type LlmVerdict = 'official' | 'unrelated' | 'suspicious'

export interface AppAsset extends AssetBase {
  store: 'app_store' | 'google_play' | null
  os: 'ios' | 'android' | null
  version: string | null
  developer: string | null
  url: string | null
  updated: string | null
  llm_verdict?: LlmVerdict | null
  official_developer?: boolean
  suspicious?: boolean
}

export interface NeighborAsset extends AssetBase {
  ip: string | null
  neighbor_of: string | null
}

// Asset row merged across companies (global dashboard) — carries its origin company name
export type WithCompany<T> = T & { company?: string }

// ── Host-centric inventory (GET /api/companies/{id}/hosts) ───────────────────
// ACTIVO = host (apex domain | subdomain | ip); everything else is an attribute.
export type HostKind = 'domain' | 'subdomain' | 'ip'

export interface HostTechnology { name: string; category: string }
export interface HostPort { port: number; service: string | null }
export interface HostEndpoint { path: string; source: string }
export interface HostAdminPanel { url: string; http_status: number | null; severity: string | null }
export interface HostExposedFile { path: string; risk: RiskLevel; url: string | null; description: string | null }
export interface HostNeighbor { domain: string; neighbor_of: string | null }

export interface HostAsset {
  kind: HostKind
  value: string
  domain: string
  ips: string[]
  http_status: number | null
  first_seen: string | null
  last_seen: string | null
  is_new: boolean
  technologies: HostTechnology[]
  open_ports: HostPort[]
  endpoints: HostEndpoint[]
  admin_panels: HostAdminPanel[]
  exposed_files: HostExposedFile[]
  apps: AppAsset[]
  neighbors: HostNeighbor[]
  risk: RiskLevel
}

export interface HostsSummary {
  hosts: number
  ips: number
  open_ports: number
  endpoints: number
  technologies: number
  admin_panels: number
  exposed_files: number
  apps: number
  neighbors: number
  new_last_cycle: number
}

export interface CompanyHosts {
  company_id: number
  company_name: string
  generated_at: string
  hosts: HostAsset[]
  summary: HostsSummary
}

// GET /api/companies/{id}/hosts/{hostValue}
export interface HostHistoryEntry {
  changed_at: string | null
  scan_id: string
  asset_type: string
  asset_value: string
  field: string
  old: unknown
  new: unknown
}

export interface HostRecentScan {
  id: string
  completed_at: string | null
  grade: string | null
}

export interface HostRelatedFinding {
  module: string | null
  finding: string
  risk: RiskLevel | null
}

export interface HostDetail {
  company_id: number
  company_name: string
  host: HostAsset
  history: HostHistoryEntry[]
  recent_scans: HostRecentScan[]
  related_findings: HostRelatedFinding[]
}

export interface CompanyAssets {
  company_id: number
  company_name: string
  generated_at: string
  summary: AssetSummary
  assets: {
    subdomains: SubdomainAsset[]
    ips: IpAsset[]
    endpoints: EndpointAsset[]
    technologies: TechnologyAsset[]
    admin_panels: AdminPanelAsset[]
    exposed_files: ExposedFileAsset[]
    ports?: PortAsset[]
    apps?: AppAsset[]
    neighbors?: NeighborAsset[]
  }
}

// GET/PUT /api/settings
export interface AppSettings {
  enabled_modules: Record<string, boolean>
  agent_default_steps: number
  default_interval_hours: number
  chain_eval_enabled?: boolean
  chain_eval_max_targets?: number
  chain_eval_fuzz?: boolean
  chain_eval_scope?: 'new' | 'all'
  agent_mode_default?: boolean
  auto_discover_domains?: boolean
  vuln_scan_enabled?: boolean
  discovery_enabled?: boolean
  default_discover_interval_hours?: number
  skip_discovery_default?: boolean
  ai: { configured: boolean; model: string | null }
  proxy: { enabled: boolean; pool_size: number }
  notify: { configured: boolean }
}

// Scan diff vs previous scan of the same domain
export interface ScanChanges {
  new_subdomains: string[]
  new_endpoints: { path: string; source: string }[]
  new_findings: string[]
  score_delta: number | null
  previous_grade: string | null
  previous_scan_id: string | null
}

// AI-generated report summary
export interface AiSummary {
  status: 'ok' | 'skipped' | 'error'
  executive_summary?: string
  attack_scenarios?: string[]
  remediation_plan?: { action: string; effort: string; impact: string }[]
  error?: string
}

// Agent Scan (LLM-driven observe → decide → act loop)
export interface AgentScanStep {
  n: number
  tool: string
  target: string
  reasoning: string
  result_summary: string
  new_findings?: string[]
  duration_s?: number
  ts?: string
}

export interface AgentScanStatus {
  agent_scan_id: string
  status: 'running' | 'completed' | 'error'
  domain?: string
  started_at?: string
  steps?: AgentScanStep[]
  final_summary?: string
  findings?: Finding[]
  assets_discovered?: number
  completed_at?: string
  error?: string
}

// GET /api/scans — one entry per scan (DB + in-flight)
export interface ScanListItem {
  scan_id: string
  domain: string
  target?: string
  status: 'queued' | 'running' | 'completed' | 'failed' | 'interrupted' | 'error'
  progress: number
  started_at: string | null
  completed_at: string | null
  grade: string | null
  kind?: ScanKind
}

// GET /api/companies/{id}/assets/diff?from=&to=
export type AssetCategoryKey =
  | 'subdomains'
  | 'ips'
  | 'endpoints'
  | 'technologies'
  | 'admin_panels'
  | 'exposed_files'
  | 'ports'
  | 'apps'
  | 'neighbors'

export interface ModifiedEntry {
  value: string
  field: string
  old: unknown
  new: unknown
}

export interface AssetsDiff {
  from_scan_at: string
  to_scan_at: string
  added: Partial<Record<AssetCategoryKey, string[]>>
  removed: Partial<Record<AssetCategoryKey, string[]>>
  modified?: Partial<Record<AssetCategoryKey, ModifiedEntry[]>>
  score_change: {
    from_grade: string | null
    to_grade: string | null
    delta: number | null
  }
}

// Global compare (GlobalDashboard) — per-company diffs merged client-side,
// every entry tagged with its origin company
export interface GlobalDiffValue {
  value: string
  company: string
}

export interface GlobalModifiedEntry extends ModifiedEntry {
  company: string
}

export interface CompanyScoreChange {
  company: string
  from_grade: string | null
  to_grade: string | null
  delta: number | null
}

export interface GlobalAssetsDiff {
  from_scan_at: string | null
  to_scan_at: string | null
  added: Partial<Record<AssetCategoryKey, GlobalDiffValue[]>>
  removed: Partial<Record<AssetCategoryKey, GlobalDiffValue[]>>
  modified: Partial<Record<AssetCategoryKey, GlobalModifiedEntry[]>>
  score_changes: CompanyScoreChange[]
  skipped_companies: string[]
}

// Combined report
export interface ScanReport {
  scan_id: string
  domain: string
  status: 'completed'
  scanned_at: string
  completed_at: string
  scorecard: Scorecard
  findings: Finding[]
  changes?: ScanChanges
  ai_summary?: AiSummary
  agent_steps?: AgentScanStep[]
  agent_summary?: string
  agent_status?: string
  agent_error?: string
  assets_discovered?: number
  modules: {
    whois: WhoisResult
    dns: DnsResult
    subdomains: SubdomainsResult
    ports: PortsResult
    ssl: SslResult
    headers: HeadersResult
    email: EmailResult
    tech: TechResult
    breach?: BreachResult
    exposed?: ExposedFilesResult
    blacklist?: BlacklistResult
    cors?: CorsResult
    cookies?: CookieSecurityResult
    js_secrets?: JsSecretsResult
    secret_verification?: SecretVerificationResult
    waf?: WafResult
    robots?: RobotsResult
    dnssec?: DnssecResult
    admin?: AdminDiscoveryResult
    tls?: TlsAuditResult
    frontend_cve?: FrontendCveResult
    cloud_storage?: CloudMetadataResult
    api_exposure?: ApiExposureResult
    wayback?: WaybackSecretsResult
    nuclei?: NucleiResult
  }
}

// ── AI Chat Assistant (POST /api/chat) ──────────────────────────────────────
export interface ChatMessage {
  role: 'user' | 'assistant'
  content: string
}

export interface ChatToolUse {
  tool: string
  args: Record<string, unknown>
  result_count: number
}

export interface ChatResponse {
  reply: string
  tools_used: ChatToolUse[]
  blocked?: boolean
  redacted_secrets?: number
}
