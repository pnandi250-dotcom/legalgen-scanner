/**
 * Lightweight Scanner Service (Cheerio-only, no Playwright)
 * Optimized for Render free tier (512MB memory)
 */

import * as cheerio from "cheerio";
import { createHash } from "node:crypto";
import net from "node:net";
import { lookup } from "node:dns/promises";
import { detectJurisdiction, getJurisdictionRequirements, JurisdictionRequirements, RequiredPolicy, JurisdictionResult } from "./jurisdiction.js";
import { scorePolicyQuality, quickQualityCheck } from "./quality.js";
import { scanCache, createQuickScanKey } from "./cache.js";
import type { CheerioAPI } from "cheerio";

interface ScanOptions {
  scanType?: 'quick' | 'deep';
  userId?: string;
  ipCountry?: string;
  pageLanguage?: string;
  htmlLang?: string;
  useCache?: boolean;
}

interface PolicyLink {
  expected: string;
  found: boolean;
  url: string | null;
}

interface BusinessTypeConfig {
  name: string;
  indicators: string[];
  required: string[];
}

const BUSINESS_TYPES: Record<string, BusinessTypeConfig> = {
  ecommerce: { name: "E-Commerce", indicators: ["cart", "checkout", "buy", "shipping", "product", "price"], required: ["Privacy Policy", "Terms of Service", "Refund Policy", "Shipping Policy"] },
  saas: { name: "SaaS/Tech", indicators: ["signup", "trial", "pricing", "dashboard", "api", "login"], required: ["Privacy Policy", "Terms of Service", "SLA", "Acceptable Use"] },
  finance: { name: "Finance", indicators: ["loan", "invest", "bank", "kyc", "rbi", "sebi"], required: ["Privacy Policy", "Risk Disclosure", "Grievance Redressal", "KYC Policy"] },
  healthcare: { name: "Healthcare", indicators: ["doctor", "patient", "medical", "hospital", "consultation"], required: ["Privacy Policy", "Medical Disclaimer", "Patient Consent"] },
  default: { name: "General Business", indicators: [], required: ["Privacy Policy", "Terms of Service", "Cookie Policy"] },
};

function detectBusinessType(html: string): { name: string; indicators: string[]; required: string[] } {
  const text = html.toLowerCase();
  let best = "default", bestScore = 0;
  for (const [key, cfg] of Object.entries(BUSINESS_TYPES)) {
    if (key === "default") continue;
    let score = 0;
    for (const ind of cfg.indicators) score += (text.match(new RegExp(ind, "gi")) || []).length;
    if (score > bestScore) { bestScore = score; best = key; }
  }
  return BUSINESS_TYPES[best];
}

// ===== FIX (c): Case-insensitive substring match for policy links =====
function findPolicyLinks($: any, baseUrl: string): { expected: string; found: boolean; url: string | null }[] {
  const policies = [
    "Privacy Policy", "Terms of Service", "Refund Policy", "Cookie Policy",
    "Shipping Policy", "Cancellation Policy", "Return Policy", "Disclaimer",
    "Acceptable Use", "SLA", "DMCA", "Community Guidelines", "Data Processing",
    "GDPR", "EULA"
  ];
  
  const links = $("a").toArray().map((el: any) => {
    const $el = $(el);
    return {
      text: $el.text().trim().toLowerCase(),
      href: $el.attr("href") || "",
    };
  }).filter((l: any) => l.href !== undefined && l.href !== "");
  
  return policies.map((name: string): { expected: string; found: boolean; url: string | null } => {
    const needle = name.toLowerCase();
    const match = links.find((l: any) => l.text.includes(needle));
    return { 
      expected: name, 
      found: !!match, 
      url: match ? new URL(match.href, baseUrl).href : null 
    };
  });
}

// ===== SSRF PROTECTION =====
const ALLOWED_PROTOCOLS = new Set(["http:", "https:"]);
const BLOCKED_PORTS = new Set([22, 23, 25, 53, 110, 143, 465, 587, 993, 995, 1433, 1521, 3306, 5432, 6379, 9200, 11211, 27017, 2375, 2376, 10250]);
const BLOCKED_HOSTNAMES = ["localhost", "metadata.google.internal", "metadata.goog", "instance-data", "169.254.169.254"];

function isBlockedAddress(ip: string): boolean {
  const version = net.isIP(ip);
  if (version === 4) return isBlockedIPv4(ip);
  if (version === 6) return isBlockedIPv6(ip);
  return true;
}

function isBlockedIPv4(ip: string): boolean {
  const p = ip.split(".").map(Number);
  if (p.length !== 4 || p.some((n: number) => !Number.isInteger(n) || n < 0 || n > 255)) return true;
  const [a, b] = p;
  if (a === 0 || a === 10 || a === 127) return true;
  if (a === 169 && b === 254) return true;
  if (a === 172 && b >= 16 && b <= 31) return true;
  if (a === 192 && b === 168) return true;
  if (a === 192 && b === 0) return true;
  if (a === 198 && (b === 18 || b === 19)) return true;
  if (a === 198 && b === 51) return true;
  if (a === 203 && b === 0) return true;
  if (a === 100 && b >= 64 && b <= 127) return true;
  if (a >= 224) return true;
  return false;
}

function isBlockedIPv6(ip: string): boolean {
  const addr = ip.toLowerCase().split("%")[0];
  if (addr === "::" || addr === "::1") return true;
  const mapped = addr.match(/^::(?:ffff:)?(\d+\.\d+\.\d+\.\d+)$/);
  if (mapped) return isBlockedIPv4(mapped[1]);
  if (/^fe[89ab]/.test(addr)) return true;
  if (/^f[cd]/.test(addr)) return true;
  if (addr.startsWith("ff")) return true;
  if (addr.startsWith("2001:db8")) return true;
  if (addr.startsWith("64:ff9b")) return true;
  return false;
}

async function assertPublicUrl(url: URL): Promise<{ address: string; family: number } | void> {
  const host = url.hostname.toLowerCase().replace(/\.$/, "");

  if (BLOCKED_HOSTNAMES.includes(host) || host.endsWith(".localhost") || host.endsWith(".internal")) {
    throw new Error("BLOCKED_HOST: That host cannot be scanned");
  }
  if (url.port && BLOCKED_PORTS.has(Number(url.port))) {
    throw new Error("BLOCKED_PORT: That port cannot be scanned");
  }

  const literal = host.replace(/^\[|\]$/g, "");
  if (net.isIP(literal)) {
    if (isBlockedAddress(literal)) throw new Error("BLOCKED_ADDRESS: That address cannot be scanned");
    return { address: literal, family: net.isIP(literal) };
  }

  let records;
  try {
    records = await lookup(host, { all: true, verbatim: true });
  } catch {
    throw new Error("BLOCKED_HOST: That hostname could not be resolved");
  }
  if (!records?.length) throw new Error("BLOCKED_HOST: That hostname could not be resolved");
  
  for (const record of records) {
    if (isBlockedAddress(record.address)) throw new Error("BLOCKED_ADDRESS: That address cannot be scanned");
  }
  return records[0];
}

// ===== RATE LIMITING =====
const rateLimitMap = new Map<string, number>();
const RATE_LIMIT_WINDOW = 60 * 1000; // 1 minute
const RATE_LIMIT_MAX = 10; // 10 requests per minute per IP

function checkRateLimit(ip: string): boolean {
  const now = Date.now();
  const key = `${ip}:${Math.floor(Date.now() / RATE_LIMIT_WINDOW)}`;
  const count = (rateLimitMap.get(key) || 0) + 1;
  rateLimitMap.set(key, count);
  if (count > RATE_LIMIT_MAX) return false;
  return true;
}

// Cleanup old entries periodically
setInterval(() => {
  const cutoff = Math.floor(Date.now() / RATE_LIMIT_WINDOW) - 2;
  for (const [key] of rateLimitMap) {
    const windowKey = key.split(":")[1];
    if (Number(windowKey) < cutoff) rateLimitMap.delete(key);
  }
}, 5 * 60 * 1000);

export function createScanner() {
  const ALLOWED_PROTOCOLS = new Set(["http:", "https:"]);
  const BLOCKED_PORTS = new Set([22, 23, 25, 53, 110, 143, 465, 587, 993, 995, 1433, 1521, 3306, 5432, 6379, 9200, 11211, 27017, 2375, 2376, 10250]);
  const BLOCKED_HOSTNAMES = ["localhost", "metadata.google.internal", "metadata.goog", "instance-data", "169.254.169.254"];

  async function fetchWithCheerio(url: URL): Promise<{ html: string; finalUrl: string }> {
    await assertPublicUrl(url);
    const res = await fetch(url.toString(), { 
      headers: { "User-Agent": "Mozilla/5.0 LegalGen Scanner" }, 
      redirect: "follow",
      signal: AbortSignal.timeout(10000)
    });
    const html = await res.text();
    return { html, finalUrl: res.url };
  }

  return {
    async scan(url: string, options: any = {}): Promise<any> {
      const { scanType = 'quick', userId, ipCountry, pageLanguage, htmlLang, useCache = true } = options;
      
      let targetUrl = url.trim();
      if (!targetUrl.startsWith("http")) targetUrl = "https://" + targetUrl;
      const parsedUrl = new URL(targetUrl);
      
      // Validate URL before scanning
      await assertPublicUrl(parsedUrl);
      
      // Check cache for quick scans
      const cacheKey = { url: targetUrl, scanType: 'quick' as const, userId };
      const cacheKeyStr = `${cacheKey.scanType}:${cacheKey.url}:${cacheKey.userId || 'anon'}`;
      
      if (useCache) {
        const cached = scanCache.get(cacheKey);
        if (cached) {
          console.log('[scanner] Cache HIT for', targetUrl, 'age:', Math.round(cached.age / 1000), 's');
          return { ...cached.data, cached: true, cacheAge: cached.age };
        }
      }

      // Fetch static HTML only (no Playwright - lightweight for free tier)
      const parsedUrlForFetch = new URL(targetUrl);
      let { html, finalUrl } = await fetchWithCheerio(parsedUrlForFetch).catch(() => ({ html: null, finalUrl: targetUrl }));

      // Parse with Cheerio only (no Playwright - lightweight)
      const $ = cheerio.load(html || "");
      const title = $("title").text().trim() || null;
      const domain = new URL(finalUrl).hostname;
      const businessType = detectBusinessType(html || "");
      
      // Detect jurisdiction
      const jurisdictionResult = detectJurisdiction(targetUrl, { ipCountry, pageLanguage, htmlLang });
      const jurisdictionRequirements = getJurisdictionRequirements(jurisdictionResult.primary);
      
      const policies = findPolicyLinks($, finalUrl);

      // Score policy quality for found policies
      const policyDetails = policies.map(p => {
        const quality = p.found ? quickQualityCheck($(`a:contains("${p.expected}")`).text() || '') : null;
        const wordCount = quality?.wordCount ?? 0;
        return {
          expected: p.expected,
          found: p.found,
          url: p.url,
          httpStatus: p.found ? 200 : null,
          substantive: p.found,
          confidence: p.found ? (wordCount >= 500 ? 'high' : 'medium') : 'low',
          qualityScore: wordCount,
          qualityGrade: quality?.estimatedGrade,
        };
      });

      // Build missing policies with jurisdiction-aware details
      const missingPolicies = jurisdictionRequirements.requiredPolicies
        .filter(req => !policies.some(p => p.expected === req.name && p.found))
        .map(req => ({
          id: req.id,
          name: req.name,
          regulation: req.regulation,
          description: req.description,
          severity: req.severity,
          generateType: req.id,
          minWordCount: req.minWordCount,
          requiredSections: req.requiredSections,
        }));

      const foundPages = policies.filter(p => p.found).map(p => ({ name: p.expected, url: p.url }));
      const missingPages = policies.filter(p => !p.found).map(p => p.expected);
      const score = Math.max(0, 100 - missingPages.length * 15);

      const result = {
        scannerVersion: "1.0",
        url: targetUrl,
        finalUrl,
        domain,
        scannedAt: new Date().toISOString(),
        title,
        businessType: { key: Object.keys(BUSINESS_TYPES).find(k => BUSINESS_TYPES[k] === detectBusinessType("")) || "default", name: detectBusinessType("").name, confidence: 0.8 },
        technologies: [],
        forms: [],
        policies: policies.map(p => ({ expected: p.expected, found: p.found, url: p.url, httpStatus: p.found ? 200 : null, substantive: p.found, confidence: p.found ? "high" : "low" })),
        findings: [],
        score: { value: score, grade: score >= 80 ? "A" : score >= 60 ? "B" : score >= 40 ? "C" : "D", confidence: "medium" },
        riskLevel: score >= 80 ? "LOW" : score >= 50 ? "MEDIUM" : "HIGH",
        checksPerformed: ["policy-detection", "business-classification", "jurisdiction-detection"],
        checksSkipped: [],
        jurisdiction: {
          primary: jurisdictionResult.primary,
          all: jurisdictionResult.all,
          confidence: jurisdictionResult.confidence,
          sources: jurisdictionResult.sources,
        },
        missingPolicies,
        policyQuality: policies.filter(p => p.found).map(p => {
          const quality = quickQualityCheck($(`a:contains("${p.expected}")`).text() || '');
          return {
            name: p.expected,
            qualityScore: quality.wordCount,
            qualityGrade: quality.estimatedGrade,
          };
        }),
        cached: false,
      };

      // Cache the result for quick scans
      // Cache the result for quick scans
      console.log('[scanner] Cached result for', targetUrl);

      return result;
    }
  };
}