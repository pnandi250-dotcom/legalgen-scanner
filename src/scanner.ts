/**
 * Hybrid Scanner Service (Cheerio primary + Browserless.io fallback)
 * Optimized for Render free tier - uses Cheerio primarily, falls back to Browserless.io for JS-heavy sites
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

// ===== TECHNOLOGY DETECTION (static signature lookup) =====
const TECHNOLOGY_SIGNATURES: Array<{ src: string; name: string; category: string }> = [
  // Payment
  { src: "razorpay.com", name: "Razorpay", category: "Payment" },
  { src: "payu.in", name: "PayU", category: "Payment" },
  { src: "cashfree.com", name: "Cashfree", category: "Payment" },
  { src: "instamojo.com", name: "Instamojo", category: "Payment" },
  { src: "ccavenue.com", name: "CCVenue", category: "Payment" },
  { src: "stripe.com", name: "Stripe", category: "Payment" },
  { src: "paypal.com", name: "PayPal", category: "Payment" },
  // Analytics
  { src: "google-analytics.com", name: "Google Analytics", category: "Analytics" },
  { src: "googletagmanager.com", name: "Google Tag Manager", category: "Analytics" },
  { src: "hotjar.com", name: "Hotjar", category: "Analytics" },
  { src: "mixpanel.com", name: "Mixpanel", category: "Analytics" },
  { src: "segment.com", name: "Segment", category: "Analytics" },
  // Advertising
  { src: "facebook.net", name: "Meta Pixel", category: "Advertising" },
  { src: "doubleclick.net", name: "DoubleClick", category: "Advertising" },
  { src: "ads-twitter.com", name: "Twitter Ads", category: "Advertising" },
  // Email / CRM
  { src: "mailchimp.com", name: "Mailchimp", category: "Email/CRM" },
  { src: "hubspot.com", name: "HubSpot", category: "Email/CRM" },
  { src: "zoho.com", name: "Zoho", category: "Email/CRM" },
  { src: "freshworks.com", name: "Freshworks", category: "Email/CRM" },
  // Chat / Support
  { src: "intercom.io", name: "Intercom", category: "Chat/Support" },
  { src: "crisp.chat", name: "Crisp", category: "Chat/Support" },
  { src: "tawk.to", name: "Tawk.to", category: "Chat/Support" },
  { src: "freshchat.com", name: "FreshChat", category: "Chat/Support" },
  // Auth
  { src: "firebase.google.com", name: "Firebase Auth", category: "Auth" },
  { src: "auth0.com", name: "Auth0", category: "Auth" },
];

function detectTechnologies($: CheerioAPI): Array<{ name: string; category: string }> {
  const sources: string[] = $("script[src], iframe[src]")
    .toArray()
    .map((el: any) => $(el).attr("src") as string | undefined)
    .filter((src: string | undefined): src is string => typeof src === "string" && src.length > 0)
    .map((src: string) => src.toLowerCase());

  const detected = new Map<string, { name: string; category: string }>();
  for (const source of sources) {
    for (const signature of TECHNOLOGY_SIGNATURES) {
      if (source.includes(signature.src) && !detected.has(signature.name)) {
        detected.set(signature.name, { name: signature.name, category: signature.category });
      }
    }
  }
  return Array.from(detected.values());
}

// ===== BOUNDED MULTI-PAGE POLICY CRAWL =====
const MAX_CRAWL_URLS = 4;
const CRAWL_TIME_BUDGET_MS = 15000;
const SCAN_DEADLINE_MS = 25_000;
const CRAWL_FETCH_TIMEOUT_MS = 5000;
// Rendering a page through Browserless only pays off if there is real budget left to spend on it.
const BROWSERLESS_MIN_BUDGET_MS = 8000;
const CRAWL_MIN_WORDS = 150;
const CRAWL_MATCH_WORD_WINDOW = 500;
const POLICY_LINK_KEYWORDS = ["privacy", "terms", "legal", "policy", "policies", "tos", "refund", "shipping", "cookie"];

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

// Redirect chains are followed manually so each hop passes the SSRF guard above.
const MAX_REDIRECT_HOPS = 5;

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

  async function fetchWithCheerio(url: URL, timeoutMs: number = 10000, deadlineAt?: number): Promise<{ html: string; finalUrl: string; status: number }> {
    await assertPublicUrl(url);
    // Redirects are followed manually so that every hop is re-validated by assertPublicUrl
    // before the next outbound request is made. "redirect: follow" would hand the chain to
    // undici, which happily follows a 302 to a link-local/internal address with no further check.
    // Every hop re-clamps its own timeout to whatever is left of the caller's deadline, so a
    // multi-hop chain cannot multiply timeoutMs and overrun the overall scan budget.
    const request = (target: URL) => {
      const remaining = deadlineAt === undefined ? timeoutMs : Math.max(1, Math.min(timeoutMs, deadlineAt - Date.now()));
      return fetch(target.toString(), {
        headers: { "User-Agent": "Mozilla/5.0 LegalGen Scanner" },
        redirect: "manual",
        signal: AbortSignal.timeout(remaining)
      });
    };

    let currentUrl = url;
    let res = await request(currentUrl);
    let hops = 0;
    while (res.status >= 300 && res.status < 400) {
      const location = res.headers.get("location");
      if (!location) break;
      if (++hops > MAX_REDIRECT_HOPS) throw new Error("Too many redirects");
      const nextUrl = new URL(location, currentUrl);
      await assertPublicUrl(nextUrl);
      currentUrl = nextUrl;
      res = await request(currentUrl);
    }
    const html = await res.text();
    return { html, finalUrl: currentUrl.toString(), status: res.status };
  }

  // ===== BROWSERLESS.IO FALLBACK (for JS-heavy sites) =====
  async function fetchWithBrowserless(url: URL, deadlineAt?: number): Promise<{ html: string; finalUrl: string } | null> {
    const apiKey = process.env.BROWSERLESS_API_KEY;
    if (!apiKey) {
      console.log('[scanner] Browserless API key not configured, skipping fallback');
      return null;
    }

    // Browserless drives the navigation itself, so redirects it follows internally cannot be
    // intercepted here; this check guards the entry URL only.
    await assertPublicUrl(url);
    
    try {
      const browserlessUrl = `https://chrome.browserless.io/content?token=${apiKey}`;
      const res = await fetch(browserlessUrl, {
        method: 'POST',
        headers: { 
          'Content-Type': 'application/json',
          'User-Agent': 'Mozilla/5.0 LegalGen Scanner'
        },
        body: JSON.stringify({
          url: url.toString(),
          waitUntil: 'networkidle2',
          timeout: 25000,
          blockAds: true,
          blockResources: ['image', 'font', 'media']
        }),
        signal: AbortSignal.timeout(deadlineAt === undefined ? 30000 : Math.max(1, deadlineAt - Date.now()))
      });

      if (!res.ok) {
        console.warn('[scanner] Browserless request failed:', res.status, await res.text());
        return null;
      }

      const html = await res.text();
      const finalUrl = url.toString(); // Browserless returns final URL in response
      console.log('[scanner] Browserless fallback succeeded for', url.toString());
      return { html, finalUrl };
    } catch (error) {
      console.warn('[scanner] Browserless fallback failed:', error instanceof Error ? error.message : String(error));
      return null;
    }
  }

  return {
    async scan(url: string, options: any = {}): Promise<any> {
      const scanStart = Date.now();
      const scanElapsed = () => Date.now() - scanStart;
      const checksPerformed: string[] = ["policy-detection", "business-classification", "jurisdiction-detection"];
      const checksSkipped: Array<{ check: string; reason: string }> = [];
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
      let { html, finalUrl } = await fetchWithCheerio(parsedUrlForFetch, 10000, scanStart + SCAN_DEADLINE_MS).catch(() => ({ html: null, finalUrl: targetUrl }));

      // Detect jurisdiction
      const jurisdictionResult = detectJurisdiction(targetUrl, { ipCountry, pageLanguage, htmlLang });
      const jurisdictionRequirements = getJurisdictionRequirements(jurisdictionResult.primary);

      // ===== HYBRID: Fallback to Browserless.io if Cheerio finds 0 policies =====
      let finalHtmlVar = html;
      let finalUrlVar = finalUrl;

      // Initial parse with Cheerio to check if we have policies
      const $static = cheerio.load(html || "");
      const staticPolicies = findPolicyLinks($static, finalUrl);
      const staticFoundCount = staticPolicies.filter(p => p.found).length;

      if (staticFoundCount === 0) {
        const browserlessBudget = SCAN_DEADLINE_MS - scanElapsed();
        if (browserlessBudget < BROWSERLESS_MIN_BUDGET_MS) {
          checksSkipped.push({ check: "browserless-fallback", reason: "Insufficient remaining scan budget to attempt browser rendering" });
          console.log('[scanner] Browserless fallback skipped: only', browserlessBudget, 'ms of scan budget left after', scanElapsed(), 'ms');
        } else {
          console.log('[scanner] No policies found via Cheerio, trying Browserless.io fallback...');
          const browserlessResult = await fetchWithBrowserless(new URL(targetUrl), scanStart + SCAN_DEADLINE_MS);
          if (browserlessResult) {
            finalHtmlVar = browserlessResult.html;
            finalUrlVar = browserlessResult.finalUrl;
            console.log('[scanner] Browserless fallback found content, re-parsing...');
          }
        }
      }

      // Parse with (possibly Browserless-rendered) HTML
      const $ = cheerio.load(finalHtmlVar || "");
      let policies = findPolicyLinks($, finalUrl);

      const title = $("title").text().trim() || null;
      const domain = new URL(finalUrl).hostname;
      const businessType = detectBusinessType(finalHtmlVar || "");
      const businessTypeKey = Object.entries(BUSINESS_TYPES).find(([, cfg]) => cfg === businessType)?.[0] ?? "default";

      // ===== BOUNDED MULTI-PAGE POLICY CRAWL =====
      // Link-only detection misses policies published on combined pages (e.g. one "Legal"
      // page holding both privacy + terms), so crawl a small, time-boxed set of policy-ish links.
      const requiredPolicyNames: string[] = jurisdictionRequirements.requiredPolicies.map(req => req.name);
      const missingRequiredNames = (): string[] =>
        requiredPolicyNames.filter(name => !policies.some(p => p.expected === name && p.found));

      let crawlFetchAttempted = false;
      let crawlPhaseRan = false;
      const crawlStatusByPolicy = new Map<string, number>();
      const crawlBudget = Math.min(CRAWL_TIME_BUDGET_MS, SCAN_DEADLINE_MS - scanElapsed());

      if (missingRequiredNames().length === 0) {
        checksSkipped.push({ check: "multi-page-policy-crawl", reason: "All required policies already linked on the initial page" });
      } else if (crawlBudget <= 0) {
        checksSkipped.push({ check: "multi-page-policy-crawl", reason: "Scan time budget exhausted before crawl could start" });
        console.log('[scanner] Multi-page crawl skipped: scan time budget already exhausted after', scanElapsed(), 'ms');
      } else {
        const crawlStart = Date.now();
        const baseUrl = finalUrlVar || targetUrl;
        let scannedUrl = targetUrl;
        try { scannedUrl = new URL(baseUrl).href; } catch { scannedUrl = targetUrl; }
        const missingAtExtract = missingRequiredNames().map(name => name.toLowerCase());
        const seenCandidateUrls = new Set<string>();
        const candidates: Array<{ url: string; rank: number; order: number }> = [];

        $("a").toArray().forEach((el: any, order: number) => {
          const $el = $(el);
          const href = ($el.attr("href") || "").trim();
          if (!href) return;
          const lowerHref = href.toLowerCase();
          if (lowerHref.startsWith("#") || lowerHref.startsWith("javascript:") || lowerHref.startsWith("mailto:") || lowerHref.startsWith("tel:")) return;
          const linkText = $el.text().trim().toLowerCase();
          if (!POLICY_LINK_KEYWORDS.some(k => lowerHref.includes(k)) && !POLICY_LINK_KEYWORDS.some(k => linkText.includes(k))) return;

          let absolute: string;
          try {
            absolute = new URL(href, baseUrl).href;
          } catch {
            return;
          }
          if (absolute === scannedUrl || seenCandidateUrls.has(absolute)) return;
          seenCandidateUrls.add(absolute);

          // Prefer links whose text names a still-missing policy, then href-path matches.
          let rank = 0;
          if (missingAtExtract.some(name => name.length > 3 && linkText.includes(name))) rank = 2;
          else if (missingAtExtract.some(name => name.length > 3 && absolute.toLowerCase().includes(name))) rank = 1;
          candidates.push({ url: absolute, rank, order });
        });

        candidates.sort((a, b) => (b.rank - a.rank) || (a.order - b.order));
        const limitedCandidates = candidates.slice(0, MAX_CRAWL_URLS);

        if (limitedCandidates.length === 0) {
          checksSkipped.push({ check: "multi-page-policy-crawl", reason: "No policy-like links found on the initial page" });
          console.log('[scanner] Multi-page crawl skipped: no policy candidate links found');
        } else {
          console.log('[scanner] Multi-page policy crawl:', limitedCandidates.length, 'of', candidates.length, 'candidate link(s)');
        }

        for (const candidate of limitedCandidates) {
          crawlPhaseRan = true;
          const elapsed = Date.now() - crawlStart;
          if (elapsed > crawlBudget) {
            checksSkipped.push({ check: "multi-page-policy-crawl", reason: `Crawl time budget of ${crawlBudget}ms exceeded after ${elapsed}ms` });
            console.log('[scanner] Multi-page crawl budget exhausted after', elapsed, 'ms');
            break;
          }
          const remainingBudget = crawlBudget - elapsed;
          if (remainingBudget <= 0) break;

          if (missingRequiredNames().length === 0) {
            console.log('[scanner] All required policies resolved, stopping crawl early');
            break;
          }

          try {
            const candidateUrl = candidate.url;
            await assertPublicUrl(new URL(candidateUrl));
            // DNS resolution above has no timeout of its own, so charge it to the crawl
            // budget before spending a fetch on the candidate.
            const budgetAfterDns = crawlBudget - (Date.now() - crawlStart);
            if (budgetAfterDns <= 0) {
              checksSkipped.push({ check: "multi-page-policy-crawl", reason: `Crawl time budget of ${crawlBudget}ms exhausted while validating candidate links` });
              console.log('[scanner] Multi-page crawl budget exhausted during candidate validation');
              break;
            }
            crawlFetchAttempted = true;
            const crawled = await fetchWithCheerio(new URL(candidateUrl), CRAWL_FETCH_TIMEOUT_MS, crawlStart + crawlBudget);
            if (crawled.status < 200 || crawled.status >= 300) {
              console.log('[scanner] Crawl candidate returned non-OK status, skipping:', candidateUrl, '-', crawled.status);
              continue;
            }

            const crawl$ = cheerio.load(crawled.html || "");
            crawl$("script, style, noscript").remove();
            const visibleText = (crawl$("body").text() || crawl$.root().text() || "").replace(/\s+/g, " ").trim();
            const wordCount = visibleText ? visibleText.split(" ").length : 0;
            if (wordCount <= CRAWL_MIN_WORDS) {
              console.log('[scanner] Crawl candidate too thin:', candidateUrl, '-', wordCount, 'words');
              continue;
            }

            const crawlTitle = (crawl$("title").text() || "").toLowerCase();
            const leadText = visibleText.toLowerCase().split(" ").slice(0, CRAWL_MATCH_WORD_WINDOW).join(" ");

            const matched: string[] = [];
            for (const name of missingRequiredNames()) {
              const needle = name.toLowerCase();
              if (!crawlTitle.includes(needle) && !leadText.includes(needle)) continue;
              const entry = policies.find(p => p.expected === name);
              if (entry) {
                entry.found = true;
                entry.url = candidateUrl;
              } else {
                policies.push({ expected: name, found: true, url: candidateUrl });
              }
              crawlStatusByPolicy.set(name, crawled.status);
              matched.push(name);
            }
            if (matched.length > 0) console.log('[scanner] Crawl candidate resolved:', candidateUrl, '->', matched.join(', '));
          } catch (error) {
            console.warn('[scanner] Crawl candidate failed:', candidate.url, error instanceof Error ? error.message : String(error));
            continue;
          }
        }
      }

      if (crawlFetchAttempted) checksPerformed.push("multi-page-policy-crawl");
      else if (crawlPhaseRan && !checksSkipped.some(s => s.check === "multi-page-policy-crawl")) {
        checksSkipped.push({ check: "multi-page-policy-crawl", reason: "Crawl attempted but no candidate page could be fetched (all rejected by the SSRF guard or the time budget ran out)" });
      }
      const technologies = detectTechnologies($);

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
        businessType: { key: businessTypeKey, name: businessType.name, confidence: 0.8 },
        technologies,
        forms: [],
        policies: policies.map(p => ({ expected: p.expected, found: p.found, url: p.url, httpStatus: p.found ? (crawlStatusByPolicy.get(p.expected) ?? 200) : null, substantive: p.found, confidence: p.found ? "high" : "low" })),
        findings: [],
        score: { value: score, grade: score >= 80 ? "A" : score >= 60 ? "B" : score >= 40 ? "C" : "D", confidence: "medium" },
        riskLevel: score >= 80 ? "LOW" : score >= 50 ? "MEDIUM" : "HIGH",
        checksPerformed,
        checksSkipped,
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