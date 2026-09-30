import * as cheerio from "cheerio";
import { chromium } from "playwright";
import { createHash } from "node:crypto";
import net from "node:net";
import { lookup } from "node:dns/promises";

const BUSINESS_TYPES = {
  ecommerce: { name: "E-Commerce", indicators: ["cart", "checkout", "buy", "shipping", "product", "price"], required: ["Privacy Policy", "Terms of Service", "Refund Policy", "Shipping Policy"] },
  saas: { name: "SaaS/Tech", indicators: ["signup", "trial", "pricing", "dashboard", "api", "login"], required: ["Privacy Policy", "Terms of Service", "SLA", "Acceptable Use"] },
  finance: { name: "Finance", indicators: ["loan", "invest", "bank", "kyc", "rbi", "sebi"], required: ["Privacy Policy", "Risk Disclosure", "Grievance Redressal", "KYC Policy"] },
  healthcare: { name: "Healthcare", indicators: ["doctor", "patient", "medical", "hospital", "consultation"], required: ["Privacy Policy", "Medical Disclaimer", "Patient Consent"] },
  default: { name: "General Business", indicators: [], required: ["Privacy Policy", "Terms of Service", "Cookie Policy"] },
};

function detectBusinessType(html) {
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
function findPolicyLinks($, baseUrl) {
  const policies = [
    "Privacy Policy", "Terms of Service", "Refund Policy", "Cookie Policy",
    "Shipping Policy", "Cancellation Policy", "Return Policy", "Disclaimer",
    "Acceptable Use", "SLA", "DMCA", "Community Guidelines", "Data Processing",
    "GDPR", "EULA"
  ];
  
  // Extract all anchor texts once (lowercased for case-insensitive matching)
  const links = $("a").toArray().map(el => {
    const $el = $(el);
    return {
      text: $el.text().trim().toLowerCase(),
      href: $el.attr("href"),
    };
  }).filter(l => l.href); // only links with href
  
  return policies.map(name => {
    const needle = name.toLowerCase();
    // Case-insensitive substring match: find any link whose text includes the policy name
    const match = links.find(l => l.text.includes(needle));
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

function isBlockedAddress(ip) {
  const version = net.isIP(ip);
  if (version === 4) return isBlockedIPv4(ip);
  if (version === 6) return isBlockedIPv6(ip);
  return true;
}

function isBlockedIPv4(ip) {
  const p = ip.split(".").map(Number);
  if (p.length !== 4 || p.some(n => !Number.isInteger(n) || n < 0 || n > 255)) return true;
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

function isBlockedIPv6(ip) {
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

async function assertPublicUrl(url) {
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
const rateLimitMap = new Map();
const RATE_LIMIT_WINDOW = 60 * 1000; // 1 minute
const RATE_LIMIT_MAX = 10; // 10 requests per minute per IP

function checkRateLimit(ip) {
  const now = Date.now();
  const key = `${ip}:${Math.floor(now / RATE_LIMIT_WINDOW)}`;
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
  let browser = null;

  async function getBrowser() {
    if (!browser) {
      browser = await chromium.launch({ headless: true, args: ["--no-sandbox", "--disable-setuid-sandbox"] });
    }
    return browser;
  }

  async function fetchWithBrowser(url) {
    await assertPublicUrl(url);
    const browser = await getBrowser();
    const context = await browser.newContext({ userAgent: "Mozilla/5.0 LegalGen Scanner" });
    const page = await context.newPage();
    try {
      // ===== FIX (b): Wait for network idle (JS rendered) instead of domcontentloaded =====
      await page.goto(url, { waitUntil: "networkidle", timeout: 25000 });
      const html = await page.content();
      const finalUrl = page.url();
      await context.close();
      return { html, finalUrl };
    } catch (e) {
      await context.close();
      throw e;
    }
  }

  async function fetchWithCheerio(url) {
    await assertPublicUrl(url);
    const res = await fetch(url, { 
      headers: { "User-Agent": "Mozilla/5.0 LegalGen Scanner" }, 
      redirect: "follow",
      signal: AbortSignal.timeout(10000)
    });
    const html = await res.text();
    return { html, finalUrl: res.url };
  }

  return {
    async scan(url) {
      let targetUrl = url.trim();
      if (!targetUrl.startsWith("http")) targetUrl = "https://" + targetUrl;
      const parsedUrl = new URL(targetUrl);
      
      // Validate URL before scanning
      await assertPublicUrl(parsedUrl);

      // Fetch static HTML first
      let { html, finalUrl } = await fetchWithCheerio(targetUrl).catch(() => ({ html: null, finalUrl: targetUrl }));

      // ===== FIX (a): Fall back to browser if NO policies found in static HTML (not just short HTML) =====
      const $static = cheerio.load(html || "");
      const staticPolicies = findPolicyLinks($static, finalUrl);
      const staticFoundCount = staticPolicies.filter(p => p.found).length;

      if (!html || html.length < 500 || staticFoundCount === 0) {
        try {
          const result = await fetchWithBrowser(targetUrl);
          html = result.html;
          finalUrl = result.finalUrl;
        } catch {}
      }

      // Re-parse with (possibly browser-rendered) HTML
      const $ = cheerio.load(html || "");
      const title = $("title").text().trim() || null;
      const domain = new URL(finalUrl).hostname;
      const businessType = detectBusinessType(html || "");
      const policies = findPolicyLinks($, finalUrl);

      const foundPages = policies.filter(p => p.found).map(p => ({ name: p.expected, url: p.url }));
      const missingPages = policies.filter(p => !p.found).map(p => p.expected);
      const score = Math.max(0, 100 - missingPages.length * 15);

      const complianceResults = policies.map(p => ({
        type: p.expected.toLowerCase().replace(/\s+/g, "-"),
        label: p.expected,
        page: p.expected,
        found: p.found,
        url: p.found ? p.url : null,
        source: p.found ? "Detected" : "",
        severity: ["Privacy Policy", "Terms of Service"].includes(p.expected) ? "critical" : "important",
        description: `Required for ${businessType.name}`,
        generateType: p.expected.toLowerCase().replace(/\s+/g, "-"),
      }));

      return {
        scannerVersion: "1.0",
        url: targetUrl,
        finalUrl,
        domain,
        scannedAt: new Date().toISOString(),
        title,
        businessType: { key: Object.keys(BUSINESS_TYPES).find(k => BUSINESS_TYPES[k] === businessType) || "default", name: businessType.name, confidence: 0.8 },
        technologies: [],
        forms: [],
        policies: policies.map(p => ({ expected: p.expected, found: p.found, url: p.url, httpStatus: p.found ? 200 : null, substantive: p.found, confidence: p.found ? "high" : "low" })),
        findings: [],
        score: { value: score, grade: score >= 80 ? "A" : score >= 60 ? "B" : score >= 40 ? "C" : "D", confidence: "medium" },
        riskLevel: score >= 80 ? "LOW" : score >= 50 ? "MEDIUM" : "HIGH",
        checksPerformed: ["policy-detection", "business-classification"],
        checksSkipped: [],
      };
    }
  };
}