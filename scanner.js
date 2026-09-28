import * as cheerio from "cheerio";
import { chromium } from "playwright";

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

function findPolicyLinks($, baseUrl) {
  const policies = [
    "Privacy Policy", "Terms of Service", "Refund Policy", "Cookie Policy",
    "Shipping Policy", "Cancellation Policy", "Return Policy", "Disclaimer",
    "Acceptable Use", "SLA", "DMCA", "Community Guidelines", "Data Processing",
    "GDPR", "EULA"
  ];
  return policies.map(name => {
    const link = $(`a:contains("${name}"), a:contains("${name.toLowerCase()}")`).first();
    const href = link.attr("href");
    return { expected: name, found: !!href, url: href ? new URL(href, baseUrl).href : null };
  });
}

export function createScanner() {
  let browser = null;

  async function getBrowser() {
    if (!browser) {
      browser = await chromium.launch({ headless: true, args: ["--no-sandbox", "--disable-setuid-sandbox"] });
    }
    return browser;
  }

  async function fetchWithBrowser(url) {
    const browser = await getBrowser();
    const context = await browser.newContext({ userAgent: "Mozilla/5.0 LegalGen Scanner" });
    const page = await context.newPage();
    try {
      await page.goto(url, { waitUntil: "domcontentloaded", timeout: 20000 });
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
    const res = await fetch(url, { headers: { "User-Agent": "Mozilla/5.0 LegalGen Scanner" }, redirect: "follow" });
    const html = await res.text();
    return { html, finalUrl: res.url };
  }

  return {
    async scan(url) {
      let targetUrl = url.trim();
      if (!targetUrl.startsWith("http")) targetUrl = "https://" + targetUrl;
      new URL(targetUrl);

      let { html, finalUrl } = await fetchWithCheerio(targetUrl).catch(() => ({ html: null, finalUrl: targetUrl }));

      if (!html || html.length < 500) {
        try {
          const result = await fetchWithBrowser(targetUrl);
          html = result.html;
          finalUrl = result.finalUrl;
        } catch {}
      }

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
