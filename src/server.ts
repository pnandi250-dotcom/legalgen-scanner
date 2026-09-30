import express, { Request, Response, NextFunction } from "express";
import { createScanner } from "./scanner.js";

const app = express();
app.use(express.json({ limit: "1mb" }));

const scanner = createScanner();
const API_KEY = process.env.SCANNER_API_KEY || "dev-scanner-key-change-in-production";

// ===== AUTHENTICATION MIDDLEWARE =====
function requireApiKey(req: Request, res: Response, next: NextFunction): void {
  const apiKey = req.headers["x-api-key"] || req.query.api_key;
  if (!apiKey || apiKey !== API_KEY) {
    res.status(401).json({ 
      success: false, 
      error: { code: "UNAUTHORIZED", message: "Invalid or missing API key" } 
    });
    return;
  }
  next();
}

// ===== RATE LIMITING MIDDLEWARE =====
const rateLimitMap = new Map<string, number>();
const RATE_LIMIT_WINDOW = 60 * 1000; // 1 minute
const RATE_LIMIT_MAX = 20; // 20 requests per minute per IP

function rateLimit(req: Request, res: Response, next: NextFunction): void {
  const ip = req.ip || req.socket.remoteAddress || "unknown";
  const now = Date.now();
  const key = `${ip}:${Math.floor(Date.now() / RATE_LIMIT_WINDOW)}`;
  const count = (rateLimitMap.get(key) || 0) + 1;
  rateLimitMap.set(key, count);
  
  res.setHeader("X-RateLimit-Limit", RATE_LIMIT_MAX);
  res.setHeader("X-RateLimit-Remaining", Math.max(0, RATE_LIMIT_MAX - count));
  
  if (count > RATE_LIMIT_MAX) {
    res.status(429).json({ 
      success: false, 
      error: { code: "RATE_LIMITED", message: "Too many requests. Try again later." } 
    });
    return;
  }
  next();
}

// Cleanup old entries
setInterval(() => {
  const cutoff = Math.floor(Date.now() / RATE_LIMIT_WINDOW) - 2;
  for (const [key] of rateLimitMap) {
    const windowKey = key.split(":")[1];
    if (Number(windowKey) < cutoff) rateLimitMap.delete(key);
  }
}, 5 * 60 * 1000);

// ===== ROUTES =====
app.get("/health", (_req: Request, res: Response) => res.json({ ok: true, service: "scanner" }));

// Apply auth and rate limiting to scan endpoint
app.post("/api/scan", requireApiKey, rateLimit, async (req: Request, res: Response) => {
  const { url } = req.body;
  if (!url) return res.status(400).json({ success: false, error: { code: "BAD_REQUEST", message: "URL required" } });

  // Basic URL validation
  try {
    const parsed = new URL(url.startsWith("http") ? url : "https://" + url);
    if (!["http:", "https:"].includes(parsed.protocol)) {
      return res.status(400).json({ success: false, error: { code: "BAD_REQUEST", message: "Only HTTP/HTTPS URLs allowed" } });
    }
  } catch {
    return res.status(400).json({ success: false, error: { code: "BAD_REQUEST", message: "Invalid URL format" } });
  }

  try {
    const result = await scanner.scan(url);
    res.json({ success: true, data: result });
  } catch (err: unknown) {
    console.error("[scan error]", err);
    const message = err instanceof Error && err.message?.startsWith("BLOCKED_") ? err.message : "Scan failed";
    const code = err instanceof Error && err.message?.startsWith("BLOCKED_") ? err.message.split(":")[0] : "INTERNAL";
    res.status(code === "INTERNAL" ? 500 : 400).json({ success: false, error: { code, message } });
  }
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`Scanner listening on ${PORT} (API key: ${API_KEY === "dev-scanner-key-change-in-production" ? "DEFAULT - CHANGE IN PRODUCTION" : "CONFIGURED"})`));