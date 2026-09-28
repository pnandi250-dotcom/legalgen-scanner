import express from "express";
import { createScanner } from "./scanner.js";

const app = express();
app.use(express.json({ limit: "1mb" }));

const scanner = createScanner();

app.get("/health", (req, res) => res.json({ ok: true, service: "scanner" }));

app.post("/api/scan", async (req, res) => {
  const { url } = req.body;
  if (!url) return res.status(400).json({ success: false, error: { code: "BAD_REQUEST", message: "URL required" } });

  try {
    const result = await scanner.scan(url);
    res.json({ success: true, data: result });
  } catch (err) {
    console.error("[scan error]", err);
    res.status(500).json({ success: false, error: { code: "INTERNAL", message: "Scan failed" } });
  }
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`Scanner listening on ${PORT}`));
