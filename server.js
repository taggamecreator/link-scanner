import express from "express";
import cors from "cors";
import path from "path";
import { fileURLToPath } from "url";

const app = express();
app.use(cors());
app.use(express.json({ limit: "64kb" }));

// --- Static frontend hosting (public/index.html) ---
const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
app.use(express.static(path.join(__dirname, "public")));

// --- Simple block fingerprints (you can expand these) ---
const BLOCK_FINGERPRINTS = [
  { name: "GoGuardian", patterns: ["goguardian", "blocked by goguardian", "ggrouter"] },
  { name: "Securly", patterns: ["securly", "blocked by securly"] },
  { name: "Lightspeed", patterns: ["lightspeed systems", "relay.lightspeedsystems"] },
  { name: "iBoss", patterns: ["iboss", "iboss cloud"] },
  { name: "FortiGuard", patterns: ["fortiguard", "web filter"] },
  { name: "Cisco Umbrella", patterns: ["umbrella", "opendns", "domain blocked"] },
];

function normalizeUrl(input) {
  let s = (input || "").trim();
  if (!s) throw new Error("Empty URL");
  if (!/^https?:\/\//i.test(s)) s = "https://" + s;
  const u = new URL(s);
  return u.toString();
}

async function tryFetch(url, method, timeoutMs = 8000) {
  const controller = new AbortController();
  const t = setTimeout(() => controller.abort(), timeoutMs);
  const start = Date.now();
  try {
    const res = await fetch(url, {
      method,
      redirect: "manual",
      signal: controller.signal,
      headers: {
        "user-agent": "SchoolPolicyLinkScanner/1.0",
        "accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
      },
    });

    const ms = Date.now() - start;
    const loc = res.headers.get("location");
    const ct = res.headers.get("content-type") || "";

    let bodySnippet = "";
    if (method === "GET") {
      const text = await res.text();
      bodySnippet = text.slice(0, 6000);
    }

    return {
      ok: true,
      status: res.status,
      ms,
      headers: { location: loc, contentType: ct },
      bodySnippet,
    };
  } catch (e) {
    const ms = Date.now() - start;
    return { ok: false, error: String(e?.message || e), ms };
  } finally {
    clearTimeout(t);
  }
}

function detectBlock(snippet) {
  const s = (snippet || "").toLowerCase();

  for (const fp of BLOCK_FINGERPRINTS) {
    if (fp.patterns.some(p => s.includes(p))) return fp.name;
  }

  const generic = [
    "access denied",
    "this site is blocked",
    "content blocked",
    "blocked by policy",
    "web page blocked",
    "filter",
    "policy",
  ];
  if (generic.some(p => s.includes(p))) return "Generic filter page";

  return null;
}

// API endpoint the frontend calls
app.post("/api/scan", async (req, res) => {
  try {
    const target = normalizeUrl(req.body?.url);
    const chain = [];
    let current = target;

    for (let hop = 0; hop < 6; hop++) {
      const head = await tryFetch(current, "HEAD");
      chain.push({ url: current, method: "HEAD", ...head });

      const loc = head.ok ? head.headers.location : null;
      if (loc && [301, 302, 303, 307, 308].includes(head.status)) {
        current = new URL(loc, current).toString();
        continue;
      }

      const needGet = !head.ok || head.status >= 400 || !head.headers.contentType;
      if (needGet) {
        const get = await tryFetch(current, "GET");
        chain.push({ url: current, method: "GET", ...get });
      }
      break;
    }

    const lastGet = chain.slice().reverse().find(x => x.method === "GET");
    const last = lastGet || chain[chain.length - 1];

    const blockVendor = detectBlock(last?.bodySnippet || "");

    let verdict = "uncertain";
    let score = 50;

    if (blockVendor) {
      verdict = "likely_blocked";
      score = 90;
    } else if (last?.ok && last.status >= 200 && last.status < 400) {
      verdict = "likely_allowed";
      score = 80;
    } else if (last?.ok && last.status === 403) {
      verdict = "likely_blocked";
      score = 75;
    } else if (!last?.ok) {
      verdict = "uncertain";
      score = 45;
    }

    res.json({
      input: target,
      verdict,
      score,
      blockVendor,
      chain: chain.map(x => ({
        url: x.url,
        method: x.method,
        ok: x.ok,
        status: x.status ?? null,
        ms: x.ms,
        location: x.headers?.location ?? null,
        contentType: x.headers?.contentType ?? null,
        error: x.error ?? null,
      })),
    });
  } catch (e) {
    res.status(400).json({ error: String(e?.message || e) });
  }
});

// Render port
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`✅ Link scanner running on port ${PORT}`));
