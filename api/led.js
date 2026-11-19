const crypto = require("crypto");

const { TUYA_ACCESS_ID, TUYA_ACCESS_SECRET, TUYA_DEVICE_ID, APP_PASSWORD } = process.env;
// Europe : tuyaeu | USA : tuyaus | Chine : tuyacn | Inde : tuyain
const BASE = process.env.TUYA_BASE_URL || "https://openapi.tuyaeu.com";

let cached = { token: null, exp: 0 };

function sign(method, path, body, token, t) {
  const bodyHash = crypto.createHash("sha256").update(body || "").digest("hex");
  const stringToSign = [method, bodyHash, "", path].join("\n");
  const str = TUYA_ACCESS_ID + (token || "") + t + stringToSign;
  return crypto.createHmac("sha256", TUYA_ACCESS_SECRET).update(str).digest("hex").toUpperCase();
}

async function tuya(method, path, bodyObj, token) {
  const t = Date.now().toString();
  const body = bodyObj ? JSON.stringify(bodyObj) : "";
  const headers = {
    client_id: TUYA_ACCESS_ID,
    sign: sign(method, path, body, token, t),
    t,
    sign_method: "HMAC-SHA256",
    "Content-Type": "application/json",
  };
  if (token) headers.access_token = token;
  const r = await fetch(BASE + path, { method, headers, body: body || undefined });
  return r.json();
}

async function getToken() {
  if (cached.token && Date.now() < cached.exp) return cached.token;
  const res = await tuya("GET", "/v1.0/token?grant_type=1");
  if (!res.success) throw new Error("Token Tuya refusé : " + res.msg);
  cached = { token: res.result.access_token, exp: Date.now() + (res.result.expire_time - 60) * 1000 };
  return cached.token;
}

function checkPassword(given) {
  const a = Buffer.from(String(given || ""));
  const b = Buffer.from(String(APP_PASSWORD || ""));
  return a.length === b.length && crypto.timingSafeEqual(a, b);
}

const clamp = (n, lo, hi) => Math.min(hi, Math.max(lo, Math.round(Number(n) || 0)));

module.exports = async (req, res) => {
  if (req.method !== "POST") return res.status(405).json({ error: "Méthode non autorisée" });

  const { password, action, h, s, v, value } = req.body || {};

  if (!APP_PASSWORD || !checkPassword(password)) {
    await new Promise((r) => setTimeout(r, 1500)); // ralentit les essais
    return res.status(401).json({ error: "Mot de passe incorrect" });
  }

  let commands;
  let codes = {};
  try {
    const token0 = await getToken();
    const f = await tuya("GET", `/v1.0/devices/${TUYA_DEVICE_ID}/functions`, null, token0);
    ((f.result && f.result.functions) || []).forEach((x) => (codes[x.code] = x));
  } catch (e) {}
  const has = (c) => !!codes[c];

  if (action === "ping") {
    return res.json({ ok: true });
  } else if (action === "power") {
    commands = [{ code: "switch_led", value: !!value }];
  } else if (action === "color") {
    commands = [{ code: "switch_led", value: true }];
    if (has("work_mode") || !Object.keys(codes).length) commands.push({ code: "work_mode", value: "colour" });
    if (has("colour_data")) {
      commands.push({ code: "colour_data", value: { h: clamp(h, 0, 360), s: Math.round(clamp(s, 0, 100) * 2.55), v: Math.round(clamp(v, 1, 100) * 2.55) } });
    } else {
      commands.push({ code: "colour_data_v2", value: { h: clamp(h, 0, 360), s: clamp(s, 0, 100) * 10, v: clamp(v, 1, 100) * 10 } });
    }
  } else if (action === "white") {
    commands = [{ code: "switch_led", value: true }];
    if (has("work_mode") || !Object.keys(codes).length) commands.push({ code: "work_mode", value: "white" });
    if (has("bright_value")) commands.push({ code: "bright_value", value: Math.max(25, Math.round(clamp(v, 1, 100) * 2.55)) });
    else commands.push({ code: "bright_value_v2", value: Math.max(10, clamp(v, 1, 100) * 10) });
  } else {
    return res.status(400).json({ error: "Action inconnue" });
  }

  try {
    const token = await getToken();
    const out = await tuya("POST", `/v1.0/devices/${TUYA_DEVICE_ID}/commands`, { commands }, token);
    if (!out.success) return res.status(502).json({ error: (out.msg || "Erreur Tuya") + " (" + (out.code || "?") + ") codes: " + Object.keys(codes).join(","), code: out.code });
    return res.json({ ok: true });
  } catch (e) {
    return res.status(500).json({ error: e.message });
  }
};
