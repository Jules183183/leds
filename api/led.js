const crypto = require("crypto");
const { TUYA_ACCESS_ID, TUYA_ACCESS_SECRET, TUYA_DEVICE_ID, APP_PASSWORD } = process.env;
const BASE = process.env.TUYA_BASE_URL || "https://openapi.tuyaeu.com";
// Plusieurs bandeaux : TUYA_DEVICE_ID = "id1,id2"
const IDS = (TUYA_DEVICE_ID || "").split(",").map((s) => s.trim()).filter(Boolean);

let cached = { token: null, exp: 0 };
let codes = null;

function sign(method, path, body, token, t) {
  const bodyHash = crypto.createHash("sha256").update(body || "").digest("hex");
  const str = TUYA_ACCESS_ID + (token || "") + t + [method, bodyHash, "", path].join("\n");
  return crypto.createHmac("sha256", TUYA_ACCESS_SECRET).update(str).digest("hex").toUpperCase();
}

async function tuya(method, path, bodyObj, token) {
  const t = Date.now().toString();
  const body = bodyObj ? JSON.stringify(bodyObj) : "";
  const headers = { client_id: TUYA_ACCESS_ID, sign: sign(method, path, body, token, t), t, sign_method: "HMAC-SHA256", "Content-Type": "application/json" };
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

async function loadCodes(token) {
  if (codes) return codes;
  const f = await tuya("GET", `/v1.0/devices/${IDS[0]}/functions`, null, token);
  const c = {};
  ((f.result && f.result.functions) || []).forEach((x) => (c[x.code] = x));
  if (Object.keys(c).length) codes = c;
  return c;
}

function rng(c, code, key, dMin, dMax) {
  try {
    const v = JSON.parse(c[code].values);
    const o = key ? v[key] : v;
    if (o && o.max != null) return [o.min != null ? o.min : 0, o.max];
  } catch (e) {}
  return [dMin, dMax];
}
const scale = ([mn, mx], pct) => Math.round(mn + ((mx - mn) * Math.min(100, Math.max(0, pct))) / 100);

function checkPassword(given) {
  const a = Buffer.from(String(given || ""));
  const b = Buffer.from(String(APP_PASSWORD || ""));
  return a.length === b.length && crypto.timingSafeEqual(a, b);
}

function build(c, b) {
  const { action, h, s, v, t, value, seconds } = b;
  const n = (x) => Number(x) || 0;
  const noMode = !Object.keys(c).length;
  const cmds = [];
  if (action === "power") return [{ code: "switch_led", value: !!value }];
  if (action === "timer") {
    if (!c.countdown_1) return null;
    return [{ code: "countdown_1", value: Math.max(0, Math.round(n(seconds))) }];
  }
  cmds.push({ code: "switch_led", value: true });
  if (action === "color") {
    if (c.work_mode || noMode) cmds.push({ code: "work_mode", value: "colour" });
    const hue = Math.min(360, Math.max(0, Math.round(n(h))));
    if (c.colour_data) {
      cmds.push({ code: "colour_data", value: { h: hue, s: scale(rng(c, "colour_data", "s", 0, 255), n(s)), v: scale(rng(c, "colour_data", "v", 0, 255), n(v)) } });
    } else {
      cmds.push({ code: "colour_data_v2", value: { h: hue, s: scale(rng(c, "colour_data_v2", "s", 0, 1000), n(s)), v: scale(rng(c, "colour_data_v2", "v", 0, 1000), n(v)) } });
    }
  } else if (action === "white") {
    if (c.work_mode || noMode) cmds.push({ code: "work_mode", value: "white" });
    if (c.bright_value) cmds.push({ code: "bright_value", value: scale(rng(c, "bright_value", null, 25, 255), n(v)) });
    else cmds.push({ code: "bright_value_v2", value: scale(rng(c, "bright_value_v2", null, 10, 1000), n(v)) });
    if (t != null) {
      if (c.temp_value) cmds.push({ code: "temp_value", value: scale(rng(c, "temp_value", null, 0, 255), n(t)) });
      else if (c.temp_value_v2) cmds.push({ code: "temp_value_v2", value: scale(rng(c, "temp_value_v2", null, 0, 1000), n(t)) });
    }
  } else return undefined;
  return cmds;
}

module.exports = async (req, res) => {
  if (req.method !== "POST") return res.status(405).json({ error: "Méthode non autorisée" });
  const b = req.body || {};
  if (!APP_PASSWORD || !checkPassword(b.password)) {
    await new Promise((r) => setTimeout(r, 1500));
    return res.status(401).json({ error: "Mot de passe incorrect" });
  }
  try {
    let token = await getToken();
    const c = await loadCodes(token);

    if (b.action === "ping") {
      const st = await tuya("GET", `/v1.0/devices/${IDS[0]}/status`, null, token);
      const sw = ((st.result) || []).find((x) => x.code === "switch_led");
      return res.json({ ok: true, on: sw ? !!sw.value : null, devices: IDS.length });
    }

    if (b.action === "debug") {
      const st = await tuya("GET", `/v1.0/devices/${IDS[0]}/status`, null, token);
      const fn = {};
      Object.keys(c).forEach((k) => (fn[k] = c[k].values));
      return res.json({ ok: true, functions: fn, status: st.result || st });
    }

    if (b.action === "white") {
      const n = (x) => Number(x) || 0;
      const known = Object.keys(c).length > 0;
      const seq = [{ code: "switch_led", value: true }];
      if (!known || c.work_mode) seq.push({ code: "work_mode", value: "white" });
      if (c.bright_value_v2 || !known) seq.push({ code: "bright_value_v2", value: scale(rng(c, "bright_value_v2", null, 10, 1000), n(b.v)) });
      if (c.bright_value) seq.push({ code: "bright_value", value: scale(rng(c, "bright_value", null, 25, 255), n(b.v)) });
      if (b.t != null) {
        if (c.temp_value_v2 || !known) seq.push({ code: "temp_value_v2", value: scale(rng(c, "temp_value_v2", null, 0, 1000), n(b.t)) });
        if (c.temp_value) seq.push({ code: "temp_value", value: scale(rng(c, "temp_value", null, 0, 255), n(b.t)) });
      }
      const warn = [];
      for (const cmd of seq) {
        const outs = await Promise.all(IDS.map((id) => tuya("POST", `/v1.0/devices/${id}/commands`, { commands: [cmd] }, token)));
        const bad = outs.find((o) => !o.success);
        if (bad) warn.push(`${cmd.code}: ${bad.msg} (${bad.code})`);
        await new Promise((r) => setTimeout(r, 250));
      }
      return res.json({ ok: true, warn });
    }

    const commands = build(c, b);
    if (commands === undefined) return res.status(400).json({ error: "Action inconnue" });
    if (commands === null) return res.status(501).json({ error: "unsupported" });

    const send = () => Promise.all(IDS.map((id) => tuya("POST", `/v1.0/devices/${id}/commands`, { commands }, token)));
    let outs = await send();
    if (outs.some((o) => o.code === 1010)) { cached = { token: null, exp: 0 }; token = await getToken(); outs = await send(); }
    const bad = outs.find((o) => !o.success);
    if (bad) return res.status(502).json({ error: `${bad.msg || "Erreur Tuya"} (${bad.code}) codes: ${Object.keys(c).join(",")}` });
    return res.json({ ok: true });
  } catch (e) {
    return res.status(500).json({ error: e.message });
  }
};
