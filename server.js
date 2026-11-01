const express = require("express");
const session = require("express-session");
const helmet = require("helmet");
const fs = require("node:fs");
const path = require("node:path");
const crypto = require("node:crypto");

const app = express();
const PORT = Number(process.env.PORT || 10000);
const DATA_DIR = process.env.DATA_DIR || path.join(__dirname, "data");
const CONFIG_FILE = path.join(DATA_DIR, "guild-configs.json");
const DISCORD_API = "https://discord.com/api/v10";
const OAUTH_SCOPES = "identify guilds";
const CLIENT_ID = process.env.DISCORD_CLIENT_ID;
const CLIENT_SECRET = process.env.DISCORD_CLIENT_SECRET;
const BOT_TOKEN = process.env.DISCORD_BOT_TOKEN;
const BASE_URL = (process.env.APP_BASE_URL || "").replace(/\/$/, "");
const SESSION_SECRET = process.env.SESSION_SECRET;

if (!SESSION_SECRET) console.warn("[config] SESSION_SECRET is not set. Configure it in Render before enabling public dashboard access.");
if (!CLIENT_ID || !CLIENT_SECRET || !BOT_TOKEN || !BASE_URL) {
  console.warn("[config] Set DISCORD_CLIENT_ID, DISCORD_CLIENT_SECRET, DISCORD_BOT_TOKEN and APP_BASE_URL in Render to enable Discord sign-in and live guild data.");
}

fs.mkdirSync(DATA_DIR, { recursive: true });
function readConfigs() {
  try { return JSON.parse(fs.readFileSync(CONFIG_FILE, "utf8")); }
  catch { return {}; }
}
let configs = readConfigs();
function saveConfigs() {
  const tmp = CONFIG_FILE + ".tmp";
  fs.writeFileSync(tmp, JSON.stringify(configs, null, 2), { mode: 0o600 });
  fs.renameSync(tmp, CONFIG_FILE);
}
function callbackUrl() { return BASE_URL + "/auth/discord/callback"; }
function requireOAuth(req, res, next) {
  if (!req.session.user || !req.session.accessToken) return res.status(401).json({ error: "Sign in with Discord first." });
  next();
}
function permissionsAllowManage(permissions) {
  try { const p = BigInt(permissions); return (p & 0x20n) !== 0n || (p & 0x8n) !== 0n; }
  catch { return false; }
}
async function discordFetch(url, options = {}) {
  const response = await fetch(url, options);
  const raw = await response.text();
  let data = {};
  try { data = raw ? JSON.parse(raw) : {}; } catch {}
  if (!response.ok) {
    const error = new Error(data.message || "Discord API request failed");
    error.status = response.status;
    throw error;
  }
  return data;
}
async function getManageableGuilds(req) {
  const [userGuilds, botGuilds] = await Promise.all([
    discordFetch(DISCORD_API + "/users/@me/guilds", { headers: { Authorization: "Bearer " + req.session.accessToken } }),
    discordFetch(DISCORD_API + "/users/@me/guilds", { headers: { Authorization: "Bot " + BOT_TOKEN } })
  ]);
  const botIds = new Set(botGuilds.map(g => g.id));
  return userGuilds.filter(g => permissionsAllowManage(g.permissions) && botIds.has(g.id))
    .map(g => ({ id: g.id, name: g.name, icon: g.icon, approximate: false }))
    .sort((a,b) => a.name.localeCompare(b.name));
}
app.disable("x-powered-by");
app.set("trust proxy", 1);
app.use(helmet({ contentSecurityPolicy: { directives: { defaultSrc: ["'self'"], styleSrc: ["'self'", "'unsafe-inline'"], scriptSrc: ["'self'"], imgSrc: ["'self'", "https://cdn.discordapp.com", "data:"], connectSrc: ["'self'"], objectSrc: ["'none'"], upgradeInsecureRequests: [] } } }));
app.use(express.json({ limit: "20kb" }));
app.use(session({
  name: "oryn.sid",
  secret: SESSION_SECRET || crypto.randomBytes(32).toString("hex"),
  resave: false,
  saveUninitialized: false,
  cookie: { httpOnly: true, secure: process.env.NODE_ENV === "production", sameSite: "lax", maxAge: 8 * 60 * 60 * 1000 }
}));
app.use(express.static(path.join(__dirname, "public"), { extensions: ["html"] }));

app.get("/health", (_req, res) => res.status(200).json({ ok: true, service: "oryn-dashboard" }));
app.get("/api/status", (req, res) => res.json({
  authenticated: Boolean(req.session.user),
  user: req.session.user || null,
  configured: Boolean(CLIENT_ID && CLIENT_SECRET && BOT_TOKEN && BASE_URL && SESSION_SECRET)
}));
app.get("/auth/discord", (req, res) => {
  if (!CLIENT_ID || !CLIENT_SECRET || !BASE_URL) return res.status(503).send("Discord OAuth is not configured yet. Add DISCORD_CLIENT_ID, DISCORD_CLIENT_SECRET and APP_BASE_URL in Render.");
  const state = crypto.randomBytes(24).toString("hex");
  req.session.oauthState = state;
  const query = new URLSearchParams({ client_id: CLIENT_ID, redirect_uri: callbackUrl(), response_type: "code", scope: OAUTH_SCOPES, state, prompt: "consent" });
  res.redirect("https://discord.com/oauth2/authorize?" + query.toString());
});
app.get("/auth/discord/callback", async (req, res) => {
  try {
    if (!req.query.code || !req.query.state || req.query.state !== req.session.oauthState) return res.status(400).send("Invalid or expired sign-in request. Return to the dashboard and try again.");
    delete req.session.oauthState;
    const body = new URLSearchParams({ client_id: CLIENT_ID, client_secret: CLIENT_SECRET, grant_type: "authorization_code", code: String(req.query.code), redirect_uri: callbackUrl() });
    const token = await discordFetch("https://discord.com/api/v10/oauth2/token", { method: "POST", headers: { "Content-Type": "application/x-www-form-urlencoded" }, body });
    const user = await discordFetch(DISCORD_API + "/users/@me", { headers: { Authorization: "Bearer " + token.access_token } });
    req.session.accessToken = token.access_token;
    req.session.user = { id: user.id, username: user.username, global_name: user.global_name || user.username, avatar: user.avatar };
    res.redirect("/dashboard.html");
  } catch (error) {
    console.error("[oauth]", error.message);
    res.status(502).send("Discord sign-in failed. Check the OAuth credentials and callback URL in Render, then try again.");
  }
});
app.post("/auth/logout", requireOAuth, (req, res) => req.session.destroy(() => res.clearCookie("oryn.sid", { httpOnly: true, sameSite: "lax", secure: process.env.NODE_ENV === "production" }).json({ ok: true })));

app.get("/api/guilds", requireOAuth, async (req, res) => {
  try { res.json({ guilds: await getManageableGuilds(req) }); }
  catch (error) { console.error("[guilds]", error.message); res.status(error.status === 401 ? 401 : 502).json({ error: "Could not load servers. Check the bot token and Discord permissions." }); }
});
app.get("/api/guilds/:id/config", requireOAuth, async (req, res) => {
  try {
    const guilds = await getManageableGuilds(req);
    const guild = guilds.find(g => g.id === req.params.id);
    if (!guild) return res.status(403).json({ error: "You must manage this server and have Oryn in it to change settings." });
    res.json({ guild, config: configs[guild.id] || { welcomeEnabled: false, moderationAlerts: true, ticketSystem: false, prefix: "OB!" } });
  } catch (error) { res.status(502).json({ error: "Could not verify server access with Discord." }); }
});
app.put("/api/guilds/:id/config", requireOAuth, async (req, res) => {
  try {
    const guilds = await getManageableGuilds(req);
    const guild = guilds.find(g => g.id === req.params.id);
    if (!guild) return res.status(403).json({ error: "You must manage this server and have Oryn in it to change settings." });
    const input = req.body || {};
    const prefix = typeof input.prefix === "string" ? input.prefix.trim() : "OB!";
    if (!/^.{1,5}$/.test(prefix) || /[\r\n]/.test(prefix)) return res.status(400).json({ error: "Prefix must be 1–5 characters." });
    configs[guild.id] = {
      welcomeEnabled: Boolean(input.welcomeEnabled),
      moderationAlerts: Boolean(input.moderationAlerts),
      ticketSystem: Boolean(input.ticketSystem),
      prefix,
      updatedAt: new Date().toISOString(),
      updatedBy: req.session.user.id
    };
    saveConfigs();
    res.json({ ok: true, config: configs[guild.id] });
  } catch (error) { console.error("[config]", error.message); res.status(500).json({ error: "Could not save settings. Check persistent disk and server logs." }); }
});
app.get("*", (req, res, next) => {
  if (req.path.startsWith("/api/") || req.path.startsWith("/auth/")) return res.status(404).json({ error: "Not found" });
  res.sendFile(path.join(__dirname, "public", "index.html"), error => { if (error) next(error); });
});
app.listen(PORT, "0.0.0.0", () => console.log("[oryn] Website and dashboard listening on port " + PORT));
