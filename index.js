import express from "express";
import crypto from "crypto";
import { WebClient } from "@slack/web-api";
import "dotenv/config";

// ───────── Config ─────────
const app = express();
const PORT = process.env.PORT || 3000;

const SLACK_SIGNING_SECRET = process.env.SLACK_SIGNING_SECRET;
const SLACK_BOT_TOKEN = process.env.SLACK_BOT_TOKEN;

const JIRA_BASE_URL = (process.env.JIRA_BASE_URL || "").replace(/\/+$/, "");
const JIRA_EMAIL = process.env.JIRA_EMAIL;
const JIRA_API_TOKEN = process.env.JIRA_API_TOKEN;

// Canales habilitados (coma-separados) — si no se setea, usa el tuyo
const ALLOWED_CHANNELS = new Set(
  (process.env.ALLOWED_CHANNELS || "C099W0T9R2P")
    .split(",")
    .map((s) => s.trim())
    .filter(Boolean)
);

if (!SLACK_SIGNING_SECRET) throw new Error("Missing SLACK_SIGNING_SECRET");
if (!SLACK_BOT_TOKEN) throw new Error("Missing SLACK_BOT_TOKEN");
if (!JIRA_BASE_URL) throw new Error("Missing JIRA_BASE_URL");
if (!JIRA_EMAIL) throw new Error("Missing JIRA_EMAIL");
if (!JIRA_API_TOKEN) throw new Error("Missing JIRA_API_TOKEN");

const slack = new WebClient(SLACK_BOT_TOKEN);

// ───────── JQLs ─────────
const JQL_PROBLEMAS_HOY = `
issuetype in (
  "Problema Eléctrico",
  "Problema Mantenimiento",
  "Problema Jardinería",
  "Problema Infraestructura"
)
AND created >= startOfDay()
ORDER BY created DESC
`.trim();

const JQL_DETALLES_HOY = `
issuetype in (
  "Detalle Eléctrico",
  "Detalle Mantenimiento",
  "Detalle Jardinería",
  "Detalle Infraestructura"
)
AND created >= startOfDay()
ORDER BY created DESC
`.trim();

const JQL_ASISTENCIA_MANANA = `
project = RH
AND issuetype = "recurso humano"
AND due >= startOfDay("+1d")
AND due <  startOfDay("+2d")
ORDER BY due ASC, created ASC
`.trim();

const JQL_DETALLES_30D = `
project = DET
and issuetype in ("Detalle Electricidad", "Detalle Infraestructura", "Detalle Jardinería", "Detalle Mantenimiento")
and statusCategory in ("To Do", "In Progress")
and created >= startOfDay("-30d")
ORDER BY created ASC
`.trim();

const JQL_PROBLEMAS_30D = `
project = PROB AND issuetype in ("Problema Eléctrico", "Problema Hidraulico", "Problema Infraestructura","Problema Jardinería","Problema Mantenimiento") and statusCategory in ("To Do", "In Progress")
and created >= startOfDay("-30d")
ORDER BY created ASC
`.trim();

// ───────── Helpers ─────────
function verifySlackSignature(req) {
  const timestamp = req.headers["x-slack-request-timestamp"];
  const signature = req.headers["x-slack-signature"];
  if (!timestamp || !signature) return false;

  // Anti-replay (5 min)
  const now = Math.floor(Date.now() / 1000);
  if (Math.abs(now - Number(timestamp)) > 60 * 5) return false;

  const rawBody = req.body.toString("utf8");
  const base = `v0:${timestamp}:${rawBody}`;

  const hmac = crypto
    .createHmac("sha256", SLACK_SIGNING_SECRET)
    .update(base)
    .digest("hex");

  const expected = `v0=${hmac}`;
  try {
    return crypto.timingSafeEqual(Buffer.from(expected), Buffer.from(signature));
  } catch {
    return false;
  }
}

function parseHashCommand(text) {
  if (!text) return null;
  const match = text.match(/(^|\s)#([a-zA-Z0-9_]+)/);
  return match ? match[2].toLowerCase() : null;
}

function jiraAuthHeader() {
  const token = Buffer.from(`${JIRA_EMAIL}:${JIRA_API_TOKEN}`).toString("base64");
  return `Basic ${token}`;
}

async function jiraSearch(jql, maxResults = 50) {
  // Tu Jira exige este endpoint
  const url =
    `${JIRA_BASE_URL}/rest/api/3/search/jql` +
    `?jql=${encodeURIComponent(jql)}` +
    `&fields=${encodeURIComponent("summary,issuetype,status")}` +
    `&maxResults=${encodeURIComponent(String(maxResults))}`;

  const resp = await fetch(url, {
    method: "GET",
    headers: {
      Authorization: jiraAuthHeader(),
      Accept: "application/json",
    },
  });

  const bodyText = await resp.text();
  if (!resp.ok) {
    throw new Error(`Jira (${resp.status}): ${bodyText}`);
  }
  return JSON.parse(bodyText);
}

function buildCommandsHelp(hashOrSlash = "#") {
  const prefix = hashOrSlash;
  return [
    "*Comandos disponibles:*",
    `• \`${prefix}comandos\` — Lista de comandos.`,
    `• \`${prefix}problemashoy\` — Problemas creados hoy (Jira).`,
    `• \`${prefix}detalleshoy\` — Detalles creados hoy (Jira).`,
    `• \`${prefix}asistenciamanana\` — Asistencias de mañana (Jira).`,
    `• \`${prefix}detallesultimos30d\` — Detalles pendientes de los ultimos 30 días (Jira).`,
    `• \`${prefix}problemasultimos30d\` — Problemas pendientes de los ultimos 30 días (Jira).`,
  ].join("\n");
}

function formatIssueLine(issue) {
  const key = issue.key;
  const f = issue.fields || {};
  const summary = (f.summary || "").toString();
  const type = f.issuetype?.name || "";
  const status = f.status?.name || "";
  const url = `${JIRA_BASE_URL}/browse/${key}`;
  return `• <${url}|${key}> — *${type}* — ${status} — ${summary}`;
}

async function respondInChannelViaResponseUrl(responseUrl, text) {
  await fetch(responseUrl, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({
      response_type: "in_channel",
      text: (text || "").slice(0, 3800),
    }),
  });
}

// ───────── Healthcheck ─────────
app.get("/", (_req, res) => res.status(200).send("ok"));


/**
 * ─────────────────────────────────────────────────────────────
 * 2) SLASH COMMANDS: POST /slack/commands
 *    /problemashoy / /detalleshoy / /comandos
 *    TODO in_channel (público)
 * ─────────────────────────────────────────────────────────────
 */
app.post(
  "/slack/commands",
  express.raw({ type: "application/x-www-form-urlencoded" }),
  async (req, res) => {
    try {
      if (!verifySlackSignature(req)) {
        return res.status(401).send("invalid signature");
      }

      const params = new URLSearchParams(req.body.toString("utf8"));
      const command = (params.get("command") || "").trim(); // "/problemashoy"
      const channelId = (params.get("channel_id") || "").trim();
      const responseUrl = params.get("response_url");

      if (!responseUrl) return res.status(400).send("missing response_url");
      if (!ALLOWED_CHANNELS.has(channelId)) {
        // Aunque pediste todo in_channel, esto conviene dejarlo como respuesta directa.
        return res.status(200).json({
          response_type: "ephemeral",
          text: "Este comando no está habilitado en este canal.",
        });
      }

      // ACK rápido (no publica nada todavía)
      res.status(200).send("");

      // Ejecutar y responder por response_url (in_channel)
      if (command === "/comandos") {
        await respondInChannelViaResponseUrl(responseUrl, buildCommandsHelp("/"));
        return;
      }

      if (command === "/problemashoy") {
        const data = await jiraSearch(JQL_PROBLEMAS_HOY, 50);
        const issues = data.issues || [];
        const header = `*Problemas de hoy* — Total: *${issues.length}*`;
        const lines = issues.slice(0, 25).map(formatIssueLine);
        const body = lines.length ? lines.join("\n") : "• Sin resultados para hoy.";
        await respondInChannelViaResponseUrl(responseUrl, `${header}\n${body}`);
        return;
      }

      if (command === "/detalleshoy") {
        const data = await jiraSearch(JQL_DETALLES_HOY, 50);
        const issues = data.issues || [];
        const header = `*Detalles de hoy* — Total: *${issues.length}*`;
        const lines = issues.slice(0, 25).map(formatIssueLine);
        const body = lines.length ? lines.join("\n") : "• Sin resultados para hoy.";
        await respondInChannelViaResponseUrl(responseUrl, `${header}\n${body}`);
        return;
      }

      if (command === "/asistenciamanana") {
      const data = await jiraSearch(JQL_ASISTENCIA_MANANA, 50);
      const issues = data.issues || [];
      const header = `*Asistencias de mañana* — Total: *${issues.length}*`;
      const lines = issues.slice(0, 25).map(formatIssueLine);
      const body = lines.length ? lines.join("\n") : "• Sin resultados para mañana.";
      await respondInChannelViaResponseUrl(responseUrl, `${header}\n${body}`);
      return;
      }
      
      if (command === "/detallesultimos30d") {
      const data = await jiraSearch(JQL_DETALLES_30D, 50);
      const issues = data.issues || [];
      const header = `*Detalles pendientes de los últimos 30 días* — Total: *${issues.length}*`;
      const lines = issues.slice(0, 25).map(formatIssueLine);
      const body = lines.length ? lines.join("\n") : "• Sin detalles pendientes.";
      await respondInChannelViaResponseUrl(responseUrl, `${header}\n${body}`);
      return;
      }

      if (command === "/problemasultimos30d") {
      const data = await jiraSearch(JQL_PROBLEMAS_30D, 50);
      const issues = data.issues || [];
      const header = `*Problemas pendientes de los últimos 30 días* — Total: *${issues.length}*`;
      const lines = issues.slice(0, 25).map(formatIssueLine);
      const body = lines.length ? lines.join("\n") : "• Sin problemas pendientes.";
      await respondInChannelViaResponseUrl(responseUrl, `${header}\n${body}`);
      return;
      }

      await respondInChannelViaResponseUrl(
        responseUrl,
        `Comando no reconocido: ${command}\n\n${buildCommandsHelp("/")}`
      );
    } catch (err) {
      console.error("Slash command handler error:", err);
      try {
        return res.status(500).send("server error");
      } catch {
        // ignore
      }
    }
  }
);

// ───────── Start ─────────
app.listen(PORT, () => {
  console.log(`Slack Jira bot listening on port ${PORT}`);
});
