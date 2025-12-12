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

// Canal habilitado
const ALLOWED_CHANNELS = new Set(["C099W0T9R2P"]);

if (!SLACK_SIGNING_SECRET) throw new Error("Missing SLACK_SIGNING_SECRET");
if (!SLACK_BOT_TOKEN) throw new Error("Missing SLACK_BOT_TOKEN");
if (!JIRA_BASE_URL) throw new Error("Missing JIRA_BASE_URL");
if (!JIRA_EMAIL) throw new Error("Missing JIRA_EMAIL");
if (!JIRA_API_TOKEN) throw new Error("Missing JIRA_API_TOKEN");

const slack = new WebClient(SLACK_BOT_TOKEN);

// ───────── Helpers ─────────
function verifySlackSignature(req) {
  const timestamp = req.headers["x-slack-request-timestamp"];
  const signature = req.headers["x-slack-signature"];
  if (!timestamp || !signature) return false;

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
  const searchUrl =
    `${JIRA_BASE_URL}/rest/api/3/search/jql` +
    `?jql=${encodeURIComponent(jql)}` +
    `&fields=${encodeURIComponent("summary,issuetype,status")}` +
    `&maxResults=${encodeURIComponent(String(maxResults))}`;

  const resp = await fetch(searchUrl, {
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

function buildCommandsHelp() {
  return [
    "*Comandos disponibles:*",
    "• `#problemashoy` — Problemas creados hoy (Jira).",
    "• `#detalleshoy` — Detalles creados hoy (Jira).",
    "• `#comandos` — Lista de comandos.",
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

// ───────── Healthcheck ─────────
app.get("/", (_req, res) => res.status(200).send("ok"));

// ───────── Slack Events Endpoint ─────────
app.post(
  "/slack/events",
  express.raw({ type: "application/json" }),
  async (req, res) => {
    let payload;

    // Parse JSON primero
    try {
      payload = JSON.parse(req.body.toString("utf8"));
    } catch {
      return res.status(400).send("bad json");
    }

    // URL verification (challenge) primero
    if (payload.type === "url_verification") {
      return res.status(200).send(payload.challenge);
    }

    // Firma para eventos reales
    if (!verifySlackSignature(req)) {
      return res.status(401).send("invalid signature");
    }

    // ACK inmediato
    res.status(200).send("ok");

    if (payload.type !== "event_callback") return;

    const ev = payload.event;

    // Solo mensajes “normales”
    if (!ev || ev.type !== "message" || ev.bot_id || ev.subtype) return;

    // Canal permitido
    if (!ALLOWED_CHANNELS.has(ev.channel)) return;

    const cmd = parseHashCommand(ev.text);
    if (!cmd) return;

    // Responder siempre en thread
    const thread_ts = ev.ts;

    // ───────── #comandos ─────────
    if (cmd === "comandos") {
      await slack.chat.postMessage({
        channel: ev.channel,
        thread_ts,
        text: buildCommandsHelp(),
      });
      return;
    }

    // ───────── #problemashoy ─────────
    if (cmd === "problemashoy") {
      const jqlProblemas = `
issuetype in (
  "Problema Eléctrico",
  "Problema Mantenimiento",
  "Problema Jardinería",
  "Problema Infraestructura"
)
AND created >= startOfDay()
ORDER BY created DESC
      `.trim();

      try {
        const data = await jiraSearch(jqlProblemas, 50);
        const issues = data.issues || [];

        const today = new Date().toLocaleDateString("es-AR");
        const header = `*Problemas de hoy* (${today}) — Total: *${issues.length}*`;

        const lines = issues.slice(0, 25).map(formatIssueLine);
        const body = lines.length ? lines.join("\n") : "• Sin resultados para hoy.";

        await slack.chat.postMessage({
          channel: ev.channel,
          thread_ts,
          text: `${header}\n${body}`.slice(0, 3800),
        });
      } catch (err) {
        await slack.chat.postMessage({
          channel: ev.channel,
          thread_ts,
          text: `Error consultando Jira: ${err.message}`.slice(0, 3800),
        });
      }
      return;
    }

    // ───────── #detalleshoy ─────────
    if (cmd === "detalleshoy") {
      const jqlDetalles = `
issuetype in (
  "Detalle Eléctricidad",
  "Detalle Mantenimiento",
  "Detalle Jardinería",
  "Detalle Infraestructura"
)
AND created >= startOfDay()
ORDER BY created DESC
      `.trim();

      try {
        const data = await jiraSearch(jqlDetalles, 50);
        const issues = data.issues || [];

        const today = new Date().toLocaleDateString("es-AR");
        const header = `*Detalles de hoy* (${today}) — Total: *${issues.length}*`;

        const lines = issues.slice(0, 25).map(formatIssueLine);
        const body = lines.length ? lines.join("\n") : "• Sin resultados para hoy.";

        await slack.chat.postMessage({
          channel: ev.channel,
          thread_ts,
          text: `${header}\n${body}`.slice(0, 3800),
        });
      } catch (err) {
        await slack.chat.postMessage({
          channel: ev.channel,
          thread_ts,
          text: `Error consultando Jira: ${err.message}`.slice(0, 3800),
        });
      }
      return;
    }

    // Comando no reconocido (si alguien escribe otro #...)
    await slack.chat.postMessage({
      channel: ev.channel,
      thread_ts,
      text: `Comando no reconocido. Escribí #comandos para ver la lista.`,
    });
  }
);

// ───────── Start ─────────
app.listen(PORT, () => {
  console.log(`Slack Jira bot listening on port ${PORT}`);
});
