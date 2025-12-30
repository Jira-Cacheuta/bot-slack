import express from "express";
import crypto from "crypto";
import { WebClient } from "@slack/web-api";
import "dotenv/config";

import fs from "fs";
import path from "path";
import { fileURLToPath } from "url";

// ───────── Node ESM paths ─────────
const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

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
project = PROB
and issuetype in ("Problema Eléctrico", "Problema Hidraulico", "Problema Infraestructura","Problema Jardinería","Problema Mantenimiento")
and statusCategory in ("To Do", "In Progress")
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

function jiraAuthHeader() {
  const token = Buffer.from(`${JIRA_EMAIL}:${JIRA_API_TOKEN}`).toString("base64");
  return `Basic ${token}`;
}

async function jiraSearch(jql, maxResults = 50) {
  const url =
    `${JIRA_BASE_URL}/rest/api/3/search/jql` +
    `?jql=${encodeURIComponent(jql)}` +
    `&fields=${encodeURIComponent("summary,issuetype,status")}` +
    `&maxResults=${encodeURIComponent(String(maxResults))}`;

  console.log(`[JIRA] GET /search/jql maxResults=${maxResults}`);

  const resp = await fetch(url, {
    method: "GET",
    headers: {
      Authorization: jiraAuthHeader(),
      Accept: "application/json",
    },
  });

  const bodyText = await resp.text();

  if (!resp.ok) {
    console.log(`[JIRA] ERROR status=${resp.status} body=${bodyText.slice(0, 500)}`);
    throw new Error(`Jira (${resp.status}): ${bodyText}`);
  }

  console.log(`[JIRA] OK status=${resp.status} bytes=${bodyText.length}`);
  return JSON.parse(bodyText);
}

function buildCommandsHelp(prefix = "/") {
  return [
    "*Comandos disponibles:*",
    `• \`${prefix}comandos\` — Lista de comandos.`,
    `• \`${prefix}problemashoy\` — Problemas creados hoy (Jira).`,
    `• \`${prefix}detalleshoy\` — Detalles creados hoy (Jira).`,
    `• \`${prefix}asistenciamanana\` — Asistencias de mañana (Jira).`,
    `• \`${prefix}detallesultimos30d\` — Detalles pendientes de los ultimos 30 días (Jira).`,
    `• \`${prefix}problemasultimos30d\` — Problemas pendientes de los ultimos 30 días (Jira).`,
    `• \`${prefix}sistema_hidraulico\` — Envía PDF + link por DM.`,
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

async function respondViaResponseUrl(responseUrl, text, responseType = "ephemeral") {
  await fetch(responseUrl, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({
      response_type: responseType,
      text: (text || "").slice(0, 3800),
    }),
  });
}

async function openDmChannel(userId) {
  // conversations.open requiere im:write
  const r = await slack.conversations.open({ users: userId });
  if (!r?.ok || !r.channel?.id) {
    throw new Error(`No se pudo abrir DM con user=${userId}`);
  }
  return r.channel.id;
}

async function sendSistemaHidraulicoByDM({ userId, systemName, systemLink }) {
  const dmChannelId = await openDmChannel(userId);

  // 1) Subir PDF al DM (privado)
  const pdfPath = path.join(__dirname, "diagrama_ch", "Diagrama_CH_final.pdf");
  if (!fs.existsSync(pdfPath)) {
    throw new Error(`No existe el PDF en ${pdfPath}`);
  }
  const fileBuffer = fs.readFileSync(pdfPath);

  const upload = await slack.files.uploadV2({
    channel_id: dmChannelId,
    filename: "sistema_hidraulico.pdf",
    title: systemName,
    file: fileBuffer,
  });

  if (!upload?.ok) {
    throw new Error("No se pudo subir el PDF al DM (files.uploadV2)");
  }

  // 2) Mensaje en DM con link “nombrado”
  await slack.chat.postMessage({
    channel: dmChannelId,
    text: `*${systemName}*\n• Link: <${systemLink}|${systemName}>\n• PDF adjunto en este chat.`,
  });

  return { dmChannelId };
}

// ───────── Healthcheck ─────────
app.get("/", (_req, res) => res.status(200).send("ok"));

// Logger HTTP global (excepto / porque está arriba)
app.use((req, _res, next) => {
  console.log(`[HTTP] ${req.method} ${req.path}`);
  next();
});

/**
 * ─────────────────────────────────────────────────────────────
 * SLASH COMMANDS: POST /slack/commands
 * Respuesta por response_url (ephemeral)
 * ─────────────────────────────────────────────────────────────
 */
app.post(
  "/slack/commands",
  express.raw({ type: "application/x-www-form-urlencoded" }),
  async (req, res) => {
    const reqId = crypto.randomUUID?.() || String(Date.now());
    const started = Date.now();

    try {
      console.log(`[SLASH][${reqId}] Incoming request`);

      if (!verifySlackSignature(req)) {
        console.log(`[SLASH][${reqId}] invalid signature`);
        return res.status(401).send("invalid signature");
      }

      const params = new URLSearchParams(req.body.toString("utf8"));
      const command = (params.get("command") || "").trim();
      const channelId = (params.get("channel_id") || "").trim();
      const userId = (params.get("user_id") || "").trim();
      const responseUrl = params.get("response_url");

      console.log(`[SLASH][${reqId}] command=${command} channel=${channelId} user=${userId}`);

      if (!responseUrl) {
        console.log(`[SLASH][${reqId}] missing response_url`);
        return res.status(400).send("missing response_url");
      }

      if (!ALLOWED_CHANNELS.has(channelId)) {
        console.log(`[SLASH][${reqId}] channel not allowed`);
        return res.status(200).json({
          response_type: "ephemeral",
          text: "Este comando no está habilitado en este canal.",
        });
      }

      // ACK rápido
      res.status(200).send("");
      console.log(`[SLASH][${reqId}] ack sent in ${Date.now() - started}ms`);

      // ───────── /comandos ─────────
      if (command === "/comandos") {
        await respondViaResponseUrl(responseUrl, buildCommandsHelp("/"), "ephemeral");
        console.log(`[SLASH][${reqId}] responded /comandos`);
        return;
      }

      // ───────── /sistema_hidraulico (DM + PDF privado) ─────────
      // ───────── /sistema_hidraulico (DM + PDF privado + lista links) ─────────
if (command === "/sistema_hidraulico") {
  const systemName = "Sistema hidráulico";

  const sistemas = [
    { name: "Sistema Gruta N1", url: "https://cacheuta.atlassian.net/browse/CH-1" },
    { name: "Sistema Gruta N2", url: "https://cacheuta.atlassian.net/browse/CH-637" },
    { name: "Sistema Gruta N3", url: "https://cacheuta.atlassian.net/browse/CH-692" },
    { name: "Sistema Gruta N4", url: "https://cacheuta.atlassian.net/browse/CH-970" },
    { name: "Sistema Hidro", url: "https://cacheuta.atlassian.net/browse/CH-741" },
    { name: "Sistema Ducha Fango Este", url: "https://cacheuta.atlassian.net/browse/CH-871" },
    { name: "Sistema Ducha Fango Oeste", url: "https://cacheuta.atlassian.net/browse/CH-917" },
    { name: "Sistema Aljibe Fango", url: "https://cacheuta.atlassian.net/browse/CH-882" },
    { name: "Sistema Ascensor", url: "https://cacheuta.atlassian.net/browse/CH-888" },
    { name: "Sistema Cacheutina", url: "https://cacheuta.atlassian.net/browse/CH-894" },
    { name: "Sistema Chorro Cacheutina", url: "https://cacheuta.atlassian.net/browse/CH-924" },
    { name: "Sistema Cascada", url: "https://cacheuta.atlassian.net/browse/CH-923" },
    { name: "Sistema Agua Fría", url: "https://cacheuta.atlassian.net/browse/CH-910" },
  ];

  const linksText =
        sistemas.map((s) => `• <${s.url}|${s.name}>`).join("\n");

  // 1) Abrir DM
  const dmChannelId = await openDmChannel(userId);

  // 2) Subir PDF al DM (privado)
  const pdfPath = path.join(__dirname, "diagrama_ch", "Diagrama_CH_final.pdf");
  if (!fs.existsSync(pdfPath)) throw new Error(`No existe el PDF en ${pdfPath}`);

  const fileBuffer = fs.readFileSync(pdfPath);

  const upload = await slack.files.uploadV2({
    channel_id: dmChannelId,
    filename: "Diagrama_CH_final.pdf",
    title: systemName,
    file: fileBuffer,
  });

  if (!upload?.ok) throw new Error("No se pudo subir el PDF al DM (files.uploadV2)");

  // 3) Enviar mensaje en DM con link principal + lista de links
  await slack.chat.postMessage({
    channel: dmChannelId,
    text:
      `*${systemName}*\n` +
      linksText,
  });

  // 4) Confirmación ephemeral en el canal (solo el usuario la ve)
  await respondViaResponseUrl(
    responseUrl,
    `Listo. Te envié por privado el PDF y la lista de links de *${systemName}*.`,
    "ephemeral"
  );

  console.log(`[SLASH][${reqId}] responded /sistema_hidraulico (sent DM + pdf + links)`);
  return;
}


      // ───────── /problemashoy ─────────
      if (command === "/problemashoy") {
        const data = await jiraSearch(JQL_PROBLEMAS_HOY, 50);
        const issues = data.issues || [];
        const header = `*Problemas de hoy* — Total: *${issues.length}*`;
        const lines = issues.slice(0, 25).map(formatIssueLine);
        const body = lines.length ? lines.join("\n") : "• Sin resultados para hoy.";
        await respondViaResponseUrl(responseUrl, `${header}\n${body}`, "ephemeral");
        console.log(`[SLASH][${reqId}] responded /problemashoy count=${issues.length}`);
        return;
      }

      // ───────── /detalleshoy ─────────
      if (command === "/detalleshoy") {
        const data = await jiraSearch(JQL_DETALLES_HOY, 50);
        const issues = data.issues || [];
        const header = `*Detalles de hoy* — Total: *${issues.length}*`;
        const lines = issues.slice(0, 25).map(formatIssueLine);
        const body = lines.length ? lines.join("\n") : "• Sin resultados para hoy.";
        await respondViaResponseUrl(responseUrl, `${header}\n${body}`, "ephemeral");
        console.log(`[SLASH][${reqId}] responded /detalleshoy count=${issues.length}`);
        return;
      }

      // ───────── /asistenciamanana ─────────
      if (command === "/asistenciamanana") {
        const data = await jiraSearch(JQL_ASISTENCIA_MANANA, 50);
        const issues = data.issues || [];
        const header = `*Asistencias de mañana* — Total: *${issues.length}*`;
        const lines = issues.slice(0, 25).map(formatIssueLine);
        const body = lines.length ? lines.join("\n") : "• Sin resultados para mañana.";
        await respondViaResponseUrl(responseUrl, `${header}\n${body}`, "ephemeral");
        console.log(`[SLASH][${reqId}] responded /asistenciamanana count=${issues.length}`);
        return;
      }

      // ───────── /detallesultimos30d ─────────
      if (command === "/detallesultimos30d") {
        const data = await jiraSearch(JQL_DETALLES_30D, 50);
        const issues = data.issues || [];
        const header = `*Detalles pendientes de los últimos 30 días* — Total: *${issues.length}*`;
        const lines = issues.slice(0, 25).map(formatIssueLine);
        const body = lines.length ? lines.join("\n") : "• Sin detalles pendientes.";
        await respondViaResponseUrl(responseUrl, `${header}\n${body}`, "ephemeral");
        console.log(`[SLASH][${reqId}] responded /detallesultimos30d count=${issues.length}`);
        return;
      }

      // ───────── /problemasultimos30d ─────────
      if (command === "/problemasultimos30d") {
        const data = await jiraSearch(JQL_PROBLEMAS_30D, 50);
        const issues = data.issues || [];
        const header = `*Problemas pendientes de los últimos 30 días* — Total: *${issues.length}*`;
        const lines = issues.slice(0, 25).map(formatIssueLine);
        const body = lines.length ? lines.join("\n") : "• Sin problemas pendientes.";
        await respondViaResponseUrl(responseUrl, `${header}\n${body}`, "ephemeral");
        console.log(`[SLASH][${reqId}] responded /problemasultimos30d count=${issues.length}`);
        return;
      }

      // Fallback
      await respondViaResponseUrl(
        responseUrl,
        `Comando no reconocido: ${command}\n\n${buildCommandsHelp("/")}`,
        "ephemeral"
      );
      console.log(`[SLASH][${reqId}] responded unknown command`);
    } catch (err) {
      console.error(`[SLASH][${reqId}] ERROR`, err);
      // Como ya mandamos ACK rápido, lo más útil es intentar avisar por response_url si existe:
      try {
        // Intento best-effort: responder algo (si el error fue antes de tener responseUrl, no se puede)
      } catch {}
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
