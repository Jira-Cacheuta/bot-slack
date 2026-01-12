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

// Si querés mostrar un mini “Te lo mandé por DM” en el canal (ephemeral),
// ponelo en true. Si querés CERO mensajes en canal, false.
const ACK_IN_CHANNEL = (process.env.ACK_IN_CHANNEL || "false").toLowerCase() === "true";

if (!SLACK_SIGNING_SECRET) throw new Error("Missing SLACK_SIGNING_SECRET");
if (!SLACK_BOT_TOKEN) throw new Error("Missing SLACK_BOT_TOKEN");
if (!JIRA_BASE_URL) throw new Error("Missing JIRA_BASE_URL");
if (!JIRA_EMAIL) throw new Error("Missing JIRA_EMAIL");
if (!JIRA_API_TOKEN) throw new Error("Missing JIRA_API_TOKEN");

const slack = new WebClient(SLACK_BOT_TOKEN);

// ───────── Mapeo Slack user -> Ejecutante (customfield_10714) ─────────
// IMPORTANTE: los strings deben coincidir EXACTO con las opciones del campo en Jira.
const EJECUTANTE_BY_SLACK_USER = {
  // Adrian Tacinazzo (Slack user_id ejemplo que pasaste)
  D09ARA2BL7M: [
    "1. Adrian Tacinazzo",
    "2. Adrian Tacinazzo",
    "3. Adrian Tacinazzo",
    "4. Adrian Tacinazzo",
    "5. Adrian Tacinazzo",
  ],
  // Agregá más usuarios aquí...
  //Octavio Colman
  U098XAH8FFV: [
    "1. Octavio Colman", 
    "2. Octavio Colman",
    "3.Octavio Colman",
      ],
  // U0XXXXXXX: ["1. Nombre Apellido", "2. Nombre Apellido", ...]
};

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

async function jiraSearch(jql, maxResults = 50, fieldsCsv = "summary,issuetype,status") {
  const url =
    `${JIRA_BASE_URL}/rest/api/3/search/jql` +
    `?jql=${encodeURIComponent(jql)}` +
    `&fields=${encodeURIComponent(fieldsCsv)}` +
    `&maxResults=${encodeURIComponent(String(maxResults))}`;

  console.log(`[JIRA] GET /search/jql maxResults=${maxResults} fields=${fieldsCsv}`);

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
    `• \`${prefix}mistareasdehoy\` — Tareas con vencimiento hoy donde sos el ejecutante (Jira).`,
    `• \`${prefix}problemashoy\` — Problemas creados hoy (Jira).`,
    `• \`${prefix}detalleshoy\` — Detalles creados hoy (Jira).`,
    `• \`${prefix}asistenciamanana\` — Asistencias de mañana (Jira).`,
    `• \`${prefix}detallesultimos30d\` — Detalles pendientes de los ultimos 30 días (Jira).`,
    `• \`${prefix}problemasultimos30d\` — Problemas pendientes de los ultimos 30 días (Jira).`,
    `• \`${prefix}sistema_hidraulico\` — Envía PDF + lista de links (DM).`,
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

// Respuesta por response_url (solo si querés un “ack”)
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
  const r = await slack.conversations.open({ users: userId });
  if (!r?.ok || !r.channel?.id) throw new Error(`No se pudo abrir DM con user=${userId}`);
  return r.channel.id;
}

async function dmText(userId, text) {
  const dmChannelId = await openDmChannel(userId);
  await slack.chat.postMessage({ channel: dmChannelId, text: (text || "").slice(0, 3800) });
  return dmChannelId;
}

async function dmPdfAndText(userId, pdfAbsPath, filename, title, messageText) {
  const dmChannelId = await openDmChannel(userId);

  if (!fs.existsSync(pdfAbsPath)) throw new Error(`No existe el PDF en ${pdfAbsPath}`);
  const fileBuffer = fs.readFileSync(pdfAbsPath);

  const upload = await slack.files.uploadV2({
    channel_id: dmChannelId,
    filename,
    title,
    file: fileBuffer,
  });

  if (!upload?.ok) throw new Error("No se pudo subir el PDF al DM (files.uploadV2)");

  await slack.chat.postMessage({
    channel: dmChannelId,
    text: (messageText || "").slice(0, 3800),
  });

  return dmChannelId;
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
 * - Abierto a TODO Slack (sin filtro por canal)
 * - TODAS las respuestas van al DM
 * - Opcional: ACK ephemeral en el canal con "Te lo mandé por DM"
 * ─────────────────────────────────────────────────────────────
 */
app.post(
  "/slack/commands",
  express.raw({ type: "application/x-www-form-urlencoded" }),
  async (req, res) => {
    const reqId = crypto.randomUUID?.() || String(Date.now());
    const started = Date.now();

    // Declaro responseUrl aquí para poder usarlo también en el catch
    let responseUrl = "";

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
      responseUrl = params.get("response_url") || "";

      console.log(`[SLASH][${reqId}] command=${command} channel=${channelId} user=${userId}`);

      if (!responseUrl) {
        console.log(`[SLASH][${reqId}] missing response_url`);
        return res.status(400).send("missing response_url");
      }

      // ACK rápido (Slack exige respuesta <= 3s)
      res.status(200).send("");
      console.log(`[SLASH][${reqId}] ack sent in ${Date.now() - started}ms`);

      // Helper: si querés confirmar en canal
      const ack = async (msg) => {
        if (!ACK_IN_CHANNEL) return;
        await respondViaResponseUrl(responseUrl, msg || "Te lo envié por privado (DM).", "ephemeral");
      };

      // ───────── /comandos ─────────
      if (command === "/comandos") {
        await dmText(userId, buildCommandsHelp("/"));
        await ack("Te envié la lista de comandos por DM.");
        console.log(`[SLASH][${reqId}] DM /comandos`);
        return;
      }

      if (command === "/mistareasdehoy") {
  const ejecutantes = EJECUTANTE_BY_SLACK_USER[userId];

  if (!ejecutantes || ejecutantes.length === 0) {
    await dmText(
      userId,
      "No tengo configurado tu mapeo Slack → Jira (customfield_10714). Avisame tu nombre exacto en las opciones del campo y lo agrego."
    );
    await ack("Te respondí por DM (falta configuración de tu usuario).");
    console.log(`[SLASH][${reqId}] /mistareasdehoy missing mapping user=${userId}`);
    return;
  }

  // Construye: "customfield_10714" in ("1. Adrian...", "2. Adrian...", ...)
  const ejecutantesJql = ejecutantes
    .map((v) => `"${String(v).replaceAll('"', '\\"')}"`)
    .join(", ");

  const jql = `
due >= startOfDay()
AND due < startOfDay("+1d")
AND customfield_10714 in (${ejecutantesJql})
ORDER BY due ASC, created ASC
  `.trim();

  // Pedimos 'duedate' para mostrarlo si querés en el output
  const data = await jiraSearch(jql, 100, "summary,issuetype,status,duedate");
  const issues = data.issues || [];

  let text;
  if (!issues.length) {
    text = `*Mis tareas de hoy* — 0 resultados.\n(Filtro: due hoy + ejecutante = tus variantes configuradas)`;
  } else {
    const lines = issues.slice(0, 50).map((it) => {
      const key = it.key;
      const summary = it.fields?.summary || "";
      const status = it.fields?.status?.name || "";
      const type = it.fields?.issuetype?.name || "";
      const due = it.fields?.duedate ? ` — vence: ${it.fields.duedate}` : "";
      const url = `${JIRA_BASE_URL}/browse/${key}`;
      return `• <${url}|${key}> — *${type}* — ${status}${due} — ${summary}`;
    });

    text = `*Mis tareas de hoy* — Total: *${issues.length}*\n${lines.join("\n")}`;
  }

  await dmText(userId, text);
  await ack("Te envié tus tareas de hoy por DM.");
  console.log(`[SLASH][${reqId}] /mistareasdehoy sent count=${issues.length}`);
  return;
}


      // ───────── /sistema_hidraulico (PDF + links por DM) ─────────
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
          "*Sistemas disponibles:*\n" +
          sistemas.map((s) => `• <${s.url}|${s.name}>`).join("\n");

        const pdfPath = path.join(__dirname, "diagrama_ch", "Diagrama_CH_final.pdf");

        await dmPdfAndText(
          userId,
          pdfPath,
          "Diagrama_CH_final.pdf",
          systemName,
          `*${systemName}*\n• PDF adjunto en este chat.\n\n${linksText}`
        );

        await ack(`Te envié por DM el PDF y la lista de links de *${systemName}*.`);
        console.log(`[SLASH][${reqId}] DM /sistema_hidraulico`);
        return;
      }

      // ───────── /problemashoy ─────────
      if (command === "/problemashoy") {
        const data = await jiraSearch(JQL_PROBLEMAS_HOY, 50);
        const issues = data.issues || [];
        const header = `*Problemas de hoy* — Total: *${issues.length}*`;
        const lines = issues.slice(0, 25).map(formatIssueLine);
        const body = lines.length ? lines.join("\n") : "• Sin resultados para hoy.";
        await dmText(userId, `${header}\n${body}`);
        await ack("Te envié el reporte por DM.");
        console.log(`[SLASH][${reqId}] DM /problemashoy count=${issues.length}`);
        return;
      }

      // ───────── /detalleshoy ─────────
      if (command === "/detalleshoy") {
        const data = await jiraSearch(JQL_DETALLES_HOY, 50);
        const issues = data.issues || [];
        const header = `*Detalles de hoy* — Total: *${issues.length}*`;
        const lines = issues.slice(0, 25).map(formatIssueLine);
        const body = lines.length ? lines.join("\n") : "• Sin resultados para hoy.";
        await dmText(userId, `${header}\n${body}`);
        await ack("Te envié el reporte por DM.");
        console.log(`[SLASH][${reqId}] DM /detalleshoy count=${issues.length}`);
        return;
      }

      // ───────── /asistenciamanana ─────────
      if (command === "/asistenciamanana") {
        const data = await jiraSearch(JQL_ASISTENCIA_MANANA, 50);
        const issues = data.issues || [];
        const header = `*Asistencias de mañana* — Total: *${issues.length}*`;
        const lines = issues.slice(0, 25).map(formatIssueLine);
        const body = lines.length ? lines.join("\n") : "• Sin resultados para mañana.";
        await dmText(userId, `${header}\n${body}`);
        await ack("Te envié el reporte por DM.");
        console.log(`[SLASH][${reqId}] DM /asistenciamanana count=${issues.length}`);
        return;
      }

      // ───────── /detallesultimos30d ─────────
      if (command === "/detallesultimos30d") {
        const data = await jiraSearch(JQL_DETALLES_30D, 50);
        const issues = data.issues || [];
        const header = `*Detalles pendientes de los últimos 30 días* — Total: *${issues.length}*`;
        const lines = issues.slice(0, 25).map(formatIssueLine);
        const body = lines.length ? lines.join("\n") : "• Sin detalles pendientes.";
        await dmText(userId, `${header}\n${body}`);
        await ack("Te envié el reporte por DM.");
        console.log(`[SLASH][${reqId}] DM /detallesultimos30d count=${issues.length}`);
        return;
      }

      // ───────── /problemasultimos30d ─────────
      if (command === "/problemasultimos30d") {
        const data = await jiraSearch(JQL_PROBLEMAS_30D, 50);
        const issues = data.issues || [];
        const header = `*Problemas pendientes de los últimos 30 días* — Total: *${issues.length}*`;
        const lines = issues.slice(0, 25).map(formatIssueLine);
        const body = lines.length ? lines.join("\n") : "• Sin problemas pendientes.";
        await dmText(userId, `${header}\n${body}`);
        await ack("Te envié el reporte por DM.");
        console.log(`[SLASH][${reqId}] DM /problemasultimos30d count=${issues.length}`);
        return;
      }

      // Fallback
      await dmText(userId, `Comando no reconocido: ${command}\n\n${buildCommandsHelp("/")}`);
      await ack("Te envié ayuda por DM.");
      console.log(`[SLASH][${reqId}] DM unknown command`);
    } catch (err) {
      console.error(`[SLASH][${reqId}] ERROR`, err);

      // Best-effort: avisar al usuario por el canal (ephemeral) si lo tenés activado
      try {
        if (ACK_IN_CHANNEL && responseUrl) {
          const msg =
            err?.data?.error === "missing_scope"
              ? `Faltan permisos en Slack App. Needed: ${err.data.needed}`
              : `Error ejecutando el comando: ${err.message}`;
          await respondViaResponseUrl(responseUrl, msg, "ephemeral");
        }
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
