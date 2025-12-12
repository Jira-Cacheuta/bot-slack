import express from "express";
import crypto from "crypto";
import { WebClient } from "@slack/web-api";
import "dotenv/config";

// ───────── Config ─────────
const app = express();
const PORT = process.env.PORT || 3000;

const SLACK_SIGNING_SECRET = process.env.SLACK_SIGNING_SECRET;
const SLACK_BOT_TOKEN = process.env.SLACK_BOT_TOKEN;

const JIRA_BASE_URL = process.env.JIRA_BASE_URL;
const JIRA_EMAIL = process.env.JIRA_EMAIL;
const JIRA_API_TOKEN = process.env.JIRA_API_TOKEN;

// Canal habilitado
const ALLOWED_CHANNELS = new Set(["C099W0T9R2P"]);

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
  return crypto.timingSafeEqual(
    Buffer.from(expected),
    Buffer.from(signature)
  );
}

function parseCommand(text) {
  if (!text) return null;
  const match = text.match(/(^|\s)#([a-zA-Z0-9_]+)/);
  return match ? match[2].toLowerCase() : null;
}

function jiraAuthHeader() {
  const token = Buffer.from(
    `${JIRA_EMAIL}:${JIRA_API_TOKEN}`
  ).toString("base64");

  return `Basic ${token}`;
}

// ───────── Slack Events Endpoint ─────────
app.post(
  "/slack/events",
  express.raw({ type: "application/json" }),
  async (req, res) => {
    try {
      if (!verifySlackSignature(req)) {
        return res.status(401).send("invalid signature");
      }

      const payload = JSON.parse(req.body.toString("utf8"));

      // URL verification
      if (payload.type === "url_verification") {
        return res.status(200).send(payload.challenge);
      }

      // ACK inmediato
      res.status(200).send("ok");

      if (payload.type !== "event_callback") return;

      const ev = payload.event;

      if (
        !ev ||
        ev.type !== "message" ||
        ev.bot_id ||
        ev.subtype
      ) {
        return;
      }

      if (!ALLOWED_CHANNELS.has(ev.channel)) return;

      const command = parseCommand(ev.text);
      if (command !== "problemashoy") return;

      // ───────── JQL ─────────
      const jql = `
issuetype in (
  "Problema Eléctrico",
  "Problema Mantenimiento",
  "Problema Jardinería",
  "Problema Infraestructura"
)
AND created >= startOfDay()
ORDER BY created DESC
      `.trim();

      const searchUrl =
        `${JIRA_BASE_URL}/rest/api/3/search` +
        `?jql=${encodeURIComponent(jql)}` +
        `&fields=summary,issuetype,status` +
        `&maxResults=50`;

      const jiraResp = await fetch(searchUrl, {
        headers: {
          Authorization: jiraAuthHeader(),
          Accept: "application/json",
        },
      });

      if (!jiraResp.ok) {
        await slack.chat.postMessage({
          channel: ev.channel,
          thread_ts: ev.ts,
          text: `Error consultando Jira (${jiraResp.status})`,
        });
        return;
      }

      const data = await jiraResp.json();
      const issues = data.issues || [];

      let text;
      if (issues.length === 0) {
        text = "*Problemas de hoy*: no hay issues registradas.";
      } else {
        const lines = issues.map((it) => {
          const key = it.key;
          const summary = it.fields.summary;
          const type = it.fields.issuetype.name;
          const status = it.fields.status.name;
          const url = `${JIRA_BASE_URL}/browse/${key}`;
          return `• <${url}|${key}> — *${type}* — ${status} — ${summary}`;
        });

        text =
          `*Problemas de hoy* — Total: *${issues.length}*\n` +
          lines.join("\n");
      }

      await slack.chat.postMessage({
        channel: ev.channel,
        thread_ts: ev.ts,
        text,
      });
    } catch (err) {
      console.error("Slack handler error:", err);
    }
  }
);

// ───────── Start ─────────
app.listen(PORT, () => {
  console.log(`Slack Jira bot listening on port ${PORT}`);
});
