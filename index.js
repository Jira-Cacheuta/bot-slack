import express from "express";
import crypto from "crypto";
import pkg from "@slack/web-api";
import fetch from "node-fetch"; // si estás en Node 18+ podés usar fetch nativo

const app = express();
const { WebClient } = pkg;

const SLACK_SIGNING_SECRET = process.env.SLACK_SIGNING_SECRET;
const SLACK_BOT_TOKEN = process.env.SLACK_BOT_TOKEN;

const JIRA_SR_ENDPOINT_URL = process.env.JIRA_SR_ENDPOINT_URL; // ej: https://tu-jira.atlassian.net/rest/scriptrunner/latest/custom/slack/command
const JIRA_SR_SHARED_SECRET = process.env.JIRA_SR_SHARED_SECRET;

const slack = new WebClient(SLACK_BOT_TOKEN);

// Canal permitido
const ALLOWED_CHANNELS = new Set(["C099W0T9R2P"]);

// --- Helpers ---
function verifySlackSignature(req) {
  const ts = req.headers["x-slack-request-timestamp"];
  const sig = req.headers["x-slack-signature"];
  if (!ts || !sig) return false;

  // anti replay (5 min)
  const now = Math.floor(Date.now() / 1000);
  if (Math.abs(now - Number(ts)) > 60 * 5) return false;

  const rawBody = req.body; // Buffer por express.raw
  const base = `v0:${ts}:${rawBody.toString("utf8")}`;
  const hmac = crypto.createHmac("sha256", SLACK_SIGNING_SECRET).update(base).digest("hex");
  const expected = `v0=${hmac}`;

  // timing safe compare
  return crypto.timingSafeEqual(Buffer.from(expected), Buffer.from(sig));
}

function parseCommand(text) {
  if (!text) return null;
  // Busca el primer token que empiece con #
  const m = text.trim().match(/(^|\s)#([a-zA-Z0-9_]+)/);
  if (!m) return null;
  return m[2].toLowerCase(); // "problemashoy"
}

// --- Slack Events endpoint ---
app.post("/slack/events", express.raw({ type: "application/json" }), async (req, res) => {
  try {
    if (!verifySlackSignature(req)) {
      return res.status(401).send("invalid signature");
    }

    const payload = JSON.parse(req.body.toString("utf8"));

    // URL verification (challenge)
    if (payload.type === "url_verification") {
      return res.status(200).send(payload.challenge);
    }

    // ACK inmediato (Slack requiere rápido)
    res.status(200).send("ok");

    if (payload.type !== "event_callback") return;

    const ev = payload.event;

    // Ignorar bots / mensajes no relevantes
    if (!ev || ev.type !== "message") return;
    if (ev.bot_id) return;
    if (ev.subtype) return; // message_changed, etc.

    const channel = ev.channel;
    if (!ALLOWED_CHANNELS.has(channel)) return;

    const cmd = parseCommand(ev.text);
    if (cmd !== "problemashoy") return;

    // Llamar a ScriptRunner para resolver comando
    const srResp = await fetch(JIRA_SR_ENDPOINT_URL, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "X-Bot-Secret": JIRA_SR_SHARED_SECRET,
      },
      body: JSON.stringify({
        command: cmd,
        rawText: ev.text,
        channelId: channel,
        userId: ev.user,
        messageTs: ev.ts,
        teamId: payload.team_id,
        timezone: "America/Argentina/Buenos_Aires",
      }),
    });

    if (!srResp.ok) {
      const errTxt = await srResp.text();
      await slack.chat.postMessage({
        channel,
        thread_ts: ev.ts,
        text: `No pude ejecutar #${cmd}. Error SR: ${srResp.status} ${errTxt}`.slice(0, 3000),
      });
      return;
    }

    const data = await srResp.json(); // { text, blocks? }

    // Responder en thread
    await slack.chat.postMessage({
      channel,
      thread_ts: ev.ts,
      text: data.text || `Resultado de #${cmd}`,
      blocks: data.blocks || undefined,
    });
  } catch (e) {
    // Como ya hicimos ACK, acá solo logueás y, si querés, notificás
    console.error("Slack events error:", e);
  }
});

app.listen(process.env.PORT || 3000, () => console.log("OK"));
