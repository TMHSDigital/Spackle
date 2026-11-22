"use strict";

const http = require("node:http");
const { generateResetToken, isExpired, maskEmail } = require("./tokens");

const pendingResets = new Map();

function requestReset(email) {
  const token = generateResetToken();
  pendingResets.set(token, { email, issuedAt: Date.now() });
  return token;
}

function redeem(token) {
  const entry = pendingResets.get(token);
  pendingResets.delete(token);
  if (!entry || isExpired(entry.issuedAt)) {
    return null;
  }
  return entry.email;
}

function queueEmail(email, token) {
  process.stdout.write(`queued reset mail for ${maskEmail(email)}\n`);
  return { to: email, link: `https://app.example.com/reset?token=${token}` };
}

const server = http.createServer((req, res) => {
  const url = new URL(req.url || "/", "http://127.0.0.1");
  if (req.method === "POST" && url.pathname === "/reset-request") {
    const email = url.searchParams.get("email") || "";
    if (email.includes("@")) {
      queueEmail(email, requestReset(email));
    }
    res.writeHead(202, { "Content-Type": "application/json" });
    res.end(JSON.stringify({ status: "if the account exists, a reset link was sent" }));
    return;
  }
  if (req.method === "POST" && url.pathname === "/reset-confirm") {
    const email = redeem(url.searchParams.get("token") || "");
    res.writeHead(email ? 200 : 400, { "Content-Type": "application/json" });
    res.end(JSON.stringify({ ok: Boolean(email) }));
    return;
  }
  res.writeHead(404, { "Content-Type": "text/plain" });
  res.end("not found");
});

server.listen(8208, "127.0.0.1");
