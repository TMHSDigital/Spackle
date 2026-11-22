"use strict";

const http = require("node:http");
const tools = require("./tools");

function sendJson(res, status, payload) {
  res.writeHead(status, { "Content-Type": "application/json" });
  res.end(JSON.stringify(payload));
}

function authorized(req) {
  const expected = process.env.SERVICE_TOKEN;
  return Boolean(expected) && tools.tokensEqual(req.headers["x-service-token"] || "", expected);
}

const server = http.createServer((req, res) => {
  const url = new URL(req.url || "/", "http://127.0.0.1");
  if (!authorized(req)) {
    sendJson(res, 401, { error: "unauthorized" });
    return;
  }
  try {
    if (url.pathname === "/status") {
      tools.serviceStatus(url.searchParams.get("service") || "", (err, stdout) => {
        sendJson(res, err ? 400 : 200, { state: err ? "unknown" : String(stdout).trim() });
      });
    } else if (url.pathname === "/upload") {
      const data = tools.readUpload(url.searchParams.get("name") || "");
      res.writeHead(200, { "Content-Type": "application/octet-stream", ETag: tools.contentEtag(data) });
      res.end(data);
    } else if (url.pathname === "/orders") {
      const rows = tools.findOrders(url.searchParams.get("customer") || "", url.searchParams.get("status") || "open");
      sendJson(res, 200, rows);
    } else {
      sendJson(res, 404, { error: "not found" });
    }
  } catch (err) {
    sendJson(res, 400, { error: "bad request" });
  }
});

server.listen(8210, "127.0.0.1");
