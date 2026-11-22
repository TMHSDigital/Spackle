import * as http from "node:http";

const ALLOWED_ORIGINS = new Set(["https://app.example.com", "https://admin.example.com"]);
const NEXT_PAGES = new Set(["/", "/dashboard", "/settings", "/billing"]);

function escapeHtml(value: string): string {
  return value
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#39;");
}

function safeNext(next: string | null): string {
  return next !== null && NEXT_PAGES.has(next) ? next : "/";
}

function applyCors(req: http.IncomingMessage, res: http.ServerResponse): void {
  const origin = req.headers.origin;
  if (origin && ALLOWED_ORIGINS.has(origin)) {
    res.setHeader("Access-Control-Allow-Origin", origin);
    res.setHeader("Access-Control-Allow-Credentials", "true");
    res.setHeader("Vary", "Origin");
  }
}

const server = http.createServer((req, res) => {
  const url = new URL(req.url ?? "/", "http://127.0.0.1");
  applyCors(req, res);
  if (url.pathname === "/continue") {
    res.writeHead(302, { Location: safeNext(url.searchParams.get("next")) });
    res.end();
    return;
  }
  if (url.pathname === "/search") {
    const q = url.searchParams.get("q") ?? "";
    res.writeHead(200, { "Content-Type": "text/html; charset=utf-8" });
    res.end(`<!doctype html><html><body><h1>Results for ${escapeHtml(q)}</h1></body></html>`);
    return;
  }
  res.writeHead(404, { "Content-Type": "text/plain" });
  res.end("not found");
});

server.listen(8209, "127.0.0.1");
