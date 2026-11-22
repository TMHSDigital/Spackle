import * as http from "node:http";

interface Profile {
  handle: string;
  bio: string;
}

const profiles: Profile[] = [
  { handle: "ada", bio: "Analytical engines and tea." },
  { handle: "lin", bio: "Compilers, mostly." },
  { handle: "grace", bio: "Finds the bugs." },
];

function escapeHtml(value: string): string {
  return value
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;");
}

function search(term: string): Profile[] {
  const needle = term.toLowerCase();
  return profiles.filter((p) => p.handle.includes(needle) || p.bio.toLowerCase().includes(needle));
}

const server = http.createServer((req, res) => {
  const url = new URL(req.url ?? "/", "http://127.0.0.1");
  if (url.pathname !== "/search") {
    res.writeHead(404, { "Content-Type": "text/plain" });
    res.end("not found");
    return;
  }
  const q = url.searchParams.get("q") ?? "";
  const items = search(q)
    .map((p) => `<li>${escapeHtml(p.handle)}: ${escapeHtml(p.bio)}</li>`)
    .join("");
  res.writeHead(200, { "Content-Type": "text/html; charset=utf-8" });
  res.end(`<!doctype html><html><body><h1>Results for ${q}</h1><ul>${items}</ul></body></html>`);
});

server.listen(8201, "127.0.0.1");
