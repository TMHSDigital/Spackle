import * as http from "node:http";

interface Account {
  id: string;
  email: string;
  plan: string;
}

const accountsBySession = new Map<string, Account>();

function sessionId(req: http.IncomingMessage): string | undefined {
  const header = req.headers.cookie ?? "";
  for (const part of header.split(";")) {
    const [name, value] = part.trim().split("=");
    if (name === "sid") {
      return value;
    }
  }
  return undefined;
}

function applyCors(req: http.IncomingMessage, res: http.ServerResponse): void {
  const origin = req.headers.origin;
  if (origin) {
    res.setHeader("Access-Control-Allow-Origin", origin);
    res.setHeader("Access-Control-Allow-Credentials", "true");
    res.setHeader("Vary", "Origin");
  }
  res.setHeader("Access-Control-Allow-Methods", "GET, OPTIONS");
  res.setHeader("Access-Control-Allow-Headers", "Content-Type");
}

const server = http.createServer((req, res) => {
  applyCors(req, res);
  if (req.method === "OPTIONS") {
    res.writeHead(204);
    res.end();
    return;
  }
  const sid = sessionId(req);
  const account = sid ? accountsBySession.get(sid) : undefined;
  if (!account) {
    res.writeHead(401, { "Content-Type": "application/json" });
    res.end(JSON.stringify({ error: "sign in required" }));
    return;
  }
  res.writeHead(200, { "Content-Type": "application/json" });
  res.end(JSON.stringify(account));
});

server.listen(8203, "127.0.0.1");
