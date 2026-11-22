import * as http from "node:http";
import { canEdit, canView } from "./policy";
import type { Doc, Session } from "./policy";

const docs = new Map<string, Doc>([
  ["d1", { id: "d1", ownerId: "u1", title: "Roadmap", body: "Q3 plans" }],
  ["d2", { id: "d2", ownerId: "u2", title: "Offer letter", body: "Draft" }],
]);
const sessions = new Map<string, Session>();

function currentSession(req: http.IncomingMessage): Session | undefined {
  const auth = req.headers.authorization ?? "";
  return sessions.get(auth.replace(/^Bearer /, ""));
}

function readBody(req: http.IncomingMessage): Promise<string> {
  return new Promise((resolve, reject) => {
    let data = "";
    req.on("data", (chunk) => {
      data += chunk;
    });
    req.on("end", () => resolve(data));
    req.on("error", reject);
  });
}

function send(res: http.ServerResponse, status: number, payload: unknown): void {
  res.writeHead(status, { "Content-Type": "application/json" });
  res.end(JSON.stringify(payload));
}

const server = http.createServer(async (req, res) => {
  const url = new URL(req.url ?? "/", "http://127.0.0.1");
  const session = currentSession(req);
  const doc = docs.get(url.pathname.replace(/^\/docs\//, ""));
  if (!session) {
    return send(res, 401, { error: "sign in required" });
  }
  if (!doc) {
    return send(res, 404, { error: "not found" });
  }
  if (req.method === "GET") {
    return canView(session, doc) ? send(res, 200, doc) : send(res, 403, { error: "forbidden" });
  }
  if (req.method === "PUT") {
    let update: { ownerId?: string; title?: string; body?: string };
    try {
      update = JSON.parse(await readBody(req));
    } catch {
      return send(res, 400, { error: "invalid json" });
    }
    if (!canEdit(session, doc, String(update.ownerId ?? ""))) {
      return send(res, 403, { error: "forbidden" });
    }
    doc.title = String(update.title ?? doc.title);
    doc.body = String(update.body ?? doc.body);
    return send(res, 200, doc);
  }
  return send(res, 405, { error: "method not allowed" });
});

server.listen(8205, "127.0.0.1");
