import * as http from "node:http";
import { verifyToken } from "./auth";

function send(res: http.ServerResponse, status: number, payload: unknown): void {
  res.writeHead(status, { "Content-Type": "application/json" });
  res.end(JSON.stringify(payload));
}

const server = http.createServer((req, res) => {
  const header = req.headers.authorization ?? "";
  const claims = verifyToken(header.replace(/^Bearer /, ""));
  if (!claims) {
    send(res, 401, { error: "invalid token" });
    return;
  }
  if (req.url === "/admin/users" && claims.role !== "admin") {
    send(res, 403, { error: "admin role required" });
    return;
  }
  send(res, 200, { sub: claims.sub, role: claims.role });
});

server.listen(8207, "127.0.0.1");
