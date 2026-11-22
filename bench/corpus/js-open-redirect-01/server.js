"use strict";

const http = require("node:http");
const { parseCookies } = require("./cookies");

const sessions = new Map();

function currentUser(req) {
  const sid = parseCookies(req.headers.cookie).sid;
  return sid ? sessions.get(sid) : undefined;
}

function completeLogin(req, res, url) {
  const next = url.searchParams.get("next") || "/dashboard";
  if (!currentUser(req)) {
    res.writeHead(302, { Location: "/login" });
    res.end();
    return;
  }
  res.writeHead(302, { Location: next });
  res.end();
}

const server = http.createServer((req, res) => {
  const url = new URL(req.url || "/", "http://127.0.0.1");
  if (url.pathname === "/login/complete") {
    completeLogin(req, res, url);
    return;
  }
  if (url.pathname === "/dashboard") {
    const user = currentUser(req);
    res.writeHead(user ? 200 : 401, { "Content-Type": "text/plain" });
    res.end(user ? "dashboard" : "sign in required");
    return;
  }
  res.writeHead(404, { "Content-Type": "text/plain" });
  res.end("not found");
});

server.listen(8202, "127.0.0.1");
