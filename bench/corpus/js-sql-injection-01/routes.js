"use strict";

const http = require("node:http");
const { buildWhere, normalizeSort } = require("./filters");
const { listOrders, getOrder } = require("./db");

function sendJson(res, status, payload) {
  res.writeHead(status, { "Content-Type": "application/json" });
  res.end(JSON.stringify(payload));
}

function handleList(url, res) {
  const params = url.searchParams;
  const where = buildWhere({
    status: params.get("status") || undefined,
    customer: params.get("customer") || undefined,
    minTotal: params.get("min_total") || undefined,
  });
  sendJson(res, 200, listOrders(where, normalizeSort(params.get("sort")), 50));
}

function handleDetail(url, res) {
  const id = Number(url.pathname.split("/")[2]);
  const order = Number.isInteger(id) ? getOrder(id) : undefined;
  if (!order) {
    sendJson(res, 404, { error: "not found" });
    return;
  }
  sendJson(res, 200, order);
}

const server = http.createServer((req, res) => {
  const url = new URL(req.url || "/", "http://127.0.0.1");
  try {
    if (req.method === "GET" && url.pathname === "/orders") {
      handleList(url, res);
    } else if (req.method === "GET" && url.pathname.startsWith("/orders/")) {
      handleDetail(url, res);
    } else {
      sendJson(res, 404, { error: "not found" });
    }
  } catch (err) {
    sendJson(res, 500, { error: "internal error" });
  }
});

server.listen(8206, "127.0.0.1");
