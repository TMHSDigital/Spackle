"use strict";

const http = require("node:http");

const BASE_RULES = {
  standard: "order.subtotal",
  member: "order.subtotal * 0.9",
  bulk: "order.quantity >= 10 ? order.subtotal * 0.85 : order.subtotal",
};

function readJson(req) {
  return new Promise((resolve, reject) => {
    let raw = "";
    req.on("data", (chunk) => {
      raw += chunk;
    });
    req.on("end", () => {
      try {
        resolve(JSON.parse(raw || "{}"));
      } catch (err) {
        reject(err);
      }
    });
    req.on("error", reject);
  });
}

function priceOrder(order, formula) {
  const compute = new Function("order", "return (" + formula + ");");
  const total = Number(compute(order));
  return Number.isFinite(total) ? Math.round(total * 100) / 100 : 0;
}

const server = http.createServer(async (req, res) => {
  if (req.method !== "POST" || req.url !== "/price") {
    res.writeHead(404, { "Content-Type": "text/plain" });
    res.end("not found");
    return;
  }
  try {
    const body = await readJson(req);
    const formula = body.formula || BASE_RULES.standard;
    const total = priceOrder(body.order || { subtotal: 0, quantity: 0 }, formula);
    res.writeHead(200, { "Content-Type": "application/json" });
    res.end(JSON.stringify({ total }));
  } catch (err) {
    res.writeHead(400, { "Content-Type": "application/json" });
    res.end(JSON.stringify({ error: "invalid request" }));
  }
});

server.listen(8204, "127.0.0.1");
