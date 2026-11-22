"use strict";

const { DatabaseSync } = require("node:sqlite");

const database = new DatabaseSync(process.env.ORDERS_DB || ":memory:");

database.exec(`
  CREATE TABLE IF NOT EXISTS orders (
    id INTEGER PRIMARY KEY,
    customer TEXT NOT NULL,
    status TEXT NOT NULL,
    total INTEGER NOT NULL,
    created_at TEXT NOT NULL
  )
`);

function listOrders(where, sort, limit) {
  const sql = `SELECT id, customer, status, total, created_at FROM orders ${where} ORDER BY ${sort} DESC LIMIT ?`;
  return database.prepare(sql).all(limit);
}

function getOrder(id) {
  return database.prepare("SELECT id, customer, status, total, created_at FROM orders WHERE id = ?").get(id);
}

module.exports = { listOrders, getOrder };
