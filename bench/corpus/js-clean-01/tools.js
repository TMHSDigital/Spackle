"use strict";

const crypto = require("node:crypto");
const fs = require("node:fs");
const path = require("node:path");
const { execFile } = require("node:child_process");
const { DatabaseSync } = require("node:sqlite");

const UPLOAD_ROOT = path.resolve("/srv/uploads");
const SERVICES = new Set(["web", "worker", "scheduler"]);
const db = new DatabaseSync(process.env.APP_DB || ":memory:");

function serviceStatus(name, callback) {
  if (!SERVICES.has(name)) {
    callback(new Error("unknown service"));
    return;
  }
  execFile("systemctl", ["is-active", `${name}.service`], { timeout: 5000 }, callback);
}

function readUpload(name) {
  const full = path.resolve(UPLOAD_ROOT, name);
  if (!full.startsWith(UPLOAD_ROOT + path.sep)) {
    throw new Error("path escapes upload root");
  }
  return fs.readFileSync(full);
}

function newApiToken() {
  return crypto.randomBytes(32).toString("hex");
}

function tokensEqual(given, expected) {
  const a = crypto.createHash("sha256").update(String(given)).digest();
  const b = crypto.createHash("sha256").update(String(expected)).digest();
  return crypto.timingSafeEqual(a, b);
}

function contentEtag(buffer) {
  return '"' + crypto.createHash("md5").update(buffer).digest("hex") + '"';
}

function findOrders(customer, status) {
  const sql = "SELECT id, total FROM orders WHERE customer = ? AND status = ? ORDER BY id DESC LIMIT 50";
  return db.prepare(sql).all(customer, status);
}

module.exports = { serviceStatus, readUpload, newApiToken, tokensEqual, contentEtag, findOrders };
