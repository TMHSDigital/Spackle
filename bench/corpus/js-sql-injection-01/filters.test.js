"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");
const { normalizeSort } = require("./filters");

test("normalizeSort keeps known columns", () => {
  assert.equal(normalizeSort("total"), "total");
  assert.equal(normalizeSort("status"), "status");
});

test("normalizeSort falls back to created_at", () => {
  assert.equal(normalizeSort("id; DROP TABLE orders"), "created_at");
  assert.equal(normalizeSort(null), "created_at");
});
