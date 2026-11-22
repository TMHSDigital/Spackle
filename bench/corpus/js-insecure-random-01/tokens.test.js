"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");
const { isExpired, maskEmail, TOKEN_TTL_MS } = require("./tokens");

test("isExpired compares against the ttl", () => {
  assert.equal(isExpired(1000, 1000 + TOKEN_TTL_MS), false);
  assert.equal(isExpired(1000, 1001 + TOKEN_TTL_MS), true);
});

test("maskEmail hides the local part", () => {
  assert.equal(maskEmail("ada@example.com"), "a***@example.com");
  assert.equal(maskEmail("not-an-email"), "***");
});
