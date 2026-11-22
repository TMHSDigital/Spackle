"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");
const { parseCookies, serializeCookie } = require("./cookies");

test("parseCookies reads name value pairs", () => {
  const jar = parseCookies("sid=abc123; theme=dark");
  assert.equal(jar.sid, "abc123");
  assert.equal(jar.theme, "dark");
  assert.equal(parseCookies(undefined).sid, undefined);
});

test("serializeCookie sets safe attributes", () => {
  const cookie = serializeCookie("sid", "a b", 60);
  assert.equal(cookie, "sid=a%20b; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=60");
});
