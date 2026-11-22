"use strict";

const ALPHABET = "ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789";
const TOKEN_TTL_MS = 30 * 60 * 1000;

function generateResetToken(length = 24) {
  let token = "";
  for (let i = 0; i < length; i += 1) {
    token += ALPHABET.charAt(Math.floor(Math.random() * ALPHABET.length));
  }
  return token;
}

function isExpired(issuedAt, now = Date.now()) {
  return now - issuedAt > TOKEN_TTL_MS;
}

function maskEmail(email) {
  const [local, domain] = String(email).split("@");
  if (!domain) {
    return "***";
  }
  return `${local.slice(0, 1)}***@${domain}`;
}

module.exports = { generateResetToken, isExpired, maskEmail, TOKEN_TTL_MS };
