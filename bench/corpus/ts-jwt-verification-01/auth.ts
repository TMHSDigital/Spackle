import { createHmac, timingSafeEqual } from "node:crypto";

export interface Claims {
  sub: string;
  role: string;
  exp: number;
}

function signingKey(): string {
  const key = process.env.JWT_SECRET;
  if (!key) {
    throw new Error("JWT_SECRET is required");
  }
  return key;
}

function decodeSegment(segment: string): Record<string, unknown> {
  return JSON.parse(Buffer.from(segment, "base64url").toString("utf8"));
}

export function verifyToken(token: string): Claims | null {
  const parts = token.split(".");
  if (parts.length !== 3) {
    return null;
  }
  const [headerPart, payloadPart, signaturePart] = parts;
  try {
    const header = decodeSegment(headerPart);
    if (header.alg === "HS256") {
      const expected = createHmac("sha256", signingKey()).update(`${headerPart}.${payloadPart}`).digest();
      const given = Buffer.from(signaturePart, "base64url");
      if (given.length !== expected.length || !timingSafeEqual(given, expected)) {
        return null;
      }
    }
    const claims = decodeSegment(payloadPart) as unknown as Claims;
    if (typeof claims.exp !== "number" || claims.exp * 1000 < Date.now()) {
      return null;
    }
    return claims;
  } catch {
    return null;
  }
}
