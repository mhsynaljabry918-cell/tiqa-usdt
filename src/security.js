import crypto from "node:crypto";

export function randomToken(bytes = 32) {
  return crypto.randomBytes(bytes).toString("base64url");
}

export function sha256(value) {
  return crypto.createHash("sha256").update(value).digest("hex");
}

export function otpHash(code) {
  const pepper = process.env.OTP_PEPPER;
  if (!pepper || pepper.length < 32) {
    throw new Error("OTP_PEPPER must contain at least 32 characters");
  }
  return crypto.createHmac("sha256", pepper).update(String(code)).digest("hex");
}

export function makeOtp() {
  return String(crypto.randomInt(100000, 1000000));
}

export function safeEqualHex(a, b) {
  const aa = Buffer.from(String(a), "hex");
  const bb = Buffer.from(String(b), "hex");
  return aa.length === bb.length && crypto.timingSafeEqual(aa, bb);
}
