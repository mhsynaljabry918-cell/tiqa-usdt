import nodemailer from "nodemailer";

function emailTransport() {
  const { SMTP_HOST, SMTP_PORT, SMTP_SECURE, SMTP_USER, SMTP_PASS } = process.env;
  if (!SMTP_HOST || !SMTP_USER || !SMTP_PASS) return null;
  return nodemailer.createTransport({
    host: SMTP_HOST,
    port: Number(SMTP_PORT || 587),
    secure: String(SMTP_SECURE).toLowerCase() === "true",
    auth: { user: SMTP_USER, pass: SMTP_PASS }
  });
}

function maskDestination(kind, value) {
  if (kind === "email") return String(value).replace(/^(.{2}).*(@.*)$/, "$1•••$2");
  const phone = String(value);
  return `${phone.slice(0, 4)}••••${phone.slice(-2)}`;
}

export async function deliverOtp({ kind, destination, code, purpose }) {
  // Temporary test-only delivery. Enable explicitly and remove before production use.
  if (process.env.OTP_DELIVERY_MODE === "console") {
    if (process.env.NODE_ENV === "production" && process.env.ALLOW_INSECURE_OTP_LOGS !== "true") {
      const error = new Error("Console OTP is blocked in production unless explicitly enabled for testing");
      error.status = 503;
      throw error;
    }
    console.warn("\n========== TIQAUSDT TEST OTP (DO NOT USE IN PRODUCTION) ==========");
    console.warn(`Purpose: ${purpose}`);
    console.warn(`Destination: ${maskDestination(kind, destination)}`);
    console.warn(`OTP CODE: ${code}`);
    console.warn(`Expires in: ${process.env.OTP_MINUTES || 10} minutes`);
    console.warn("================================================================\n");
    return;
  }
  if (kind === "email") {
    const transport = emailTransport();
    if (!transport) {
      const error = new Error("Email OTP provider is not configured");
      error.status = 503;
      throw error;
    }
    await transport.sendMail({
      from: process.env.SMTP_FROM || process.env.SMTP_USER,
      to: destination,
      subject: "رمز التحقق - ثقة USDT",
      text: `رمز التحقق الخاص بك هو: ${code}\nصلاحية الرمز 10 دقائق. لا تشاركه مع أي شخص. الغرض: ${purpose}.`,
      html: `<div dir="rtl" style="font-family:Arial,sans-serif"><h2>ثقة USDT</h2><p>رمز التحقق:</p><h1 style="letter-spacing:5px">${code}</h1><p>تنتهي صلاحيته خلال 10 دقائق. لا تشاركه مع أي شخص.</p></div>`
    });
    return;
  }

  if (kind === "phone") {
    const { TWILIO_ACCOUNT_SID, TWILIO_AUTH_TOKEN, TWILIO_FROM_NUMBER } = process.env;
    if (!TWILIO_ACCOUNT_SID || !TWILIO_AUTH_TOKEN || !TWILIO_FROM_NUMBER) {
      const error = new Error("SMS OTP provider is not configured");
      error.status = 503;
      throw error;
    }
    const auth = Buffer.from(`${TWILIO_ACCOUNT_SID}:${TWILIO_AUTH_TOKEN}`).toString("base64");
    const body = new URLSearchParams({
      To: destination,
      From: TWILIO_FROM_NUMBER,
      Body: `رمز التحقق من ثقة USDT: ${code}. صالح لمدة 10 دقائق. لا تشاركه.`
    });
    const response = await fetch(
      `https://api.twilio.com/2010-04-01/Accounts/${TWILIO_ACCOUNT_SID}/Messages.json`,
      { method: "POST", headers: { Authorization: `Basic ${auth}`, "Content-Type": "application/x-www-form-urlencoded" }, body }
    );
    if (!response.ok) {
      const error = new Error("SMS provider rejected the request");
      error.status = 502;
      throw error;
    }
    return;
  }

  const error = new Error("Unsupported contact kind");
  error.status = 400;
  throw error;
}
