import "dotenv/config";
import express from "express";
import helmet from "helmet";
import cors from "cors";
import cookieParser from "cookie-parser";
import morgan from "morgan";
import rateLimit from "express-rate-limit";
import path from "node:path";
import { fileURLToPath } from "node:url";
import authRoutes from "./routes/auth.js";
import adminRoutes from "./routes/admin.js";
import { pool } from "./db.js";

const app = express();
const here = path.dirname(fileURLToPath(import.meta.url));
const publicDir = path.join(here, "..", "public");
app.disable("x-powered-by");
// The prototype HTML contains inline scripts/styles; keep the other Helmet protections
// while allowing this legacy single-file frontend. Replace with nonces/hashes before production.
app.use(helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      scriptSrc: ["'self'", "'unsafe-inline'"],
      styleSrc: ["'self'", "'unsafe-inline'"],
      imgSrc: ["'self'", "data:", "https:"],
      connectSrc: ["'self'"],
      fontSrc: ["'self'", "data:", "https:"],
      objectSrc: ["'none'"],
      upgradeInsecureRequests: []
    }
  }
}));
app.use(cors({
  origin: process.env.FRONTEND_ORIGIN?.split(",").map(x => x.trim()) || false,
  credentials: true
}));
app.use(express.json({ limit: "250kb" }));
app.use(cookieParser());
app.use(morgan("combined"));
app.use(express.static(publicDir));

const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  limit: 10,
  standardHeaders: "draft-7",
  legacyHeaders: false,
  message: { error: "RATE_LIMIT", message: "محاولات كثيرة. حاول لاحقاً." }
});

app.get("/api/health", async (_req, res, next) => {
  try { await pool.query("SELECT 1"); res.json({ ok: true, database: "connected" }); }
  catch (error) { next(error); }
});
app.use("/api/auth", authLimiter, authRoutes);
app.use("/api/admin/login", authLimiter);
app.use("/api/admin", adminRoutes);

app.use((req, res) => res.status(404).json({ error: "NOT_FOUND", message: "المسار غير موجود." }));
app.use((error, _req, res, _next) => {
  if (error?.name === "ZodError") return res.status(400).json({ error: "VALIDATION", details: error.issues });
  const status = Number(error.status) || 500;
  if (status >= 500) console.error(error);
  res.status(status).json({ error: error.code || "REQUEST_FAILED", message: status >= 500 ? "حدث خطأ في الخادم." : error.message });
});

const port = Number(process.env.PORT || 3000);
app.listen(port, () => console.log(`TiqaUSDT API listening on port ${port}`));
