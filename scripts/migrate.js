import "dotenv/config";
import fs from "node:fs/promises";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { pool } from "../src/db.js";

const here = path.dirname(fileURLToPath(import.meta.url));
const migrationsDir = path.join(here, "..", "database");

try {
  const files = (await fs.readdir(migrationsDir))
    .filter(name => /^\d+_[a-z0-9_-]+\.sql$/i.test(name))
    .sort();

  await pool.query(`CREATE TABLE IF NOT EXISTS schema_migrations (
    filename TEXT PRIMARY KEY,
    applied_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
  )`);

  for (const filename of files) {
    const already = await pool.query("SELECT 1 FROM schema_migrations WHERE filename=$1", [filename]);
    if (already.rowCount) {
      console.log(`Skipped ${filename} (already applied).`);
      continue;
    }
    const sql = await fs.readFile(path.join(migrationsDir, filename), "utf8");
    const client = await pool.connect();
    try {
      await client.query("BEGIN");
      await client.query(sql);
      await client.query("INSERT INTO schema_migrations(filename) VALUES($1)", [filename]);
      await client.query("COMMIT");
      console.log(`Applied ${filename}.`);
    } catch (error) {
      await client.query("ROLLBACK");
      throw new Error(`${filename}: ${error.message}`);
    } finally {
      client.release();
    }
  }
  console.log("Database migrations complete.");
} catch (error) {
  console.error("Migration failed:", error.message);
  process.exitCode = 1;
} finally {
  await pool.end();
}
