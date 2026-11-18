import "dotenv/config";
import readline from "node:readline/promises";
import { stdin as input, stdout as output } from "node:process";
import bcrypt from "bcryptjs";
import { pool } from "../src/db.js";

const rl = readline.createInterface({ input, output });
try {
  const email = (await rl.question("Admin email: ")).trim().toLowerCase();
  const name = (await rl.question("Display name: ")).trim();
  const country = (await rl.question("Country scope (2-letter code, default MA): ")).trim().toUpperCase() || "MA";
  const password = await rl.question("Strong password (min 14 chars): ");
  if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email) || !name || !/^[A-Z]{2}$/.test(country) || password.length < 14) {
    throw new Error("Invalid email/name or password shorter than 14 characters.");
  }
  const hash = await bcrypt.hash(password, 12);
  const result = await pool.query(
    "INSERT INTO admins(email,display_name,password_hash) VALUES($1,$2,$3) RETURNING id",
    [email, name, hash]
  );
  const role = await pool.query("SELECT id FROM admin_roles WHERE code='owner'");
  await pool.query("INSERT INTO admin_user_roles(admin_id,role_id) VALUES($1,$2)", [result.rows[0].id, role.rows[0].id]);
  await pool.query("INSERT INTO admin_country_scopes(admin_id,country) VALUES($1,$2)", [result.rows[0].id, country]);
  console.log("Admin created:", result.rows[0].id);
} catch (error) {
  console.error("Could not create admin:", error.message);
  process.exitCode = 1;
} finally {
  rl.close();
  await pool.end();
}
