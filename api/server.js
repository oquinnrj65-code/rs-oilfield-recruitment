const express = require("express");
const helmet = require("helmet");
const cors = require("cors");
const rateLimit = require("express-rate-limit");
const session = require("express-session");
const PgSession = require("connect-pg-simple")(session);
const { Pool } = require("pg");
const bcrypt = require("bcryptjs");
const { z } = require("zod");
const crypto = require("crypto");

const required = ["DATABASE_URL", "SESSION_SECRET", "ADMIN_EMAIL", "ADMIN_PASSWORD", "SITE_ORIGIN"];
for (const key of required) if (!process.env[key]) console.error("Missing required environment variable:", key);
if (required.some(k => !process.env[k])) process.exit(1);

const app = express();
const pool = new Pool({ connectionString: process.env.DATABASE_URL, ssl: process.env.DATABASE_URL.includes("localhost") ? false : { rejectUnauthorized: false } });
const origin = process.env.SITE_ORIGIN.replace(/\/$/, "");
app.set("trust proxy", 1);
app.use(helmet({ crossOriginResourcePolicy: { policy: "cross-origin" } }));
app.use(cors({ origin, credentials: true, methods: ["GET","POST","PATCH","DELETE"], allowedHeaders: ["Content-Type","Authorization"] }));
app.use(express.json({ limit: "32kb" }));
app.use(session({
  store: new PgSession({ pool, tableName: "user_sessions", createTableIfMissing: true }),
  name: "rs_admin_session", secret: process.env.SESSION_SECRET,
  resave: false, saveUninitialized: false,
  cookie: { httpOnly: true, secure: true, sameSite: "none", maxAge: 8 * 60 * 60 * 1000 }
}));
app.use("/api/", rateLimit({ windowMs: 15 * 60 * 1000, limit: 100, standardHeaders: "draft-7", legacyHeaders: false }));
app.use("/api/admin/login", rateLimit({ windowMs: 15 * 60 * 1000, limit: 8, standardHeaders: "draft-7", legacyHeaders: false }));

function originGuard(req,res,next) {
  if (req.method !== "GET" && req.get("origin") !== origin) return res.status(403).json({ error: "Request origin not allowed" });
  next();
}
app.use("/api", originGuard);
const clean = s => typeof s === "string" ? s.trim() : "";
const applicationSchema = z.object({
  fullName:z.string().trim().min(2).max(120), email:z.string().trim().email().max(254),
  phone:z.string().trim().min(7).max(30), location:z.string().trim().min(2).max(120),
  targetRole:z.string().trim().min(2).max(120), experience:z.string().trim().max(3000).optional().default(""),
  certifications:z.string().trim().max(1500).optional().default(""), consent:z.literal(true)
});
const employerSchema = z.object({
  contactName:z.string().trim().min(2).max(120), company:z.string().trim().min(2).max(160),
  email:z.string().trim().email().max(254), phone:z.string().trim().max(30).optional().default(""),
  jobTitle:z.string().trim().min(2).max(120), location:z.string().trim().min(2).max(120),
  details:z.string().trim().max(3000).optional().default(""), consent:z.literal(true)
});
const asyncRoute = fn => (req,res,next) => Promise.resolve(fn(req,res,next)).catch(next);
function makeAdminToken(email) {
  const payload = Buffer.from(JSON.stringify({ email, exp: Date.now() + 8 * 60 * 60 * 1000 })).toString("base64url");
  const signature = crypto.createHmac("sha256", process.env.SESSION_SECRET).update(payload).digest("base64url");
  return payload + "." + signature;
}
function requireAdmin(req,res,next) {
  const token = (req.get("authorization") || "").replace(/^Bearer\s+/i, "");
  const parts = token.split(".");
  if (parts.length !== 2) return res.status(401).json({error:"Sign in required"});
  const expected = crypto.createHmac("sha256", process.env.SESSION_SECRET).update(parts[0]).digest();
  let supplied;
  try { supplied = Buffer.from(parts[1], "base64url"); } catch { return res.status(401).json({error:"Sign in required"}); }
  if (expected.length !== supplied.length || !crypto.timingSafeEqual(expected, supplied)) return res.status(401).json({error:"Sign in required"});
  try {
    const data = JSON.parse(Buffer.from(parts[0], "base64url").toString("utf8"));
    if (!data.email || data.email !== process.env.ADMIN_EMAIL.toLowerCase() || !Number.isFinite(data.exp) || data.exp < Date.now()) return res.status(401).json({error:"Session expired. Please sign in again."});
    req.adminEmail = data.email;
    next();
  } catch { return res.status(401).json({error:"Sign in required"}); }
}

app.get("/health", (req,res) => res.json({status:"ok", service:"R&S recruiting API"}));
app.post("/api/applications", asyncRoute(async (req,res) => {
  const parsed = applicationSchema.safeParse(req.body);
  if (!parsed.success) return res.status(400).json({error:"Please check the required fields."});
  const v = parsed.data;
  await pool.query("INSERT INTO candidate_applications (full_name,email,phone,location,target_role,experience,certifications,consent_at) VALUES ($1,$2,$3,$4,$5,$6,$7,NOW())",
    [v.fullName,v.email.toLowerCase(),v.phone,v.location,v.targetRole,v.experience,v.certifications]);
  res.status(201).json({message:"Application received. R&S will contact you if a relevant opportunity is available."});
}));
app.post("/api/employer-inquiries", asyncRoute(async (req,res) => {
  const parsed = employerSchema.safeParse(req.body);
  if (!parsed.success) return res.status(400).json({error:"Please check the required fields."});
  const v = parsed.data;
  await pool.query("INSERT INTO employer_inquiries (contact_name,company,email,phone,job_title,location,details,consent_at) VALUES ($1,$2,$3,$4,$5,$6,$7,NOW())",
    [v.contactName,v.company,v.email.toLowerCase(),v.phone,v.jobTitle,v.location,v.details]);
  res.status(201).json({message:"Inquiry received. The R&S team will follow up."});
}));
app.post("/api/admin/login", asyncRoute(async (req,res) => {
  const email = clean(req.body.email).toLowerCase();
  const password = typeof req.body.password === "string" ? req.body.password : "";
  const valid = email === process.env.ADMIN_EMAIL.toLowerCase() && await bcrypt.compare(password, process.env.ADMIN_PASSWORD_HASH || await bcrypt.hash(process.env.ADMIN_PASSWORD, 12));
  if (!valid) return res.status(401).json({error:"Email or password is incorrect."});
  res.json({email, token:makeAdminToken(email)});
}));
app.post("/api/admin/logout", requireAdmin, (req,res) => res.json({ok:true}));
app.get("/api/admin/me", requireAdmin, (req,res) => res.json({email:req.adminEmail}));
app.get("/api/admin/overview", requireAdmin, asyncRoute(async (req,res) => {
  const [a,e] = await Promise.all([
    pool.query("SELECT id,full_name,email,phone,location,target_role,experience,certifications,status,created_at FROM candidate_applications ORDER BY created_at DESC LIMIT 200"),
    pool.query("SELECT id,contact_name,company,email,phone,job_title,location,details,status,created_at FROM employer_inquiries ORDER BY created_at DESC LIMIT 200")
  ]);
  res.json({applications:a.rows,inquiries:e.rows});
}));
app.patch("/api/admin/applications/:id", requireAdmin, asyncRoute(async (req,res) => {
  const status = z.enum(["new","reviewing","contacted","placed","closed"]).safeParse(req.body.status);
  if (!status.success) return res.status(400).json({error:"Invalid status"});
  const result = await pool.query("UPDATE candidate_applications SET status=$1 WHERE id=$2 RETURNING id,status",[status.data,req.params.id]);
  if (!result.rowCount) return res.status(404).json({error:"Application not found"});
  res.json(result.rows[0]);
}));
app.patch("/api/admin/inquiries/:id", requireAdmin, asyncRoute(async (req,res) => {
  const status = z.enum(["new","reviewing","contacted","filled","closed"]).safeParse(req.body.status);
  if (!status.success) return res.status(400).json({error:"Invalid status"});
  const result = await pool.query("UPDATE employer_inquiries SET status=$1 WHERE id=$2 RETURNING id,status",[status.data,req.params.id]);
  if (!result.rowCount) return res.status(404).json({error:"Inquiry not found"});
  res.json(result.rows[0]);
}));
app.use((err,req,res,next) => { console.error(err); res.status(500).json({error:"Something went wrong. Please try again later."}); });

async function start() {
  await pool.query(`
    CREATE TABLE IF NOT EXISTS candidate_applications (
      id BIGSERIAL PRIMARY KEY, full_name VARCHAR(120) NOT NULL, email VARCHAR(254) NOT NULL,
      phone VARCHAR(30) NOT NULL, location VARCHAR(120) NOT NULL, target_role VARCHAR(120) NOT NULL,
      experience TEXT NOT NULL DEFAULT '', certifications TEXT NOT NULL DEFAULT '',
      status VARCHAR(20) NOT NULL DEFAULT 'new', consent_at TIMESTAMPTZ NOT NULL, created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    );
    CREATE TABLE IF NOT EXISTS employer_inquiries (
      id BIGSERIAL PRIMARY KEY, contact_name VARCHAR(120) NOT NULL, company VARCHAR(160) NOT NULL,
      email VARCHAR(254) NOT NULL, phone VARCHAR(30) NOT NULL DEFAULT '', job_title VARCHAR(120) NOT NULL,
      location VARCHAR(120) NOT NULL, details TEXT NOT NULL DEFAULT '',
      status VARCHAR(20) NOT NULL DEFAULT 'new', consent_at TIMESTAMPTZ NOT NULL, created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    );
    CREATE INDEX IF NOT EXISTS candidate_created_idx ON candidate_applications(created_at DESC);
    CREATE INDEX IF NOT EXISTS employer_created_idx ON employer_inquiries(created_at DESC);
  `);
  const port = process.env.PORT || 10000;
  app.listen(port, "0.0.0.0", () => console.log("R&S API listening on", port));
}
start().catch(err => { console.error("Startup failed",err); process.exit(1); });
