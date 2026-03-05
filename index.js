// index.js (FULL FILE) — RentSphere LINE Backend (Web-only “B”: LINE = แจ้งเตือนอย่างเดียว)
// ✅ ไม่มี LINE webhook / ไม่มีปุ่มใน LINE (ยืนยัน/จบทำในเว็บ)
// ✅ CRON: เตือนก่อนหมด 15 นาที + แจ้งหมดเวลา (ข้อความล้วน)
//
// ✅ FIX รอบนี้:
// - แก้ TIMEZONE (Bangkok) ให้ไม่เพี้ยนเวลา/วัน (ทำให้ “จองแล้วไม่ขึ้น / lock ไม่ตรง” หาย)
// - ใช้ขอบเขตวันแบบ explicit +07:00 (ไม่ลบ 7 ชั่วโมงซ้ำ)
// - availability key HH:mm ใช้ Asia/Bangkok เสถียร ไม่ขึ้นกับ timezone เครื่อง
// - เพิ่ม route cancel ใน Routes ready
import jwt from "jsonwebtoken";
import multer from "multer";
import express from "express";
import cors from "cors";
import "dotenv/config";
import { createClient } from "@supabase/supabase-js";
import { randomUUID } from "crypto";
import cron from "node-cron";
import crypto from "crypto";
import bcrypt from "bcryptjs";

const app = express();

// ✅ CORS
app.use(
  cors({
    origin: true,
    credentials: true,
    allowedHeaders: [
      "Content-Type",
      "Authorization",
      "x-line-user-id",
      "Cache-Control",
      "cache-control",
      "Pragma",
      "pragma",
    ],
    methods: ["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"],
  })
);
app.options("*", cors());

// ✅ กัน preflight ตาย
app.options("*", cors());

app.use(express.json());

const fetchFn = globalThis.fetch;

// ✅ ชื่อ bucket ต้องตรงใน Supabase Storage
const REPAIR_BUCKET = "repair-images";
const PARCEL_BUCKET = "parcel-images";

console.log("SUPABASE_URL:", process.env.SUPABASE_URL);
console.log("HAS_SERVICE_ROLE:", !!process.env.SUPABASE_SERVICE_ROLE_KEY);
console.log("REPAIR_BUCKET:", REPAIR_BUCKET);
console.log("PARCEL_BUCKET:", PARCEL_BUCKET);
console.log("HAS_LINE_MESSAGING_TOKEN:", !!process.env.LINE_MESSAGING_ACCESS_TOKEN);
// NOTE: ปิดโหมด admin secret แล้ว (ฝั่งเว็บจะไม่ต้องกรอกรหัส admin)

// ---- Supabase Admin Client ----
const supabaseAdmin = createClient(
  process.env.SUPABASE_URL,
  process.env.SUPABASE_SERVICE_ROLE_KEY,
  { auth: { persistSession: false } }
);

// ✅ health check
app.get("/health", (req, res) => res.json({ ok: true }));
/* =========================
   Auth v1 (OWNER USERS)
   - POST /api/v1/auth/register
   - POST /api/v1/auth/verify/email
   - POST /api/v1/auth/verify/resend
   - POST /api/v1/auth/login
   - POST /api/v1/auth/password/forgot
   - POST /api/v1/auth/password/reset
   ========================= */

const JWT_SECRET = process.env.JWT_SECRET || "dev-secret-change-me";
const VERIFY_EXPIRES_MIN = Number(process.env.VERIFY_EXPIRES_MIN || 15);
const RESET_EXPIRES_MIN = Number(process.env.RESET_EXPIRES_MIN || 15);


function authRequired(req, res, next) {
  try {
    const h = req.headers.authorization || "";
    const m = h.match(/^Bearer\s+(.+)$/i);
    if (!m) return res.status(401).json({ error: "missing_bearer_token" });

    if (!JWT_SECRET) return res.status(500).json({ error: "JWT_SECRET_not_set" });

    const payload = jwt.verify(m[1], JWT_SECRET);
    req.ownerId = payload?.sub;
    if (!req.ownerId) return res.status(401).json({ error: "invalid_token_no_sub" });

    next();
  } catch (e) {
    return res.status(401).json({ error: "invalid_token" });
  }
}


async function assertOwnsCondo(ownerId, condoId) {
  const { data, error } = await supabaseAdmin
    .schema("public")
    .from("condos")
    .select("id, owner_id")
    .eq("id", condoId)
    .maybeSingle();

  if (error) throw error;
  if (!data) return { ok: false, status: 404, error: "condo_not_found" };
  if (data.owner_id !== ownerId) return { ok: false, status: 403, error: "forbidden_not_owner" };
  return { ok: true, condo: data };
}



function normEmail(email) {
  return String(email || "").trim().toLowerCase();
}
function makeCode(len = 6) {
  // 000000-999999
  return String(Math.floor(Math.random() * 10 ** len)).padStart(len, "0");
}
function addMinutes(d, mins) {
  return new Date(d.getTime() + mins * 60 * 1000);
}


async function sendEmailMock(to, subject, text) {
  const apiKey = process.env.BREVO_API_KEY;
  if (!apiKey) {
    console.log("[EMAIL MOCK]", { to, subject, text });
    return;
  }

  const code = text.match(/\d{6}/)?.[0] || text;

  try {
    const r = await fetch("https://api.brevo.com/v3/smtp/email", {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "api-key": apiKey,
      },
      body: JSON.stringify({
        sender: { name: "RentSphere", email: "renspheres@gmail.com" },
        to: [{ email: to }],
        subject,
        htmlContent: `<div style="font-family:sans-serif;max-width:480px;margin:0 auto;padding:32px;border:1px solid #e0e0e0;border-radius:16px"><h2 style="color:#3b82f6;margin:0 0 16px">🏢 RentSphere</h2><p style="font-size:14px;color:#666">${subject}</p><div style="margin:24px 0;padding:20px;background:#f0f4ff;border-radius:12px;text-align:center"><div style="font-size:36px;font-weight:900;letter-spacing:8px;color:#1e40af">${code}</div></div><p style="font-size:12px;color:#999;text-align:center">รหัสนี้จะหมดอายุใน 15 นาที</p></div>`,
      }),
    });

    const result = await r.json();
    console.log("[BREVO]", r.ok ? "SENT" : "FAIL", result);
  } catch (e) {
    console.error("[BREVO ERROR]", e.message);
  }
}




/** สร้าง JWT */
function signToken(user) {
  return jwt.sign(
    { sub: user.id, role: user.role || "OWNER", email: user.email },
    JWT_SECRET,
    { expiresIn: "7d" }
  );
}

/** หา user ด้วย email */
async function getOwnerByEmail(email) {
  const { data, error } = await supabaseAdmin
    .schema("public")
    .from("owner_users")
    .select("*")
    .eq("email", email)
    .maybeSingle();

  if (error) throw error;
  return data || null;
}

/** สร้าง verification request */
async function createVerification({ userId, type, channel, code, email, phone, expiresAt }) {
  const { data, error } = await supabaseAdmin
    .schema("public")
    .from("verification_requests")
    .insert([
      {
        user_id: userId,
        type,
        channel,
        code,
        email: email || null,
        phone: phone || null,
        is_used: false,
        expires_at: expiresAt.toISOString(),
      },
    ])
    .select("*")
    .single();

  if (error) throw error;
  return data;
}

/** ใช้โค้ด verify (ต้องไม่หมดอายุ/ไม่ถูกใช้) */
async function consumeCode({ userId, type, channel, code }) {
  const nowIso = new Date().toISOString();

  // หา request ล่าสุดที่ตรงเงื่อนไข
  const { data, error } = await supabaseAdmin
    .schema("public")
    .from("verification_requests")
    .select("*")
    .eq("user_id", userId)
    .eq("type", type)
    .eq("channel", channel)
    .eq("code", code)
    .eq("is_used", false)
    .gt("expires_at", nowIso)
    .order("created_at", { ascending: false })
    .limit(1)
    .maybeSingle();

  if (error) throw error;
  if (!data) return null;

  // mark used
  const { error: updErr } = await supabaseAdmin
    .schema("public")
    .from("verification_requests")
    .update({ is_used: true })
    .eq("id", data.id);

  if (updErr) throw updErr;
  return data;
}

/** 1) REGISTER */
app.post("/api/v1/auth/register", async (req, res) => {
  try {
    const name = String(req.body?.name || "").trim();
    const email = normEmail(req.body?.email);
    const phone = String(req.body?.phone || "").trim() || null;
    const password = String(req.body?.password || "");

    if (!name) return res.status(400).json({ error: "name_required" });
    if (!email) return res.status(400).json({ error: "email_required" });
    if (password.length < 6) return res.status(400).json({ error: "password_min_6" });

    const exists = await getOwnerByEmail(email);
    if (exists) return res.status(409).json({ error: "email_already_used" });

    const password_hash = await bcrypt.hash(password, 10);

    const { data: user, error } = await supabaseAdmin
      .schema("public")
      .from("owner_users")
      .insert([
        {
          name,
          email,
          phone,
          password_hash,
          role: "OWNER",
          is_verified: false,
        },
      ])
      .select("id, name, email, phone, role, is_verified, created_at")
      .single();

    if (error) return res.status(500).json({ error: pickErr(error) });

    // create verify code
    const code = makeCode(6);
    const expiresAt = addMinutes(new Date(), VERIFY_EXPIRES_MIN);
    await createVerification({
      userId: user.id,
      type: "EMAIL_VERIFY",
      channel: "EMAIL",
      code,
      email: user.email,
      expiresAt,
    });

    await sendEmailMock(
      user.email,
      "Verify your email",
      `Your verification code is ${code} (expires in ${VERIFY_EXPIRES_MIN} min)`
    );

    return res.json({
      ok: true,
      user,
      verify: { sent: true, channel: "EMAIL" },
    });
  } catch (e) {
    return res.status(500).json({ error: pickErr(e) });
  }
});

/** 2) VERIFY EMAIL */
app.post("/api/v1/auth/verify/email", async (req, res) => {
  try {
    const email = normEmail(req.body?.email);
    const code = String(req.body?.code || "").trim();

    if (!email) return res.status(400).json({ error: "email_required" });
    if (!code) return res.status(400).json({ error: "code_required" });

    const user = await getOwnerByEmail(email);
    if (!user) return res.status(404).json({ error: "user_not_found" });

    const used = await consumeCode({
      userId: user.id,
      type: "EMAIL_VERIFY",
      channel: "EMAIL",
      code,
    });

    if (!used) return res.status(400).json({ error: "invalid_or_expired_code" });

    const { data: updated, error } = await supabaseAdmin
      .schema("public")
      .from("owner_users")
      .update({ is_verified: true, updated_at: new Date().toISOString() })
      .eq("id", user.id)
      .select("id, name, email, phone, role, is_verified")
      .single();

    if (error) return res.status(500).json({ error: pickErr(error) });

    return res.json({ ok: true, user: updated });
  } catch (e) {
    return res.status(500).json({ error: pickErr(e) });
  }
});

/** 3) RESEND VERIFY */
app.post("/api/v1/auth/verify/resend", async (req, res) => {
  try {
    const email = normEmail(req.body?.email);
    if (!email) return res.status(400).json({ error: "email_required" });

    const user = await getOwnerByEmail(email);
    if (!user) return res.status(404).json({ error: "user_not_found" });
    if (user.is_verified) return res.json({ ok: true, already_verified: true });

    const code = makeCode(6);
    const expiresAt = addMinutes(new Date(), VERIFY_EXPIRES_MIN);
    await createVerification({
      userId: user.id,
      type: "EMAIL_VERIFY",
      channel: "EMAIL",
      code,
      email: user.email,
      expiresAt,
    });

    await sendEmailMock(
      user.email,
      "Verify your email (resend)",
      `Your verification code is ${code} (expires in ${VERIFY_EXPIRES_MIN} min)`
    );

    return res.json({ ok: true, resent: true });
  } catch (e) {
    return res.status(500).json({ error: pickErr(e) });
  }
});

/** 4) LOGIN */
app.post("/api/v1/auth/login", async (req, res) => {
  try {
    const email = normEmail(req.body?.email);
    const password = String(req.body?.password || "");

    if (!email) return res.status(400).json({ error: "email_required" });
    if (!password) return res.status(400).json({ error: "password_required" });

    const user = await getOwnerByEmail(email);
    if (!user) return res.status(401).json({ error: "invalid_credentials" });

    const ok = await bcrypt.compare(password, user.password_hash);
    if (!ok) return res.status(401).json({ error: "invalid_credentials" });

    if (!user.is_verified) return res.status(403).json({ error: "email_not_verified" });

    const token = signToken(user);

    return res.json({
      ok: true,
      token,
      user: {
        id: user.id,
        name: user.name,
        email: user.email,
        phone: user.phone,
        role: user.role,
        is_verified: user.is_verified,
      },
    });
  } catch (e) {
    return res.status(500).json({ error: pickErr(e) });
  }
});

/** 5) FORGOT PASSWORD */
app.post("/api/v1/auth/password/forgot", async (req, res) => {
  try {
    const email = normEmail(req.body?.email);
    if (!email) return res.status(400).json({ error: "email_required" });

    const user = await getOwnerByEmail(email);

    // ✅ กัน user enumeration: ไม่บอกว่ามี/ไม่มี user
    if (!user) return res.json({ ok: true, sent: true });

    const code = makeCode(6);
    const expiresAt = addMinutes(new Date(), RESET_EXPIRES_MIN);
    await createVerification({
      userId: user.id,
      type: "PASSWORD_RESET",
      channel: "EMAIL",
      code,
      email: user.email,
      expiresAt,
    });

    await sendEmailMock(
      user.email,
      "Reset your password",
      `Your reset code is ${code} (expires in ${RESET_EXPIRES_MIN} min)`
    );

    return res.json({ ok: true, sent: true });
  } catch (e) {
    return res.status(500).json({ error: pickErr(e) });
  }
});

/** 6) RESET PASSWORD */
app.post("/api/v1/auth/password/reset", async (req, res) => {
  try {
    const email = normEmail(req.body?.email);
    const code = String(req.body?.code || "").trim();
    const newPassword = String(req.body?.new_password || "");

    if (!email) return res.status(400).json({ error: "email_required" });
    if (!code) return res.status(400).json({ error: "code_required" });
    if (newPassword.length < 6) return res.status(400).json({ error: "password_min_6" });

    const user = await getOwnerByEmail(email);
    if (!user) return res.status(404).json({ error: "user_not_found" });

    const used = await consumeCode({
      userId: user.id,
      type: "PASSWORD_RESET",
      channel: "EMAIL",
      code,
    });

    if (!used) return res.status(400).json({ error: "invalid_or_expired_code" });

    const password_hash = await bcrypt.hash(newPassword, 10);

    const { data: updated, error } = await supabaseAdmin
      .schema("public")
      .from("owner_users")
      .update({ password_hash, updated_at: new Date().toISOString() })
      .eq("id", user.id)
      .select("id, name, email, phone, role, is_verified")
      .single();

    if (error) return res.status(500).json({ error: pickErr(error) });

    return res.json({ ok: true, user: updated });
  } catch (e) {
    return res.status(500).json({ error: pickErr(e) });
  }
});

/* =========================
   Condo Staff (เจ้าหน้าที่ของคอนโด)
   ========================= */

// GET /api/v1/condos/:condoId/users — ดึงเจ้าหน้าที่ทั้งหมดของคอนโด
app.get("/api/v1/condos/:condoId/users", authRequired, async (req, res) => {
  try {
    const ownerId = req.ownerId;
    const condoId = req.params.condoId;

    const own = await assertOwnsCondo(ownerId, condoId);
    if (!own.ok) return res.status(own.status).json({ error: own.error });

    const { data, error } = await supabaseAdmin
      .schema("public")
      .from("condo_staff")
      .select("id, full_name, phone, email, role, created_at")
      .eq("condo_id", condoId)
      .order("created_at", { ascending: false });

    if (error) return res.status(500).json({ error: error.message });

    return res.json({ ok: true, users: data || [] });
  } catch (e) {
    return res.status(500).json({ error: e?.message || "server_error" });
  }
});

// POST /api/v1/condos/:condoId/users — เพิ่มเจ้าหน้าที่
app.post("/api/v1/condos/:condoId/users", authRequired, async (req, res) => {
  try {
    const ownerId = req.ownerId;
    const condoId = req.params.condoId;

    const own = await assertOwnsCondo(ownerId, condoId);
    if (!own.ok) return res.status(own.status).json({ error: own.error });

    const full_name = String(req.body?.fullName || "").trim();
    const phone = String(req.body?.phone || "").trim();
    const email = String(req.body?.email || "").trim().toLowerCase();
    const role = String(req.body?.role || "ADMIN").toUpperCase();

    if (!full_name) return res.status(400).json({ error: "fullName_required" });
    if (!phone) return res.status(400).json({ error: "phone_required" });
    if (!email) return res.status(400).json({ error: "email_required" });
    if (!["OWNER", "ADMIN"].includes(role)) return res.status(400).json({ error: "invalid_role" });

    const { data, error } = await supabaseAdmin
      .schema("public")
      .from("condo_staff")
      .insert([{ condo_id: condoId, full_name, phone, email, role }])
      .select("id, full_name, phone, email, role, created_at")
      .single();

    if (error) {
      // duplicate email ในคอนโดเดียวกัน
      if (error.code === "23505") return res.status(409).json({ error: "email_already_exists_in_condo" });
      return res.status(500).json({ error: error.message });
    }

    return res.status(201).json({ ok: true, user: data });
  } catch (e) {
    return res.status(500).json({ error: e?.message || "server_error" });
  }
});

// PATCH /api/v1/condos/:condoId/users/:userId — แก้ไขเจ้าหน้าที่
app.patch("/api/v1/condos/:condoId/users/:userId", authRequired, async (req, res) => {
  try {
    const ownerId = req.ownerId;
    const condoId = req.params.condoId;
    const userId = req.params.userId;

    const own = await assertOwnsCondo(ownerId, condoId);
    if (!own.ok) return res.status(own.status).json({ error: own.error });

    const updates = {};
    if (req.body?.fullName !== undefined) updates.full_name = String(req.body.fullName).trim();
    if (req.body?.phone !== undefined) updates.phone = String(req.body.phone).trim();
    if (req.body?.email !== undefined) updates.email = String(req.body.email).trim().toLowerCase();
    if (req.body?.role !== undefined) {
      const role = String(req.body.role).toUpperCase();
      if (!["OWNER", "ADMIN"].includes(role)) return res.status(400).json({ error: "invalid_role" });
      updates.role = role;
    }

    if (Object.keys(updates).length === 0) return res.status(400).json({ error: "no_fields_to_update" });
    updates.updated_at = new Date().toISOString();

    const { data, error } = await supabaseAdmin
      .schema("public")
      .from("condo_staff")
      .update(updates)
      .eq("id", userId)
      .eq("condo_id", condoId)
      .select("id, full_name, phone, email, role, updated_at")
      .single();

    if (error) {
      if (error.code === "23505") return res.status(409).json({ error: "email_already_exists_in_condo" });
      return res.status(500).json({ error: error.message });
    }
    if (!data) return res.status(404).json({ error: "staff_not_found" });

    return res.json({ ok: true, user: data });
  } catch (e) {
    return res.status(500).json({ error: e?.message || "server_error" });
  }
});

// DELETE /api/v1/condos/:condoId/users/:userId — ลบเจ้าหน้าที่
app.delete("/api/v1/condos/:condoId/users/:userId", authRequired, async (req, res) => {
  try {
    const ownerId = req.ownerId;
    const condoId = req.params.condoId;
    const userId = req.params.userId;

    const own = await assertOwnsCondo(ownerId, condoId);
    if (!own.ok) return res.status(own.status).json({ error: own.error });

    const { error } = await supabaseAdmin
      .schema("public")
      .from("condo_staff")
      .delete()
      .eq("id", userId)
      .eq("condo_id", condoId);

    if (error) return res.status(500).json({ error: error.message });

    return res.json({ ok: true });
  } catch (e) {
    return res.status(500).json({ error: e?.message || "server_error" });
  }
});

/* =========================
   Helpers
   ========================= */
function genCode(len = 8) {
  const chars = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789";
  let s = "";
  for (let i = 0; i < len; i++) s += chars[Math.floor(Math.random() * chars.length)];
  return s;
}
const pickErr = (e) => (typeof e === "string" ? e : e?.message || String(e));

function fmt(dt) {
  try {
    return new Date(dt).toLocaleString("th-TH", {
      timeZone: "Asia/Bangkok",
      hour: "2-digit",
      minute: "2-digit",
      day: "2-digit",
      month: "2-digit",
      year: "2-digit",
    });
  } catch {
    return String(dt);
  }
}

function pad2(n) {
  return String(n).padStart(2, "0");
}

// ✅ สร้างขอบเขต “วันตามเวลาไทย” แบบชัดเจน (ไม่ลบ 7 ซ้ำอีก)
function bkkDayRangeUTCFromYmd(dateYmd) {
  // dateYmd: "YYYY-MM-DD"
  const startUtc = new Date(`${dateYmd}T00:00:00+07:00`);
  const endUtc = new Date(startUtc.getTime() + 24 * 60 * 60 * 1000);
  return { startUtc, endUtc };
}

function bkkDayRangeUTCFromDate(dateObj) {
  // dateObj เป็น Date (instant) -> เอาวันตามเวลาไทยของเครื่อง แล้วทำขอบเขต +07:00
  const y = dateObj.getFullYear();
  const m = dateObj.getMonth() + 1;
  const d = dateObj.getDate();
  const ymd = `${y}-${pad2(m)}-${pad2(d)}`;
  return { ymd, ...bkkDayRangeUTCFromYmd(ymd) };
}

// ✅ แปลง ISO -> "HH:mm" ตามเวลาไทยแบบเสถียร (ไม่ขึ้นกับ timezone เครื่อง)
function hhmmBangkokFromISO(iso) {
  const d = new Date(iso);
  const parts = new Intl.DateTimeFormat("en-GB", {
    timeZone: "Asia/Bangkok",
    hour: "2-digit",
    minute: "2-digit",
    hour12: false,
  }).formatToParts(d);

  const hh = parts.find((p) => p.type === "hour")?.value ?? "00";
  const mm = parts.find((p) => p.type === "minute")?.value ?? "00";
  return `${hh}:${mm}`;
}

/* =========================
   Multer
   ========================= */
const upload = multer({ storage: multer.memoryStorage() });
////// สร้างคอนโด
app.post("/api/v1/condos", authRequired, upload.single("logo"), async (req, res) => {
  try {
    const ownerId = req.ownerId;

    // // 1 owner = 1 condo check
    // const { data: existing, error: exErr } = await supabaseAdmin
    //   .schema("public")
    //   .from("condos")
    //   .select("id")
    //   .eq("owner_id", ownerId)
    //   .maybeSingle();
    // if (exErr) return res.status(500).json({ error: exErr.message });
    // if (existing) return res.status(409).json({ error: "owner_already_has_condo" });

    const raw = req.body?.payload;
    if (!raw) return res.status(400).json({ error: "payload_required" });

    let payload;
    try { payload = JSON.parse(raw); } catch { return res.status(400).json({ error: "payload_invalid_json" }); }

    const name_th = String(payload?.nameTh || "").trim();
    const address_th = String(payload?.addressTh || "").trim();
    if (!name_th) return res.status(400).json({ error: "nameTh_required" });
    if (!address_th) return res.status(400).json({ error: "addressTh_required" });

    // logo_url: ยังไม่ทำ upload => null
    const logo_url = null;

    const { data: condo, error } = await supabaseAdmin
      .schema("public")
      .from("condos")
      .insert([{
        owner_id: ownerId,
        name_th,
        name_en: payload?.nameEn || null,
        address_th,
        address_en: payload?.addressEn || null,
        phone_number: payload?.phoneNumber || null,
        tax_id: payload?.taxId || null,
        logo_url,
        payment_due_date: payload?.paymentDueDate || null,
        accept_fine: !!payload?.acceptFine,
        fine_amount: Number(payload?.fineAmount || 0),
        payment_note: payload?.paymentNote || null,
        floor_count: Number(payload?.floorCount || 1),
      }])
      .select("id")
      .single();

    if (error) return res.status(500).json({ error: error.message });

    return res.status(201).json({ ok: true, condoId: condo.id });
  } catch (e) {
    return res.status(500).json({ error: e?.message || "server_error" });
  }
});

app.get("/api/v1/condos/mine", authRequired, async (req, res) => {
  try {
    const ownerId = req.ownerId;
    const { data: condos, error } = await supabaseAdmin
      .schema("public")
      .from("condos")
      .select("id, name_th, name_en, address_th, address_en, phone_number, tax_id, floor_count")
      .eq("owner_id", ownerId)
      .order("created_at", { ascending: false });
    if (error) return res.status(500).json({ error: error.message });
    if (!condos || condos.length === 0) return res.json({ ok: true, condo: null, condos: [] });
    // ส่งทั้ง array + ตัวแรกเป็น default (backward compatible)
    const items = [];
    for (const condo of condos) {
      const { count: totalRooms } = await supabaseAdmin
        .schema("public")
        .from("rooms")
        .select("*", { count: "exact", head: true })
        .eq("condo_id", condo.id);
      const { count: occupiedRooms } = await supabaseAdmin
        .schema("public")
        .from("rooms")
        .select("*", { count: "exact", head: true })
        .eq("condo_id", condo.id)
        .eq("status", "OCCUPIED");
      const { count: unpaidBills } = await supabaseAdmin
        .schema("public")
        .from("invoices")
        .select("*", { count: "exact", head: true })
        .eq("condo_id", condo.id)
        .eq("status", "UNPAID");
      const tr = Number(totalRooms || 0);
      const or = Number(occupiedRooms || 0);
      items.push({
        id: condo.id,
        nameTh: condo.name_th,
        nameEn: condo.name_en,
        addressTh: condo.address_th,
        addressEn: condo.address_en,
        phoneNumber: condo.phone_number,
        taxId: condo.tax_id,
        floorCount: condo.floor_count,
        totalRooms: tr,
        occupiedRooms: or,
        vacantRooms: Math.max(tr - or, 0),
        unpaidBills: Number(unpaidBills || 0),
      });
    }
    return res.json({
      ok: true,
      condo: items[0],   // backward compatible
      condos: items,      // ✅ array ทั้งหมด
    });
  } catch (e) {
    return res.status(500).json({ error: e?.message || "server_error" });
  }
});

// DELETE /api/v1/condos/:condoId — ลบคอนโด + ห้องที่ผูกอยู่
app.delete("/api/v1/condos/:condoId", authRequired, async (req, res) => {
  try {
    const condoId = req.params.condoId;
    const ownerId = req.ownerId;

    // ตรวจว่าเป็นเจ้าของจริง
    const { data: condo } = await supabaseAdmin
      .from("condos").select("id").eq("id", condoId).eq("owner_id", ownerId).maybeSingle();
    if (!condo) return res.status(404).json({ error: "not_found" });

    // ลบห้องก่อน
    await supabaseAdmin.from("rooms").delete().eq("condo_id", condoId);
    // ลบคอนโด
    await supabaseAdmin.from("condos").delete().eq("id", condoId);

    return res.json({ ok: true });
  } catch (e) {
    return res.status(500).json({ error: e?.message || "server_error" });
  }
});

// ===== GET routes สำหรับโหลดข้อมูลแสดง Frontend =====

// GET /api/v1/condos/:condoId — ข้อมูลคอนโด (Step 0)
app.get("/api/v1/condos/:condoId", authRequired, async (req, res) => {
  try {
    const ownerId = req.ownerId;
    const condoId = req.params.condoId;

    const own = await assertOwnsCondo(ownerId, condoId);
    if (!own.ok) return res.status(own.status).json({ error: own.error });

    const { data, error } = await supabaseAdmin
      .schema("public")
      .from("condos")
      .select("*")
      .eq("id", condoId)
      .maybeSingle();

    if (error) return res.status(500).json({ error: error.message });
    if (!data) return res.status(404).json({ error: "condo_not_found" });

    return res.json({ ok: true, condo: data });
  } catch (e) {
    return res.status(500).json({ error: e?.message || "server_error" });
  }
});

// GET /api/v1/condos/:condoId/services — บริการเสริม (Step 1)
app.get("/api/v1/condos/:condoId/services", authRequired, async (req, res) => {
  try {
    const ownerId = req.ownerId;
    const condoId = req.params.condoId;

    const own = await assertOwnsCondo(ownerId, condoId);
    if (!own.ok) return res.status(own.status).json({ error: own.error });

    const { data, error } = await supabaseAdmin
      .schema("public")
      .from("condo_services")
      .select("*")
      .eq("condo_id", condoId)
      .order("created_at", { ascending: true });

    if (error) return res.status(500).json({ error: error.message });

    return res.json({ ok: true, services: data || [] });
  } catch (e) {
    return res.status(500).json({ error: e?.message || "server_error" });
  }
});

// GET /api/v1/condos/:condoId/utilities — ค่าน้ำ/ไฟ (Step 2)
app.get("/api/v1/condos/:condoId/utilities", authRequired, async (req, res) => {
  try {
    const ownerId = req.ownerId;
    const condoId = req.params.condoId;

    const own = await assertOwnsCondo(ownerId, condoId);
    if (!own.ok) return res.status(own.status).json({ error: own.error });

    const { data, error } = await supabaseAdmin
      .schema("public")
      .from("condo_utility_configs")
      .select("*")
      .eq("condo_id", condoId);

    if (error) return res.status(500).json({ error: error.message });

    return res.json({ ok: true, configs: data || [] });
  } catch (e) {
    return res.status(500).json({ error: e?.message || "server_error" });
  }
});

// GET /api/v1/condos/:condoId/bank-accounts — บัญชีธนาคาร (Step 3)
app.get("/api/v1/condos/:condoId/bank-accounts", authRequired, async (req, res) => {
  try {
    const ownerId = req.ownerId;
    const condoId = req.params.condoId;

    const own = await assertOwnsCondo(ownerId, condoId);
    if (!own.ok) return res.status(own.status).json({ error: own.error });

    const { data, error } = await supabaseAdmin
      .schema("public")
      .from("condo_bank_accounts")
      .select("*")
      .eq("condo_id", condoId)
      .order("created_at", { ascending: true });

    if (error) return res.status(500).json({ error: error.message });

    return res.json({ ok: true, accounts: data || [] });
  } catch (e) {
    return res.status(500).json({ error: e?.message || "server_error" });
  }
});

app.post("/api/v1/condos/:condoId/services", authRequired, async (req, res) => {
  try {
    const ownerId = req.ownerId;
    const condoId = req.params.condoId;

    const own = await assertOwnsCondo(ownerId, condoId);
    if (!own.ok) return res.status(own.status).json({ error: own.error });

    const name = String(req.body?.name || "").trim();
    const price = Number(req.body?.price || 0);
    const is_variable = !!req.body?.isVariable;
    const variable_type = String(req.body?.variableType || "NONE").toUpperCase();

    if (!name) return res.status(400).json({ error: "name_required" });

    const { data, error } = await supabaseAdmin
      .schema("public")
      .from("condo_services")
      .insert([{ condo_id: condoId, name, price, is_variable, variable_type }])
      .select("*")
      .single();

    if (error) return res.status(500).json({ error: error.message });

    return res.json({ ok: true, service: data });
  } catch (e) {
    return res.status(500).json({ error: e?.message || "server_error" });
  }
});

app.put("/api/v1/condos/:condoId/utilities", authRequired, async (req, res) => {
  try {
    const ownerId = req.ownerId;
    const condoId = req.params.condoId;

    const own = await assertOwnsCondo(ownerId, condoId);
    if (!own.ok) return res.status(own.status).json({ error: own.error });

    const water = req.body?.water;
    const electricity = req.body?.electricity;

    const rows = [];
    if (water) rows.push({ condo_id: condoId, utility_type: "water", billing_type: water.billingType, rate: Number(water.rate || 0) });
    if (electricity) rows.push({ condo_id: condoId, utility_type: "electricity", billing_type: electricity.billingType, rate: Number(electricity.rate || 0) });

    if (!rows.length) return res.status(400).json({ error: "no_configs" });

    // Supabase upsert โดยใช้ unique(condo_id, utility_type)
    const { error } = await supabaseAdmin
      .schema("public")
      .from("condo_utility_configs")
      .upsert(rows, { onConflict: "condo_id,utility_type" });

    if (error) return res.status(500).json({ error: error.message });

    return res.json({ ok: true });
  } catch (e) {
    return res.status(500).json({ error: e?.message || "server_error" });
  }
});

app.post("/api/v1/condos/:condoId/bank-accounts", authRequired, async (req, res) => {
  try {
    const ownerId = req.ownerId;
    const condoId = req.params.condoId;

    const own = await assertOwnsCondo(ownerId, condoId);
    if (!own.ok) return res.status(own.status).json({ error: own.error });

    const bank = String(req.body?.bank || "").trim();
    const account_name = String(req.body?.accountName || "").trim();
    const account_no = String(req.body?.accountNo || "").trim();

    if (!bank || !account_name || !account_no) return res.status(400).json({ error: "missing_fields" });

    const { data, error } = await supabaseAdmin
      .schema("public")
      .from("condo_bank_accounts")
      .insert([{ condo_id: condoId, bank, account_name, account_no }])
      .select("*")
      .single();

    if (error) return res.status(500).json({ error: error.message });

    return res.json({ ok: true, account: data });
  } catch (e) {
    return res.status(500).json({ error: e?.message || "server_error" });
  }
});

app.post("/api/v1/condos/:condoId/floors", authRequired, async (req, res) => {
  try {
    const ownerId = req.ownerId;
    const condoId = req.params.condoId;

    const own = await assertOwnsCondo(ownerId, condoId);
    if (!own.ok) return res.status(own.status).json({ error: own.error });

    const floorCount = Number(req.body?.floorCount || 0);
    const roomsPerFloor = req.body?.roomsPerFloor;

    if (!floorCount || !Array.isArray(roomsPerFloor) || roomsPerFloor.length !== floorCount) {
      return res.status(400).json({ error: "invalid_floor_payload" });
    }

    const inserts = [];
    for (let f = 1; f <= floorCount; f++) {
      const n = Number(roomsPerFloor[f - 1] || 0);
      if (!Number.isFinite(n) || n < 0) {
        return res.status(400).json({ error: "invalid_rooms_per_floor" });
      }
      for (let i = 1; i <= n; i++) {
        const roomNo = `${f}${String(i).padStart(2, "0")}`; // 101..108, 201..208
        inserts.push({
          condo_id: condoId,
          floor: f,
          room_no: roomNo,
          status: "VACANT",
          is_active: true,
        });
      }
    }

    // sync layout: clear previous rooms before inserting latest plan
    const { error: delErr } = await supabaseAdmin
      .schema("public")
      .from("rooms")
      .delete()
      .eq("condo_id", condoId);
    if (delErr) return res.status(500).json({ error: delErr.message });

    if (inserts.length > 0) {
      const { error } = await supabaseAdmin
        .schema("public")
        .from("rooms")
        .insert(inserts);
      if (error) return res.status(500).json({ error: error.message });
    }

    // update floor_count ที่ condos ด้วย
    await supabaseAdmin
      .schema("public")
      .from("condos")
      .update({ floor_count: floorCount, updated_at: new Date().toISOString() })
      .eq("id", condoId);

    return res.json({ ok: true, totalRooms: inserts.length });
  } catch (e) {
    return res.status(500).json({ error: e?.message || "server_error" });
  }
});

app.put("/api/v1/condos/:condoId/rooms/layout", authRequired, async (req, res) => {
  try {
    const ownerId = req.ownerId;
    const condoId = req.params.condoId;

    const own = await assertOwnsCondo(ownerId, condoId);
    if (!own.ok) return res.status(own.status).json({ error: own.error });

    const rooms = req.body?.rooms;
    const floorCount = Number(req.body?.floorCount || 0);
    if (!Array.isArray(rooms)) return res.status(400).json({ error: "rooms_required" });

    const inserts = [];
    for (const r of rooms) {
      const floor = Number(r?.floor || 0);
      const roomNo = String(r?.roomNo || "").trim();
      if (!floor || !roomNo) return res.status(400).json({ error: "invalid_room_payload" });
      inserts.push({
        condo_id: condoId,
        floor,
        room_no: roomNo,
        price: r?.price != null ? Number(r.price) : null,
        service_id: r?.serviceId != null ? r.serviceId : null,
        is_active: r?.isActive !== false,
        status: String(r?.status || "VACANT"),
      });
    }

    const { error: delErr } = await supabaseAdmin
      .schema("public")
      .from("rooms")
      .delete()
      .eq("condo_id", condoId);
    if (delErr) return res.status(500).json({ error: delErr.message });

    if (inserts.length > 0) {
      const { error: insErr } = await supabaseAdmin
        .schema("public")
        .from("rooms")
        .insert(inserts);
      if (insErr) return res.status(500).json({ error: insErr.message });
    }

    if (floorCount > 0) {
      await supabaseAdmin
        .schema("public")
        .from("condos")
        .update({ floor_count: floorCount, updated_at: new Date().toISOString() })
        .eq("id", condoId);
    }

    const { data, error } = await supabaseAdmin
      .schema("public")
      .from("rooms")
      .select("id, floor, room_no, price, status, service_id, is_active")
      .eq("condo_id", condoId)
      .order("floor", { ascending: true })
      .order("room_no", { ascending: true });
    if (error) return res.status(500).json({ error: error.message });

    return res.json({
      ok: true,
      rooms: (data || []).map((row) => ({
        id: row.id,
        floor: row.floor,
        roomNo: row.room_no,
        price: row.price,
        status: row.status,
        serviceId: row.service_id,
        isActive: row.is_active,
      })),
    });
  } catch (e) {
    return res.status(500).json({ error: e?.message || "server_error" });
  }
});

app.put("/api/v1/condos/:condoId/rooms/price", authRequired, async (req, res) => {
  try {
    const ownerId = req.ownerId;
    const condoId = req.params.condoId;

    const own = await assertOwnsCondo(ownerId, condoId);
    if (!own.ok) return res.status(own.status).json({ error: own.error });

    const rooms = req.body?.rooms;
    if (!Array.isArray(rooms) || rooms.length === 0) return res.status(400).json({ error: "rooms_required" });

    for (const r of rooms) {
      await supabaseAdmin.schema("public").from("rooms")
        .update({ price: Number(r.price), updated_at: new Date().toISOString() })
        .eq("id", r.roomId)
        .eq("condo_id", condoId);
    }

    return res.json({ ok: true });
  } catch (e) {
    return res.status(500).json({ error: e?.message || "server_error" });
  }
});
app.put("/api/v1/condos/:condoId/rooms/status", authRequired, async (req, res) => {
  try {
    const ownerId = req.ownerId;
    const condoId = req.params.condoId;

    const own = await assertOwnsCondo(ownerId, condoId);
    if (!own.ok) return res.status(own.status).json({ error: own.error });

    const rooms = req.body?.rooms;
    if (!Array.isArray(rooms) || rooms.length === 0) return res.status(400).json({ error: "rooms_required" });

    for (const r of rooms) {
      await supabaseAdmin.schema("public").from("rooms")
        .update({ status: String(r.status), updated_at: new Date().toISOString() })
        .eq("id", r.roomId)
        .eq("condo_id", condoId);
    }

    return res.json({ ok: true });
  } catch (e) {
    return res.status(500).json({ error: e?.message || "server_error" });
  }
});

app.put("/api/v1/condos/:condoId/rooms/service", authRequired, async (req, res) => {
  try {
    const ownerId = req.ownerId;
    const condoId = req.params.condoId;

    const own = await assertOwnsCondo(ownerId, condoId);
    if (!own.ok) return res.status(own.status).json({ error: own.error });

    const rooms = req.body?.rooms;
    if (!Array.isArray(rooms) || rooms.length === 0) return res.status(400).json({ error: "rooms_required" });

    for (const r of rooms) {
      await supabaseAdmin.schema("public").from("rooms")
        .update({ service_id: r.serviceId || null, updated_at: new Date().toISOString() })
        .eq("id", r.roomId)
        .eq("condo_id", condoId);
    }

    return res.json({ ok: true });
  } catch (e) {
    return res.status(500).json({ error: e?.message || "server_error" });
  }
});

app.get("/api/v1/condos/:condoId/rooms", authRequired, async (req, res) => {
  try {
    const ownerId = req.ownerId;
    const condoId = req.params.condoId;

    const own = await assertOwnsCondo(ownerId, condoId);
    if (!own.ok) return res.status(own.status).json({ error: own.error });

    const { data, error } = await supabaseAdmin
      .schema("public")
      .from("rooms")
      .select("id, floor, room_no, price, status, service_id, is_active")
      .eq("condo_id", condoId)
      .order("floor", { ascending: true })
      .order("room_no", { ascending: true });

    if (error) return res.status(500).json({ error: error.message });

    return res.json({
      ok: true,
      rooms: (data || []).map(r => ({
        id: r.id,
        floor: r.floor,
        roomNo: r.room_no,
        price: r.price,
        status: r.status,
        serviceId: r.service_id,
        isActive: r.is_active,
      })),
    });
  } catch (e) {
    return res.status(500).json({ error: e?.message || "server_error" });
  }
});

// ===== บันทึก access code ลงห้อง =====
app.put("/api/v1/condos/:condoId/rooms/access-code", authRequired, async (req, res) => {
  try {
    const ownerId = req.ownerId;
    const condoId = req.params.condoId;

    const own = await assertOwnsCondo(ownerId, condoId);
    if (!own.ok) return res.status(own.status).json({ error: own.error });

    const { roomId, accessCode, tenantName } = req.body || {};
    if (!roomId || !accessCode) return res.status(400).json({ error: "roomId and accessCode required" });

    const { error } = await supabaseAdmin
      .schema("public")
      .from("rooms")
      .update({
        access_code: String(accessCode),
        tenant_name: tenantName ? String(tenantName) : null,
        updated_at: new Date().toISOString(),
      })
      .eq("id", roomId)
      .eq("condo_id", condoId);

    if (error) return res.status(500).json({ error: error.message });

    return res.json({ ok: true });
  } catch (e) {
    return res.status(500).json({ error: e?.message || "server_error" });
  }
});

// ===== ผู้เช่าใส่ access code เพื่อผูก LINE กับห้อง =====
app.post("/api/v1/tenant/link-room", async (req, res) => {
  try {
    const { accessCode, lineUserId } = req.body || {};
    if (!accessCode) return res.status(400).json({ error: "accessCode required" });
    if (!lineUserId) return res.status(400).json({ error: "lineUserId required" });

    const trimmed = String(accessCode).trim();

    // หาห้องที่ตรงกับ access code
    const { data: room, error: roomErr } = await supabaseAdmin
      .schema("public")
      .from("rooms")
      .select("id, room_no, floor, condo_id, tenant_name, access_code, status")
      .eq("access_code", trimmed)
      .maybeSingle();

    if (roomErr) return res.status(500).json({ error: roomErr.message });
    if (!room) return res.status(404).json({ error: "invalid_code" });

    // ดึงข้อมูลคอนโด
    const { data: condo } = await supabaseAdmin
      .schema("public")
      .from("condos")
      .select("id, name_th")
      .eq("id", room.condo_id)
      .maybeSingle();

    // สร้าง/อัพเดต dorm_user ผู้เช่า (ใช้ access code เป็น code)
    const { data: existingDorm } = await supabaseAdmin
      .schema("public")
      .from("dorm_users")
      .select("id, line_user_id")
      .eq("line_user_id", String(lineUserId))
      .maybeSingle();

    if (existingDorm) {
      // อัพเดต room + full_name
      await supabaseAdmin.from("dorm_users").update({
        room: room.room_no || null,
        full_name: room.tenant_name || existingDorm.full_name || "ผู้เช่า",
        condo_id: room.condo_id,   // ✅ เพิ่มนี้
      }).eq("id", existingDorm.id);
    } else {
      // สร้างใหม่
      await supabaseAdmin.from("dorm_users").insert([{
        code: trimmed,
        full_name: room.tenant_name || "ผู้เช่า",
        line_user_id: String(lineUserId),
        room: room.room_no || null,
        condo_id: room.condo_id,   // ✅ เพิ่มนี้
      }]);
    }

    return res.json({
      ok: true,
      roomId: room.id,
      roomNo: room.room_no,
      floor: room.floor,
      condoId: room.condo_id,
      condoName: condo?.name_th || "RentSphere",
      tenantName: room.tenant_name || "ผู้เช่า",
    });
  } catch (e) {
    return res.status(500).json({ error: e?.message || "server_error" });
  }
});

// GET facilities ของ condo
app.get("/api/v1/condos/:condoId/facilities", authRequired, async (req, res) => {
  const own = await assertOwnsCondo(req.ownerId, req.params.condoId);
  if (!own.ok) return res.status(own.status).json({ error: own.error });

  const { data, error } = await supabaseAdmin
    .from("facilities").select("*").eq("condo_id", req.params.condoId)
    .order("created_at", { ascending: false });
  if (error) return res.status(500).json({ error: error.message });
  return res.json({ ok: true, items: data || [] });
});

// POST สร้าง facility ใหม่
app.post("/api/v1/condos/:condoId/facilities", authRequired, async (req, res) => {
  const own = await assertOwnsCondo(req.ownerId, req.params.condoId);
  if (!own.ok) return res.status(own.status).json({ error: own.error });

  const { name, type, capacity, open_time, close_time, slot_minutes,
    is_auto_approve, description, active } = req.body || {};
  if (!name) return res.status(400).json({ error: "name required" });

  const { data, error } = await supabaseAdmin
    .from("facilities").insert([{
      condo_id: req.params.condoId, name,
      type: type || "sport", capacity: Number(capacity || 10),
      open_time, close_time,
      slot_minutes: Number(slot_minutes || 60),
      is_auto_approve: Boolean(is_auto_approve ?? true),
      description: description || null,
      active: active !== false,
    }]).select("*").single();
  if (error) return res.status(500).json({ error: error.message });
  return res.json({ ok: true, item: data });
});






/* ===================================
   ========== DORM + LINE LOGIN =======
   =================================== */

// ===== 1) สมัครหอพัก =====
app.post("/dorm/register", async (req, res) => {
  try {
    const { full_name, phone, email } = req.body || {};
    if (!full_name || !String(full_name).trim()) {
      return res.status(400).json({ error: "full_name is required" });
    }

    const payload = {
      full_name: String(full_name).trim(),
      phone: phone ? String(phone).trim() : null,
      email: email ? String(email).trim() : null,
    };

    for (let tries = 0; tries < 5; tries++) {
      const code = genCode(8);

      const { data, error } = await supabaseAdmin
        .schema("public")
        .from("dorm_users")
        .insert([{ code, ...payload }])
        .select("code, registered_at")
        .single();

      if (!error) return res.json({ ok: true, ...data });

      // unique violation
      if (error.code !== "23505") {
        return res.status(500).json({ step: "insert_failed", error: pickErr(error) });
      }
    }

    return res.status(500).json({ error: "Could not generate unique code" });
  } catch (e) {
    return res.status(500).json({ error: pickErr(e) });
  }
});

// ===== 2) LINE login =====
app.get("/auth/line/login", (req, res) => {
  const state = Math.random().toString(36).slice(2);

  const url =
    `https://access.line.me/oauth2/v2.1/authorize` +
    `?response_type=code` +
    `&client_id=${process.env.LINE_LOGIN_CLIENT_ID}` +
    `&redirect_uri=${encodeURIComponent(process.env.LINE_LOGIN_REDIRECT_URI)}` +
    `&state=${state}` +
    `&scope=profile%20openid`;

  return res.redirect(url);
});

// ===== 3) LINE callback =====
app.get("/auth/line/callback", async (req, res) => {
  const { code } = req.query;
  if (!code) return res.status(400).send("No code");

  try {
    const tokenRes = await fetchFn("https://api.line.me/oauth2/v2.1/token", {
      method: "POST",
      headers: { "Content-Type": "application/x-www-form-urlencoded" },
      body: new URLSearchParams({
        grant_type: "authorization_code",
        code: String(code),
        redirect_uri: process.env.LINE_LOGIN_REDIRECT_URI,
        client_id: process.env.LINE_LOGIN_CLIENT_ID,
        client_secret: process.env.LINE_LOGIN_CLIENT_SECRET,
      }),
    });

    const token = await tokenRes.json();
    if (!tokenRes.ok || !token.access_token) {
      return res.status(400).json({ step: "token_exchange_failed", status: tokenRes.status, token });
    }

    const profileRes = await fetchFn("https://api.line.me/v2/profile", {
      headers: { Authorization: `Bearer ${token.access_token}` },
    });

    const profile = await profileRes.json();
    if (!profileRes.ok || !profile.userId) {
      return res.status(400).json({ step: "profile_fetch_failed", status: profileRes.status, profile });
    }

    const { error: upsertErr } = await supabaseAdmin
      .schema("public")
      .from("line_users")
      .upsert(
        {
          line_user_id: profile.userId,
          display_name: profile.displayName,
          picture_url: profile.pictureUrl,
          raw_profile: profile,
          last_login_at: new Date().toISOString(),
        },
        { onConflict: "line_user_id" }
      );

    if (upsertErr) {
      return res.status(500).json({ step: "supabase_upsert_failed", error: pickErr(upsertErr) });
    }

    const frontend = process.env.FRONTEND_URL || "http://localhost:5173";
    return res.redirect(`${frontend}/owner/line-login-success?lineUserId=${encodeURIComponent(profile.userId)}`);
  } catch (e) {
    return res.status(500).json({ step: "callback_catch", error: pickErr(e) });
  }
});

// ===== 4) link code =====
app.post("/dorm/link-line", async (req, res) => {
  try {
    const { code, lineUserId } = req.body || {};
    if (!code || !lineUserId) return res.status(400).json({ error: "code and lineUserId required" });

    const normalizedCode = String(code).trim().toUpperCase();

    const { data: user, error: findErr } = await supabaseAdmin
      .schema("public")
      .from("dorm_users")
      .select("id, line_user_id")
      .eq("code", normalizedCode)
      .maybeSingle();

    if (findErr) return res.status(500).json({ step: "find_failed", error: pickErr(findErr) });
    if (!user) return res.status(404).json({ error: "invalid_code" });
    if (user.line_user_id) return res.status(409).json({ error: "code_already_used" });

    const { error: updErr } = await supabaseAdmin
      .schema("public")
      .from("dorm_users")
      .update({ line_user_id: String(lineUserId) })
      .eq("id", user.id);

    if (updErr) return res.status(500).json({ step: "update_failed", error: pickErr(updErr) });

    return res.json({ ok: true });
  } catch (e) {
    return res.status(500).json({ error: pickErr(e) });
  }
});

// dorm status
app.get("/dorm/status", async (req, res) => {
  try {
    const { lineUserId } = req.query;
    if (!lineUserId) return res.status(400).json({ error: "lineUserId required" });

    const { data, error } = await supabaseAdmin
      .schema("public")
      .from("dorm_users")
      .select("id, full_name, phone, email, registered_at, line_user_id, room")
      .eq("line_user_id", String(lineUserId))
      .maybeSingle();

    if (error) return res.status(500).json({ error: pickErr(error) });
    if (!data) return res.json({ ok: true, linked: false });

    return res.json({ ok: true, linked: true, dormUser: data });
  } catch (e) {
    return res.status(500).json({ error: pickErr(e) });
  }
});

/* ===================================
   ========== REPAIRS API =============
   =================================== */

app.post("/repair/create", upload.array("images", 5), async (req, res) => {
  try {
    const { lineUserId, problem_type, description, location, room, room_id } = req.body || {};
    if (!lineUserId) return res.status(400).json({ error: "lineUserId required" });
    if (!problem_type || !String(problem_type).trim()) return res.status(400).json({ error: "problem_type required" });

    const { data: dormUser, error: dormErr } = await supabaseAdmin
      .schema("public")
      .from("dorm_users")
      .select("id")
      .eq("line_user_id", String(lineUserId))
      .maybeSingle();

    if (dormErr) return res.status(500).json({ step: "find_dorm_failed", error: pickErr(dormErr) });
    if (!dormUser) return res.status(403).json({ error: "not_linked_dorm_code" });

    const files = req.files || [];
    const imageUrls = [];

    for (const f of files) {
      const ext = (f.mimetype?.split("/")?.[1] || "jpg").replace("jpeg", "jpg");
      const filename = `${randomUUID()}.${ext}`;
      const path = `${dormUser.id}/${Date.now()}_${filename}`;

      const { error: upErr } = await supabaseAdmin.storage
        .from(REPAIR_BUCKET)
        .upload(path, f.buffer, { contentType: f.mimetype, upsert: false });

      if (upErr) return res.status(500).json({ step: "upload_failed", error: pickErr(upErr), bucket: REPAIR_BUCKET });

      const { data: pub } = supabaseAdmin.storage.from(REPAIR_BUCKET).getPublicUrl(path);
      imageUrls.push(pub.publicUrl);
    }

    const payload = {
      problem_type: String(problem_type).trim(),
      description: description ? String(description) : null,
      location: location ? String(location) : null,
      room: room ? String(room) : null,
      room_id: room_id ? String(room_id) : null,
      status: "new",
      line_user_id: String(lineUserId),
      dorm_user_id: dormUser.id,
      image_url: imageUrls[0] || null,
    };

    const { data: created, error: insErr } = await supabaseAdmin
      .schema("public")
      .from("repair_request")
      .insert([payload])
      .select("*")
      .single();

    if (insErr) return res.status(500).json({ step: "insert_failed", error: pickErr(insErr) });

    return res.json({ ok: true, repair: created, imageUrls });
  } catch (e) {
    return res.status(500).json({ step: "catch", error: pickErr(e) });
  }
});

app.get("/repair/my", async (req, res) => {
  try {
    const { lineUserId } = req.query;
    if (!lineUserId) return res.status(400).json({ error: "lineUserId required" });

    const { data, error } = await supabaseAdmin
      .schema("public")
      .from("repair_request")
      .select("id, created_at, problem_type, status, location, room, image_url")
      .eq("line_user_id", String(lineUserId))
      .order("created_at", { ascending: false });

    if (error) return res.status(500).json({ step: "select_failed", error: pickErr(error) });

    return res.json({ ok: true, items: data || [] });
  } catch (e) {
    return res.status(500).json({ error: pickErr(e) });
  }
});

app.get("/repair/:id", async (req, res) => {
  try {
    const { id } = req.params;
    const { lineUserId } = req.query;
    if (!lineUserId) return res.status(400).json({ error: "lineUserId required" });

    const { data, error } = await supabaseAdmin
      .schema("public")
      .from("repair_request")
      .select("*")
      .eq("id", id)
      .eq("line_user_id", String(lineUserId))
      .maybeSingle();

    if (error) return res.status(500).json({ step: "select_failed", error: pickErr(error) });
    if (!data) return res.status(404).json({ error: "not_found" });

    return res.json({ ok: true, item: data });
  } catch (e) {
    return res.status(500).json({ error: pickErr(e) });
  }
});

/* ===================================
   ========== ADMIN + LINE PUSH =======
   =================================== */

async function isAdminLineUser(lineUserId) {
  const { data, error } = await supabaseAdmin
    .schema("public")
    .from("line_users")
    .select("role")
    .eq("line_user_id", String(lineUserId))
    .maybeSingle();

  if (error) throw error;
  return data?.role === "admin";
}

function requireAdmin(req, res, next) {
  // ✅ ปิดการเช็คสิทธิ์แอดมินทั้งหมด (ไม่มี admin secret / ไม่เช็ค role)
  // หมายเหตุ: route ที่ครอบด้วย requireAdmin จะเปิดให้ใช้งานได้ทุกคน
  req.adminLineUserId = "public-admin";
  return next();
}

// ✅ push LINE message (ข้อความอย่างเดียว / หรือ object text)
async function pushLineMessage(toLineUserId, payload) {
  const token = process.env.LINE_MESSAGING_ACCESS_TOKEN;
  if (!token) throw new Error("Missing LINE_MESSAGING_ACCESS_TOKEN");

  let messages = [];

  if (typeof payload === "string") {
    messages = [{ type: "text", text: payload }];
  } else if (payload?.type === "text") {
    messages = [{ type: "text", text: String(payload.text) }];
  } else if (payload?.type === "multi") {
    const img = String(payload.imageUrl || "").trim();
    if (!img) throw new Error("Missing imageUrl for multi");

    messages = [
      { type: "text", text: String(payload.text || "") },
      { type: "image", originalContentUrl: img, previewImageUrl: img },
    ];
  } else {
    throw new Error("Invalid push payload");
  }

  const r = await fetchFn("https://api.line.me/v2/bot/message/push", {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      Authorization: `Bearer ${token}`,
    },
    body: JSON.stringify({ to: String(toLineUserId), messages }),
  });

  const raw = await r.text();
  if (!r.ok) throw new Error(`LINE push failed: ${r.status} ${raw}`);
}

async function requireLineLogin(req, res, next) {
  try {
    const lineUserId = req.headers["x-line-user-id"] || req.query.lineUserId || req.body?.lineUserId;
    if (!lineUserId) return res.status(401).json({ error: "lineUserId required" });

    const { data: dormUser, error } = await supabaseAdmin
      .schema("public")
      .from("dorm_users")
      .select("id, line_user_id, full_name, room")
      .eq("line_user_id", String(lineUserId))
      .maybeSingle();

    if (error) return res.status(500).json({ error: pickErr(error) });
    if (!dormUser) return res.status(403).json({ error: "not_linked_dorm_code" });

    req.user = {
      line_user_id: String(lineUserId),
      dorm_user_id: dormUser.id,
      full_name: dormUser.full_name,
      room: dormUser.room,
    };

    next();
  } catch (e) {
    return res.status(500).json({ error: pickErr(e) });
  }
}

// ===== push by dorm_user_id =====
async function pushLineByDormUserId(dormUserId, payload) {
  const { data: u, error } = await supabaseAdmin
    .schema("public")
    .from("dorm_users")
    .select("line_user_id")
    .eq("id", String(dormUserId))
    .maybeSingle();

  if (error) throw error;
  if (!u?.line_user_id) throw new Error("tenant_has_no_line_user_id");

  return pushLineMessage(u.line_user_id, payload);
}

/* =========================
   Admin Tenants
   ========================= */
app.get("/admin/tenants", async (req, res) => {
  try {
    const { condoId } = req.query;

    let query = supabaseAdmin
      .from("dorm_users")
      .select("*")
      .order("created_at", { ascending: false });

    if (condoId) {
      query = query.eq("condo_id", condoId);
    }

    const { data, error } = await query;
    if (error) return res.status(500).json({ error: error.message });
    return res.json({ items: data || [] });
  } catch (e) {
    return res.status(500).json({ error: e?.message || "server_error" });
  }
});


// DELETE /admin/terminate-contract — ยุติสัญญา (ลบ dorm_user + เปลี่ยนห้องเป็น VACANT)
app.delete("/admin/terminate-contract", requireAdmin, async (req, res) => {
  try {
    const { dormUserId, roomId, condoId } = req.body || {};
    if (!dormUserId) return res.status(400).json({ error: "dormUserId required" });
    if (!roomId) return res.status(400).json({ error: "roomId required" });

    // 1) ลบ dorm_user (ผู้เช่า)
    const { error: delErr } = await supabaseAdmin
      .from("dorm_users")
      .delete()
      .eq("id", dormUserId);
    if (delErr) return res.status(500).json({ error: delErr.message });

    // 2) เปลี่ยนห้องเป็น VACANT + เคลียร์ access_code, tenant_name
    const { error: updErr } = await supabaseAdmin
      .from("rooms")
      .update({
        status: "VACANT",
        access_code: null,
        tenant_name: null,
        updated_at: new Date().toISOString(),
      })
      .eq("id", roomId);
    if (updErr) return res.status(500).json({ error: updErr.message });

    return res.json({ ok: true });
  } catch (e) {
    return res.status(500).json({ error: e?.message || "server_error" });
  }
});



// PATCH /tenant/profile — อัพเดตชื่อ/โทร/เมลของ tenant
app.patch("/tenant/profile", requireLineLogin, async (req, res) => {
  try {
    const dormUserId = req.user.dorm_user_id;
    const updates = {};
    if (req.body?.full_name) updates.full_name = String(req.body.full_name).trim();
    if (req.body?.phone) updates.phone = String(req.body.phone).trim();
    if (req.body?.email) updates.email = String(req.body.email).trim();

    if (Object.keys(updates).length === 0)
      return res.status(400).json({ error: "no_fields" });

    const { data, error } = await supabaseAdmin
      .from("dorm_users")
      .update(updates)
      .eq("id", dormUserId)
      .select("id, full_name, phone, email, room")
      .single();

    if (error) return res.status(500).json({ error: error.message });
    return res.json({ ok: true, user: data });
  } catch (e) {
    return res.status(500).json({ error: e?.message || "server_error" });
  }
});



/* =========================
   Parcels (Admin create + Tenant view/pickup)
   ========================= */

// ===== admin: สร้างพัสดุ + อัปโหลดรูป + ส่ง LINE =====
app.post("/admin/parcel/create", requireAdmin, upload.single("image"), async (req, res) => {
  try {
    const { dormUserId, note } = req.body || {};
    if (!dormUserId) return res.status(400).json({ error: "dormUserId required" });
    if (!req.file) return res.status(400).json({ error: "image file required" });

    const { data: tenant, error: tErr } = await supabaseAdmin
      .schema("public")
      .from("dorm_users")
      .select("id, line_user_id, full_name")
      .eq("id", String(dormUserId))
      .maybeSingle();

    if (tErr) return res.status(500).json({ error: pickErr(tErr) });
    if (!tenant) return res.status(404).json({ error: "tenant_not_found" });
    if (!tenant.line_user_id) return res.status(400).json({ error: "tenant_has_no_line_user_id" });

    const f = req.file;
    const ext = (f.mimetype?.split("/")?.[1] || "jpg").replace("jpeg", "jpg");
    const filename = `${randomUUID()}.${ext}`;
    const path = `${tenant.id}/${Date.now()}_${filename}`;

    const { error: upErr } = await supabaseAdmin.storage
      .from(PARCEL_BUCKET)
      .upload(path, f.buffer, { contentType: f.mimetype, upsert: false });

    if (upErr) return res.status(500).json({ step: "upload_failed", error: pickErr(upErr) });

    const { data: pub } = supabaseAdmin.storage.from(PARCEL_BUCKET).getPublicUrl(path);
    const imageUrl = pub.publicUrl;

    const { data: created, error: insErr } = await supabaseAdmin
      .schema("public")
      .from("parcels")
      .insert([
        {
          dorm_user_id: tenant.id,
          line_user_id: tenant.line_user_id,
          image_url: imageUrl,
          note: note ? String(note) : null,
          status: "sent",
        },
      ])
      .select("*")
      .single();

    if (insErr) return res.status(500).json({ step: "insert_failed", error: pickErr(insErr) });

    const text =
      note && String(note).trim()
        ? `📦 พัสดุมาถึงแล้ว!\n${String(note).trim()}`
        : `📦 พัสดุมาถึงแล้ว!\nกรุณามารับที่จุดรับพัสดุ`;

    await pushLineMessage(tenant.line_user_id, { type: "multi", text, imageUrl });

    return res.json({ ok: true, item: created, imageUrl });
  } catch (e) {
    return res.status(500).json({ error: e.message || "server error" });
  }
});

// ===== tenant: list parcels ของฉัน =====
app.get("/parcels/my", async (req, res) => {
  try {
    const { lineUserId } = req.query;
    if (!lineUserId) return res.status(400).json({ error: "lineUserId required" });

    const { data, error } = await supabaseAdmin
      .schema("public")
      .from("parcels")
      .select("id, created_at, image_url, note, status, picked_up_at")
      .eq("line_user_id", String(lineUserId))
      .order("created_at", { ascending: false });

    if (error) return res.status(500).json({ error: pickErr(error) });
    return res.json({ ok: true, items: data || [] });
  } catch (e) {
    return res.status(500).json({ error: pickErr(e) });
  }
});

// tenant: detail parcel ของฉัน
app.get("/parcels/:id", async (req, res) => {
  try {
    const { id } = req.params;
    const { lineUserId } = req.query;
    if (!lineUserId) return res.status(400).json({ error: "lineUserId required" });

    const { data, error } = await supabaseAdmin
      .schema("public")
      .from("parcels")
      .select("*")
      .eq("id", String(id))
      .eq("line_user_id", String(lineUserId))
      .maybeSingle();

    if (error) return res.status(500).json({ error: pickErr(error) });
    if (!data) return res.status(404).json({ error: "not_found" });

    return res.json({ ok: true, item: data });
  } catch (e) {
    return res.status(500).json({ error: pickErr(e) });
  }
});

// tenant: ยืนยันรับพัสดุ (picked_up)
app.patch("/parcels/:id/pickup", async (req, res) => {
  try {
    const { id } = req.params;
    const { lineUserId } = req.body || {};
    if (!lineUserId) return res.status(400).json({ error: "lineUserId required" });

    const { data: parcel, error: fErr } = await supabaseAdmin
      .schema("public")
      .from("parcels")
      .select("id, line_user_id, status, picked_up_at")
      .eq("id", String(id))
      .maybeSingle();

    if (fErr) return res.status(500).json({ error: pickErr(fErr) });
    if (!parcel) return res.status(404).json({ error: "not_found" });
    if (String(parcel.line_user_id) !== String(lineUserId)) {
      return res.status(403).json({ error: "forbidden" });
    }

    if (String(parcel.status || "").toLowerCase() === "picked_up") {
      return res.json({ ok: true, item: parcel, already: true });
    }

    const { data: updated, error: uErr } = await supabaseAdmin
      .schema("public")
      .from("parcels")
      .update({ status: "picked_up", picked_up_at: new Date().toISOString() })
      .eq("id", String(id))
      .eq("line_user_id", String(lineUserId))
      .select("*")
      .single();

    if (uErr) return res.status(500).json({ error: pickErr(uErr) });
    return res.json({ ok: true, item: updated });
  } catch (e) {
    return res.status(500).json({ error: pickErr(e) });
  }
});

// ===== admin: ประวัติการแจ้งพัสดุ =====
// ===== GET /admin/parcel/history — filter by condoId =====
app.get("/admin/parcel/history", async (req, res) => {
  try {
    const { condoId } = req.query;

    let dormUserFilter = null;
    if (condoId) {
      const { data: users } = await supabaseAdmin
        .from("dorm_users")
        .select("id, full_name, room")
        .eq("condo_id", condoId);

      if (!users || users.length === 0) return res.json({ items: [] });
      dormUserFilter = users;
    }

    let query = supabaseAdmin
      .from("parcels")
      .select("*")
      .order("created_at", { ascending: false });

    if (dormUserFilter) {
      query = query.in("dorm_user_id", dormUserFilter.map(u => u.id));
    }

    const { data, error } = await query;
    if (error) return res.status(500).json({ error: error.message });

    let dormMap = {};
    if (dormUserFilter) {
      for (const u of dormUserFilter) dormMap[u.id] = { name: u.full_name || "", room: u.room || "" };
    } else {
      const ids = [...new Set((data || []).map(r => r.dorm_user_id).filter(Boolean))];
      if (ids.length > 0) {
        const { data: d } = await supabaseAdmin.from("dorm_users").select("id, full_name, room").in("id", ids);
        for (const u of (d || [])) dormMap[u.id] = { name: u.full_name || "", room: u.room || "" };
      }
    }

    const mapped = (data || []).map(row => ({
      id: row.id,
      dormUserId: row.dorm_user_id,
      tenantName: dormMap[row.dorm_user_id]?.name || "",
      room: dormMap[row.dorm_user_id]?.room || null,
      note: row.note || null,
      imageUrl: row.image_url || null,
      createdAt: row.created_at,
      status: row.status || "sent",
    }));

    return res.json({ items: mapped });
  } catch (e) {
    return res.status(500).json({ error: e?.message || "server_error" });
  }
});





/* =========================
   Admin Repairs
   ========================= */
// ===== GET /admin/repairs  — filter by status + condoId =====
app.get("/admin/repairs", async (req, res) => {
  try {
    const { status, condoId } = req.query;
    let query = supabaseAdmin
      .from("repair_request")
      .select("*")
      .order("created_at", { ascending: false });
    if (status) {
      const statusMap = {
        new: ["new", "ใหม่"],
        in_progress: ["in_progress", "กำลังดำเนินงาน"],
        done: ["done", "เสร็จแล้ว"],
        rejected: ["rejected", "ปฏิเสธ"],
      };
      const vals = statusMap[status];
      if (vals) query = query.in("status", vals);
    }
    if (condoId) {
      // ดึง dorm_user_id ของคอนโดนี้
      const { data: users } = await supabaseAdmin
        .from("dorm_users")
        .select("id")
        .eq("condo_id", condoId);
      if (!users || users.length === 0) return res.json({ items: [] });
      query = query.in("dorm_user_id", users.map(u => u.id));
    }
    const { data, error } = await query;
    if (error) return res.status(500).json({ error: error.message });
    return res.json({ items: data || [] });
  } catch (e) {
    return res.status(500).json({ error: e?.message || "server_error" });
  }
});





app.patch("/admin/repair/:id/status", requireAdmin, async (req, res) => {
  try {
    const { id } = req.params;
    const { status, message } = req.body || {};
    if (!status) return res.status(400).json({ error: "status required" });

    const { data: ticket, error: findErr } = await supabaseAdmin
      .schema("public")
      .from("repair_request")
      .select("*")
      .eq("id", id)
      .maybeSingle();

    if (findErr) return res.status(500).json({ error: pickErr(findErr) });
    if (!ticket) return res.status(404).json({ error: "not_found" });

    const { data: updated, error: updErr } = await supabaseAdmin
      .schema("public")
      .from("repair_request")
      .update({ status: String(status) })
      .eq("id", id)
      .select("*")
      .single();

    if (updErr) return res.status(500).json({ error: pickErr(updErr) });

    const text = message?.trim() ? message.trim() : `อัปเดตงานแจ้งซ่อม #${ticket.id}\nสถานะ: ${status}`;
    if (ticket.line_user_id) {
      try {
        await pushLineMessage(ticket.line_user_id, text);
      } catch (e) {
        console.error("LINE push repair status error:", e);
      }
    }

    return res.json({ ok: true, item: updated });
  } catch (e) {
    return res.status(500).json({ error: e.message || "server error" });
  }
});

/* =========================
   Facilities (Admin)
   ========================= */

// list facilities
app.get("/admin/facilities", requireAdmin, async (req, res) => {
  try {
    const { data, error } = await supabaseAdmin
      .schema("public")
      .from("facilities")
      .select("*")
      .order("created_at", { ascending: false });

    if (error) return res.status(500).json({ error: pickErr(error) });
    return res.json({ ok: true, items: data || [] });
  } catch (e) {
    return res.status(500).json({ error: pickErr(e) });
  }
});

// create facility
app.post("/admin/facilities", requireAdmin, async (req, res) => {
  try {
    const {
      name,
      description,
      image_url,
      type,
      status,
      capacity,
      open_time,
      close_time,
      slot_minutes,
      is_auto_approve,
      tags,
      location,
      active,
    } = req.body || {};

    if (!name || !String(name).trim()) return res.status(400).json({ error: "name required" });
    if (!open_time || !close_time) return res.status(400).json({ error: "open_time and close_time required" });

    const payload = {
      name: String(name).trim(),
      description: description ? String(description) : null,
      image_url: image_url ? String(image_url) : null,
      type: String(type || "sport"),
      status: String(status || "available"),
      capacity: Number(capacity || 10),
      open_time: String(open_time),
      close_time: String(close_time),
      slot_minutes: Number(slot_minutes || 60),
      is_auto_approve: Boolean(is_auto_approve ?? true),
      tags: Array.isArray(tags) ? tags : [],
      location: location ? String(location) : null,
      active: typeof active === "boolean" ? active : true,
    };

    const { data, error } = await supabaseAdmin
      .schema("public")
      .from("facilities")
      .insert([payload])
      .select("*")
      .single();

    if (error) return res.status(500).json({ error: pickErr(error) });
    return res.json({ ok: true, item: data });
  } catch (e) {
    return res.status(500).json({ error: pickErr(e) });
  }
});

/* ===================================
   ========== FACILITIES (TENANT) =====
   =================================== */
app.get("/tenant/facilities", requireLineLogin, async (req, res) => {
  try {
    // 1. หา code ของ tenant (ที่ใช้ลิงก์ห้อง)
    const { data: du } = await supabaseAdmin
      .from("dorm_users")
      .select("code")
      .eq("id", req.user.dorm_user_id)
      .single();

    let condoId = null;

    if (du?.code) {
      // 2. หาห้องที่ตรงกับ access_code → ได้ condo_id
      const { data: room } = await supabaseAdmin
        .from("rooms")
        .select("condo_id")
        .eq("access_code", du.code)
        .maybeSingle();

      condoId = room?.condo_id || null;
    }

    // 3. โหลด facilities (ถ้ามี condoId → เฉพาะคอนโดนั้น, ไม่มี → ทั้งหมด)
    let q = supabaseAdmin
      .schema("public")
      .from("facilities")
      .select("*")
      .eq("active", true)
      .order("created_at", { ascending: false });

    if (condoId) {
      q = q.eq("condo_id", condoId);
    }

    const { data, error } = await q;
    if (error) return res.status(500).json({ error: pickErr(error) });
    return res.json({ ok: true, items: data || [] });
  } catch (e) {
    return res.status(500).json({ error: pickErr(e) });
  }
});


/** ✅ รายการจองของฉัน (วันเลือก) */
app.get("/tenant/facility-bookings/my", requireLineLogin, async (req, res) => {
  // กัน cache 304
  res.setHeader("Cache-Control", "no-store, no-cache, must-revalidate, proxy-revalidate");
  res.setHeader("Pragma", "no-cache");
  res.setHeader("Expires", "0");

  try {
    const dormUserId = req.user.dorm_user_id;
    const date = String(req.query.date || "").trim(); // YYYY-MM-DD (วันไทย)

    let q = supabaseAdmin
      .schema("public")
      .from("facility_bookings")
      .select("id, facility_id, start_at, end_at, status, note, checked_in_at, finished_at, end_reminded_at, end_notified_at")
      .eq("dorm_user_id", dormUserId)
      .order("start_at", { ascending: true });

    if (date) {
      const { startUtc, endUtc } = bkkDayRangeUTCFromYmd(date);
      q = q.gte("start_at", startUtc.toISOString()).lt("start_at", endUtc.toISOString());
    }

    const { data, error } = await q;
    if (error) return res.status(500).json({ error: pickErr(error) });

    return res.json({ ok: true, items: data || [] });
  } catch (e) {
    return res.status(500).json({ error: pickErr(e) });
  }
});

/** ✅ Availability: นับจำนวนต่อ slot เพื่อให้ UI รู้ว่าช่วงไหนมีคนจองแล้ว */
app.get("/tenant/facility-bookings/availability", requireLineLogin, async (req, res) => {
  try {
    const facilityId = String(req.query.facility_id || "").trim();
    const date = String(req.query.date || "").trim(); // YYYY-MM-DD
    if (!facilityId) return res.status(400).json({ error: "facility_id required" });
    if (!date) return res.status(400).json({ error: "date required" });

    const { data: fac, error: facErr } = await supabaseAdmin
      .schema("public")
      .from("facilities")
      .select("id, capacity")
      .eq("id", facilityId)
      .maybeSingle();

    if (facErr) return res.status(500).json({ error: pickErr(facErr) });
    if (!fac) return res.status(404).json({ error: "facility not found" });

    // ✅ boundary วันไทย -> UTC (explicit +07:00)
    const { startUtc, endUtc } = bkkDayRangeUTCFromYmd(date);

    const { data: list, error } = await supabaseAdmin
      .schema("public")
      .from("facility_bookings")
      .select("id, start_at, status")
      .eq("facility_id", facilityId)
      .gte("start_at", startUtc.toISOString())
      .lt("start_at", endUtc.toISOString())
      .in("status", ["booked", "active"]);

    if (error) return res.status(500).json({ error: pickErr(error) });

    const counts = {};
    for (const b of list || []) {
      const key = hhmmBangkokFromISO(b.start_at); // ✅ HH:mm เวลาไทย
      counts[key] = (counts[key] || 0) + 1;
    }

    return res.json({
      ok: true,
      facility_id: facilityId,
      date,
      capacity: Number(fac.capacity || 1),
      counts,
    });
  } catch (e) {
    return res.status(500).json({ error: pickErr(e) });
  }
});

/** ✅ สร้าง booking (จองครั้งละ 60 นาที) */
app.post("/tenant/facility-bookings", requireLineLogin, async (req, res) => {
  try {
    const { facility_id, start_at, minutes, note } = req.body || {};
    if (!facility_id) return res.status(400).json({ error: "facility_id required" });
    if (!start_at) return res.status(400).json({ error: "start_at required" });

    const m = Number(minutes || 60);
    if (m !== 60) return res.status(400).json({ error: "จองได้ครั้งละ 1 ชั่วโมง (60 นาที) เท่านั้น" });

    const dormUserId = req.user.dorm_user_id;

    const { data: fac, error: facErr } = await supabaseAdmin
      .schema("public")
      .from("facilities")
      .select("id, capacity, active, name")
      .eq("id", facility_id)
      .maybeSingle();

    if (facErr) return res.status(500).json({ error: pickErr(facErr) });
    if (!fac) return res.status(404).json({ error: "facility not found" });
    if (!fac.active) return res.status(400).json({ error: "พื้นที่นี้ปิดใช้งาน" });

    const start = new Date(start_at);
    if (Number.isNaN(start.getTime())) return res.status(400).json({ error: "start_at invalid" });
    const end = new Date(start.getTime() + 60 * 60 * 1000);

    // ✅ จำกัดรวมต่อวัน ไม่เกิน 2 ชม (ขอบเขตวันไทยแบบ +07:00)
    const { startUtc: dayStart, endUtc: dayEnd } = bkkDayRangeUTCFromDate(start);

    const { data: dayBookings, error: dayErr } = await supabaseAdmin
      .schema("public")
      .from("facility_bookings")
      .select("id, start_at, end_at, status")
      .eq("dorm_user_id", dormUserId)
      .gte("start_at", dayStart.toISOString())
      .lt("start_at", dayEnd.toISOString())
      .in("status", ["booked", "active"]);

    if (dayErr) return res.status(500).json({ error: pickErr(dayErr) });

    const usedMinutes =
      (dayBookings || []).reduce((sum, b) => {
        const s = new Date(b.start_at).getTime();
        const e = new Date(b.end_at).getTime();
        const mins = Math.max(0, Math.round((e - s) / 60000));
        return sum + mins;
      }, 0) || 0;

    if (usedMinutes + 60 > 120) {
      return res.status(400).json({ error: "วันนี้คุณจองได้ไม่เกิน 2 ชั่วโมง" });
    }

    // ✅ กันเวลาทับซ้อนของ user เอง
    const { data: myOverlap, error: myOErr } = await supabaseAdmin
      .schema("public")
      .from("facility_bookings")
      .select("id")
      .eq("dorm_user_id", dormUserId)
      .in("status", ["booked", "active"])
      .lt("start_at", end.toISOString())
      .gt("end_at", start.toISOString())
      .limit(1);

    if (myOErr) return res.status(500).json({ error: pickErr(myOErr) });
    if ((myOverlap || []).length) return res.status(400).json({ error: "คุณมีการจองที่ทับซ้อนช่วงเวลานี้" });

    // ✅ เช็คช่วงเวลานี้มีคนจองแล้วไหม (exclusive: มีคนเดียวก็ล็อก)
    const { count: overlapCount, error: capErr } = await supabaseAdmin
      .schema("public")
      .from("facility_bookings")
      .select("id", { count: "exact", head: true })
      .eq("facility_id", facility_id)
      .in("status", ["booked", "active"])
      .lt("start_at", end.toISOString())
      .gt("end_at", start.toISOString());

    if (capErr) return res.status(500).json({ error: pickErr(capErr) });
    if ((overlapCount || 0) > 0) {
      return res.status(400).json({ error: "ช่วงเวลานี้มีคนจองแล้ว" });
    }

    const payload = {
      facility_id,
      dorm_user_id: dormUserId,
      start_at: start.toISOString(),
      end_at: end.toISOString(),
      status: "booked",
      note: note ? String(note) : null,
      checkin_token: randomUUID().replace(/-/g, ""),
      end_token: randomUUID().replace(/-/g, ""),
    };

    const { data: created, error: insErr } = await supabaseAdmin
      .schema("public")
      .from("facility_bookings")
      .insert([payload])
      .select("*")
      .single();

    // ✅ ถ้าโดน constraint no_overlap ให้แปลงเป็นข้อความไทย
    if (insErr) {
      const msg = String(insErr.message || "");
      if (msg.includes("facility_bookings_no_overlap")) {
        return res.status(400).json({ error: "ช่วงเวลานี้มีคนจองแล้ว" });
      }
      return res.status(500).json({ error: pickErr(insErr) });
    }

    // push LINE
    try {
      const facName = fac?.name || "พื้นที่ส่วนกลาง";
      const text =
        `✅ จองสำเร็จแล้ว\n` +
        `สถานที่: ${facName}\n` +
        `เริ่ม: ${fmt(created.start_at)}\n` +
        `หมด: ${fmt(created.end_at)}\n` +
        `สถานะ: booked`;

      await pushLineByDormUserId(dormUserId, text);
    } catch (e) {
      console.error("LINE push booking error:", e);
    }

    return res.json({ ok: true, item: created });
  } catch (e) {
    return res.status(500).json({ error: pickErr(e) });
  }
});

/** ✅ ยืนยันเข้าใช้งาน */
app.post("/tenant/facility-bookings/:id/check-in", requireLineLogin, async (req, res) => {
  try {
    const id = req.params.id;
    const dormUserId = req.user.dorm_user_id;

    const { data: bk, error: bkErr } = await supabaseAdmin
      .schema("public")
      .from("facility_bookings")
      .select("id, dorm_user_id, facility_id, start_at, end_at, status, checked_in_at")
      .eq("id", id)
      .eq("dorm_user_id", dormUserId)
      .maybeSingle();

    if (bkErr) return res.status(500).json({ error: pickErr(bkErr) });
    if (!bk) return res.status(404).json({ error: "booking not found" });
    if (bk.checked_in_at) return res.json({ ok: true, item: bk, already: true });
    if (bk.status !== "booked") return res.status(400).json({ error: "สถานะไม่ถูกต้อง" });

    // ✅ เช็คเวลา: อนุโลมก่อน 10 นาที
    const now = new Date();
    const start = new Date(bk.start_at);
    const end = new Date(bk.end_at);

    const earlyMs = 10 * 60 * 1000;
    if (now.getTime() < start.getTime() - earlyMs) {
      return res.status(400).json({ error: "ยังไม่ถึงเวลาเข้าใช้งาน" });
    }
    if (now.getTime() > end.getTime()) {
      return res.status(400).json({ error: "เลยเวลาใช้งานแล้ว" });
    }

    const { data: updated, error: updErr } = await supabaseAdmin
      .schema("public")
      .from("facility_bookings")
      .update({ checked_in_at: now.toISOString(), status: "active" })
      .eq("id", id)
      .eq("dorm_user_id", dormUserId)
      .select("*")
      .single();

    if (updErr) return res.status(500).json({ error: pickErr(updErr) });

    try {
      await pushLineByDormUserId(
        dormUserId,
        `✅ ยืนยันเข้าใช้งานแล้ว\nเริ่ม: ${fmt(bk.start_at)}\nหมดเวลา: ${fmt(bk.end_at)}\nสถานะ: active`
      );
    } catch (e) {
      console.error("LINE push check-in error:", e);
    }

    return res.json({ ok: true, item: updated });
  } catch (e) {
    return res.status(500).json({ error: pickErr(e) });
  }
});

/** ✅ ยกเลิกการจอง (เฉพาะ booked + ยังไม่ check-in) */
app.post("/tenant/facility-bookings/:id/cancel", requireLineLogin, async (req, res) => {
  try {
    const id = req.params.id;
    const dormUserId = req.user.dorm_user_id;

    const { data: bk, error: bkErr } = await supabaseAdmin
      .schema("public")
      .from("facility_bookings")
      .select("id, dorm_user_id, status, checked_in_at, start_at, end_at")
      .eq("id", id)
      .eq("dorm_user_id", dormUserId)
      .maybeSingle();

    if (bkErr) return res.status(500).json({ error: pickErr(bkErr) });
    if (!bk) return res.status(404).json({ error: "booking not found" });

    if (bk.status !== "booked") return res.status(400).json({ error: "ยกเลิกได้เฉพาะรายการที่ยังเป็น booked" });
    if (bk.checked_in_at) return res.status(400).json({ error: "รายการนี้เข้าใช้งานแล้ว ยกเลิกไม่ได้" });

    const { data: updated, error: updErr } = await supabaseAdmin
      .schema("public")
      .from("facility_bookings")
      .update({ status: "cancelled" })
      .eq("id", id)
      .eq("dorm_user_id", dormUserId)
      .select("*")
      .single();

    if (updErr) return res.status(500).json({ error: pickErr(updErr) });

    try {
      await pushLineByDormUserId(
        dormUserId,
        `❌ ยกเลิกการจองแล้ว\nเริ่ม: ${fmt(bk.start_at)}\nหมด: ${fmt(bk.end_at)}\nสถานะ: cancelled`
      );
    } catch (e) {
      console.error("LINE push cancel error:", e);
    }

    return res.json({ ok: true, item: updated });
  } catch (e) {
    return res.status(500).json({ error: pickErr(e) });
  }
});

/** ✅ จบการใช้งาน */
app.post("/tenant/facility-bookings/:id/finish", requireLineLogin, async (req, res) => {
  try {
    const id = req.params.id;
    const dormUserId = req.user.dorm_user_id;

    const { data: bk, error: bkErr } = await supabaseAdmin
      .schema("public")
      .from("facility_bookings")
      .select("id, dorm_user_id, status, finished_at, start_at, end_at")
      .eq("id", id)
      .eq("dorm_user_id", dormUserId)
      .maybeSingle();

    if (bkErr) return res.status(500).json({ error: pickErr(bkErr) });
    if (!bk) return res.status(404).json({ error: "booking not found" });
    if (bk.finished_at) return res.json({ ok: true, item: bk, already: true });

    const now = new Date();

    const { data: updated, error: updErr } = await supabaseAdmin
      .schema("public")
      .from("facility_bookings")
      .update({ finished_at: now.toISOString(), status: "finished" })
      .eq("id", id)
      .eq("dorm_user_id", dormUserId)
      .select("*")
      .single();

    if (updErr) return res.status(500).json({ error: pickErr(updErr) });

    try {
      await pushLineByDormUserId(
        dormUserId,
        `✅ จบการใช้งานเรียบร้อย\nเริ่ม: ${fmt(bk.start_at)}\nหมด: ${fmt(bk.end_at)}\nสถานะ: finished`
      );
    } catch (e) {
      console.error("LINE push finish error:", e);
    }

    return res.json({ ok: true, item: updated });
  } catch (e) {
    return res.status(500).json({ error: pickErr(e) });
  }
});

/* =========================
   CRON: เตือนก่อนหมด 15 นาที + แจ้งหมดเวลา (ข้อความล้วน)
   ========================= */
cron.schedule("* * * * *", async () => {
  const now = new Date();
  const in15 = new Date(now.getTime() + 15 * 60 * 1000);

  // 1) remind ก่อนหมด 15 นาที
  {
    const { data: list, error } = await supabaseAdmin
      .schema("public")
      .from("facility_bookings")
      .select("id, dorm_user_id, end_at, status")
      .is("end_reminded_at", null)
      .lte("end_at", in15.toISOString())
      .gt("end_at", now.toISOString())
      .in("status", ["booked", "active"])
      .limit(50);

    if (!error) {
      for (const b of list || []) {
        try {
          await pushLineByDormUserId(
            b.dorm_user_id,
            `⏰ ใกล้หมดเวลาใช้งาน (อีก 15 นาที)\nหมดเวลา: ${fmt(b.end_at)}`
          );
        } catch (e) {
          console.error("LINE push remind error:", e);
        }

        await supabaseAdmin
          .schema("public")
          .from("facility_bookings")
          .update({ end_reminded_at: now.toISOString() })
          .eq("id", b.id);
      }
    }
  }

  // 2) ครบเวลาแล้ว แจ้งหมดเวลา
  {
    const { data: list, error } = await supabaseAdmin
      .schema("public")
      .from("facility_bookings")
      .select("id, dorm_user_id, end_at, status")
      .is("end_notified_at", null)
      .lte("end_at", now.toISOString())
      .in("status", ["booked", "active"])
      .limit(50);

    if (!error) {
      for (const b of list || []) {
        try {
          await pushLineByDormUserId(
            b.dorm_user_id,
            `⌛ หมดเวลาใช้งานแล้ว\nหมดเวลา: ${fmt(b.end_at)}`
          );
        } catch (e) {
          console.error("LINE push end notify error:", e);
        }

        await supabaseAdmin
          .schema("public")
          .from("facility_bookings")
          .update({ end_notified_at: now.toISOString() })
          .eq("id", b.id);
      }
    }
  }
});
/* =========================
   Facility Bookings (Admin/Owner)
   ========================= */

// helper: day boundary from date string (YYYY-MM-DD) in Bangkok -> UTC range
function bkkDayRangeUTC(dateYmd) {
  // dateYmd like "2026-02-18"
  const dayStartBkk = new Date(`${dateYmd}T00:00:00`);
  const startUtc = new Date(dayStartBkk.getTime() - 7 * 60 * 60 * 1000);
  const endUtc = new Date(startUtc.getTime() + 24 * 60 * 60 * 1000);
  return { startUtc, endUtc };
}

/** ✅ Owner: ดูรายการจองของ facility เดียว (ตามวัน) */
app.get("/admin/facility-bookings", requireAdmin, async (req, res) => {
  try {
    const facilityId = String(req.query.facility_id || "").trim();
    const date = String(req.query.date || "").trim(); // YYYY-MM-DD (วันไทย)

    if (!facilityId) return res.status(400).json({ error: "facility_id required" });

    let q = supabaseAdmin
      .schema("public")
      .from("facility_bookings")
      .select(
        `
        id, facility_id, dorm_user_id,
        start_at, end_at,
        status, note,
        checked_in_at, finished_at,
        created_at,
        dorm_users ( full_name, room, phone, line_user_id )
      `
      )
      .eq("facility_id", facilityId)
      .order("start_at", { ascending: true });

    if (date) {
      const { startUtc, endUtc } = bkkDayRangeUTC(date);
      q = q.gte("start_at", startUtc.toISOString()).lt("start_at", endUtc.toISOString());
    }

    const { data, error } = await q;
    if (error) return res.status(500).json({ error: pickErr(error) });

    const items = (data || []).map((b) => ({
      id: b.id,
      facility_id: b.facility_id,
      dorm_user_id: b.dorm_user_id,
      start_at: b.start_at,
      end_at: b.end_at,
      status: b.status,
      note: b.note,
      checked_in_at: b.checked_in_at,
      finished_at: b.finished_at,
      created_at: b.created_at,
      tenant: {
        full_name: b.dorm_users?.full_name || "-",
        room: b.dorm_users?.room || null,
        phone: b.dorm_users?.phone || null,
        line_user_id: b.dorm_users?.line_user_id || null,
      },
    }));

    return res.json({ ok: true, items });
  } catch (e) {
    return res.status(500).json({ error: pickErr(e) });
  }
});

/** ✅ Owner: ดูรายการจองทั้งวัน (ทุก facility) */
app.get("/admin/facility-bookings/day", requireAdmin, async (req, res) => {
  try {
    const date = String(req.query.date || "").trim(); // YYYY-MM-DD
    if (!date) return res.status(400).json({ error: "date required" });

    const { startUtc, endUtc } = bkkDayRangeUTC(date);

    const { data, error } = await supabaseAdmin
      .schema("public")
      .from("facility_bookings")
      .select(
        `
        id, facility_id, dorm_user_id,
        start_at, end_at,
        status, note,
        checked_in_at, finished_at,
        created_at,
        facilities ( id, name ),
        dorm_users ( full_name, room, phone )
      `
      )
      .gte("start_at", startUtc.toISOString())
      .lt("start_at", endUtc.toISOString())
      .order("start_at", { ascending: true });

    if (error) return res.status(500).json({ error: pickErr(error) });

    const items = (data || []).map((b) => ({
      id: b.id,
      facility_id: b.facility_id,
      facility_name: b.facilities?.name || b.facility_id,
      dorm_user_id: b.dorm_user_id,
      start_at: b.start_at,
      end_at: b.end_at,
      status: b.status,
      note: b.note,
      checked_in_at: b.checked_in_at,
      finished_at: b.finished_at,
      created_at: b.created_at,
      tenant: {
        full_name: b.dorm_users?.full_name || "-",
        room: b.dorm_users?.room || null,
        phone: b.dorm_users?.phone || null,
      },
    }));

    return res.json({ ok: true, date, items });
  } catch (e) {
    return res.status(500).json({ error: pickErr(e) });
  }
});

/** ✅ Owner: บังคับ check-in (ทำให้ booked -> active) */
app.post("/admin/facility-bookings/:id/check-in", requireAdmin, async (req, res) => {
  try {
    const id = String(req.params.id);
    const now = new Date().toISOString();

    const { data: bk, error: fErr } = await supabaseAdmin
      .schema("public")
      .from("facility_bookings")
      .select("id, status, checked_in_at, finished_at")
      .eq("id", id)
      .maybeSingle();

    if (fErr) return res.status(500).json({ error: pickErr(fErr) });
    if (!bk) return res.status(404).json({ error: "booking not found" });
    if (bk.finished_at) return res.status(400).json({ error: "รายการนี้จบการใช้งานแล้ว" });
    if (bk.checked_in_at) return res.json({ ok: true, item: bk, already: true });

    // ยอมให้ check-in ได้จาก booked เท่านั้น
    if (String(bk.status) !== "booked") {
      return res.status(400).json({ error: "สถานะไม่ถูกต้อง (ต้องเป็น booked)" });
    }

    const { data: updated, error: uErr } = await supabaseAdmin
      .schema("public")
      .from("facility_bookings")
      .update({ checked_in_at: now, status: "active" })
      .eq("id", id)
      .select("*")
      .single();

    if (uErr) return res.status(500).json({ error: pickErr(uErr) });
    return res.json({ ok: true, item: updated });
  } catch (e) {
    return res.status(500).json({ error: pickErr(e) });
  }
});

/** ✅ Owner: จบการใช้งาน (active/booked -> finished) */
app.post("/admin/facility-bookings/:id/finish", requireAdmin, async (req, res) => {
  try {
    const id = String(req.params.id);
    const now = new Date().toISOString();

    const { data: bk, error: fErr } = await supabaseAdmin
      .schema("public")
      .from("facility_bookings")
      .select("id, status, finished_at")
      .eq("id", id)
      .maybeSingle();

    if (fErr) return res.status(500).json({ error: pickErr(fErr) });
    if (!bk) return res.status(404).json({ error: "booking not found" });
    if (bk.finished_at) return res.json({ ok: true, item: bk, already: true });

    // ยอมให้ finish จาก booked/active
    if (!["booked", "active"].includes(String(bk.status))) {
      return res.status(400).json({ error: "สถานะไม่ถูกต้อง (ต้องเป็น booked หรือ active)" });
    }

    const { data: updated, error: uErr } = await supabaseAdmin
      .schema("public")
      .from("facility_bookings")
      .update({ finished_at: now, status: "finished" })
      .eq("id", id)
      .select("*")
      .single();

    if (uErr) return res.status(500).json({ error: pickErr(uErr) });
    return res.json({ ok: true, item: updated });
  } catch (e) {
    return res.status(500).json({ error: pickErr(e) });
  }
});

/** ✅ Owner: ยกเลิกการจอง (เฉพาะ booked) */
app.post("/admin/facility-bookings/:id/cancel", requireAdmin, async (req, res) => {
  try {
    const id = String(req.params.id);

    const { data: bk, error: fErr } = await supabaseAdmin
      .schema("public")
      .from("facility_bookings")
      .select("id, status, checked_in_at, finished_at")
      .eq("id", id)
      .maybeSingle();

    if (fErr) return res.status(500).json({ error: pickErr(fErr) });
    if (!bk) return res.status(404).json({ error: "booking not found" });
    if (bk.finished_at) return res.status(400).json({ error: "รายการนี้จบการใช้งานแล้ว" });

    // owner cancel: จำกัดให้ยกเลิกเฉพาะ booked และยังไม่ check-in
    if (String(bk.status) !== "booked") return res.status(400).json({ error: "ยกเลิกได้เฉพาะ booked" });
    if (bk.checked_in_at) return res.status(400).json({ error: "รายการนี้เข้าใช้งานแล้ว ยกเลิกไม่ได้" });

    const { data: updated, error: uErr } = await supabaseAdmin
      .schema("public")
      .from("facility_bookings")
      .update({ status: "cancelled" })
      .eq("id", id)
      .select("*")
      .single();

    if (uErr) return res.status(500).json({ error: pickErr(uErr) });
    return res.json({ ok: true, item: updated });
  } catch (e) {
    return res.status(500).json({ error: pickErr(e) });
  }
});

/* =========================
   Dashboard Series 12 เดือน
   ========================= */

// GET /api/v1/condos/:id/dashboard/series12 — กราฟรายได้ 12 เดือนย้อนหลัง
app.get("/api/v1/condos/:id/dashboard/series12", authRequired, async (req, res) => {
  try {
    const ownerId = req.ownerId;
    const condoId = req.params.id;

    const own = await assertOwnsCondo(ownerId, condoId);
    if (!own.ok) return res.status(own.status).json({ error: own.error });

    // ช่วงเวลา 12 เดือนย้อนหลัง (Bangkok timezone)
    const now = new Date();
    const months = [];
    for (let i = 11; i >= 0; i--) {
      const d = new Date(now.getFullYear(), now.getMonth() - i, 1);
      const year = d.getFullYear();
      const month = d.getMonth() + 1;
      const startISO = new Date(`${year}-${String(month).padStart(2, "0")}-01T00:00:00+07:00`).toISOString();
      const nextD = new Date(year, month, 1);
      const endISO = new Date(`${nextD.getFullYear()}-${String(nextD.getMonth() + 1).padStart(2, "0")}-01T00:00:00+07:00`).toISOString();
      months.push({ label: `${year}-${String(month).padStart(2, "0")}`, startISO, endISO });
    }

    const series = [];
    for (const m of months) {
      // นับยอดชำระจาก invoices ที่ paid_at อยู่ในเดือนนั้น
      const { data: invoices, error } = await supabaseAdmin
        .schema("public")
        .from("invoices")
        .select("total_amount")
        .eq("condo_id", condoId)
        .eq("status", "PAID")
        .gte("paid_at", m.startISO)
        .lt("paid_at", m.endISO);

      if (error) return res.status(500).json({ error: error.message });

      const revenue = (invoices || []).reduce((sum, inv) => sum + Number(inv.total_amount || 0), 0);
      series.push({ month: m.label, revenue });
    }

    return res.json({ ok: true, series });
  } catch (e) {
    return res.status(500).json({ error: e?.message || "server_error" });
  }
});

/* =========================
   Billing Reports
   ========================= */

// GET /api/v1/condos/:id/billing-reports — รายงานบิลทั้งหมด (ReportsPage)
app.get("/api/v1/condos/:id/billing-reports", authRequired, async (req, res) => {
  try {
    const ownerId = req.ownerId;
    const condoId = req.params.id;

    const own = await assertOwnsCondo(ownerId, condoId);
    if (!own.ok) return res.status(own.status).json({ error: own.error });

    const status = req.query.status || null;  // UNPAID | PAID | OVERDUE
    const month = req.query.month || null;  // YYYY-MM
    const page = Math.max(1, Number(req.query.page || 1));
    const limit = Math.min(100, Number(req.query.limit || 20));
    const offset = (page - 1) * limit;

    let query = supabaseAdmin
      .schema("public")
      .from("invoices")
      .select(
        "id, room_id, condo_id, status, total_amount, due_date, paid_at, created_at, rooms(room_no, floor)",
        { count: "exact" }
      )
      .eq("condo_id", condoId)
      .order("created_at", { ascending: false })
      .range(offset, offset + limit - 1);

    if (status) query = query.eq("status", status.toUpperCase());
    if (month) {
      const startISO = new Date(`${month}-01T00:00:00+07:00`).toISOString();
      const [y, m2] = month.split("-").map(Number);
      const next = new Date(y, m2, 1);
      const endISO = new Date(`${next.getFullYear()}-${String(next.getMonth() + 1).padStart(2, "0")}-01T00:00:00+07:00`).toISOString();
      query = query.gte("created_at", startISO).lt("created_at", endISO);
    }

    const { data, error, count } = await query;
    if (error) return res.status(500).json({ error: error.message });

    return res.json({
      ok: true,
      total: count || 0,
      page,
      limit,
      reports: (data || []).map(inv => ({
        id: inv.id,
        roomId: inv.room_id,
        roomNo: inv.rooms?.room_no,
        floor: inv.rooms?.floor,
        status: inv.status,
        totalAmount: inv.total_amount,
        dueDate: inv.due_date,
        paidAt: inv.paid_at,
        createdAt: inv.created_at,
      })),
    });
  } catch (e) {
    return res.status(500).json({ error: e?.message || "server_error" });
  }
});


// ===== Room Contracts สัญญา =====

// POST /api/v1/condos/:condoId/contracts — บันทึกสัญญาใหม่
app.post("/api/v1/condos/:condoId/contracts", authRequired, async (req, res) => {
  try {
    const ownerId = req.ownerId;
    const condoId = req.params.condoId;
    const own = await assertOwnsCondo(ownerId, condoId);
    if (!own.ok) return res.status(own.status).json({ error: own.error });

    const b = req.body || {};
    const roomId = String(b.roomId || "").trim();
    if (!roomId) return res.status(400).json({ error: "roomId_required" });

    const { data, error } = await supabaseAdmin
      .from("room_contracts")
      .insert([{
        condo_id: condoId,
        room_id: roomId,
        tenant_first_name: b.tenantFirstName || null,
        tenant_last_name: b.tenantLastName || null,
        tenant_phone: b.tenantPhone || null,
        tenant_citizen_id: b.tenantCitizenId || null,
        tenant_address: b.tenantAddress || null,
        check_in: b.checkIn || null,
        check_out: b.checkOut || null,
        monthly_rent: Number(b.monthlyRent || 0),
        deposit: Number(b.deposit || 0),
        deposit_pay_by: b.depositPayBy || null,
        booking_fee: Number(b.bookingFee || 0),
        booking_no: b.bookingNo || null,
        emergency_name: b.emergencyName || null,
        emergency_relation: b.emergencyRelation || null,
        emergency_phone: b.emergencyPhone || null,
        note: b.note || null,
        status: "ACTIVE",
      }])
      .select("*")
      .single();

    if (error) return res.status(500).json({ error: error.message });
    return res.status(201).json({ ok: true, contract: data });
  } catch (e) {
    return res.status(500).json({ error: e?.message || "server_error" });
  }
});

// GET /api/v1/condos/:condoId/contracts?roomId=xxx — ดึงสัญญา ACTIVE ของห้อง
app.get("/api/v1/condos/:condoId/contracts", authRequired, async (req, res) => {
  try {
    const ownerId = req.ownerId;
    const condoId = req.params.condoId;
    const own = await assertOwnsCondo(ownerId, condoId);
    if (!own.ok) return res.status(own.status).json({ error: own.error });

    const roomId = req.query.roomId || null;
    let q = supabaseAdmin
      .from("room_contracts")
      .select("*")
      .eq("condo_id", condoId)
      .eq("status", "ACTIVE")
      .order("created_at", { ascending: false });

    if (roomId) q = q.eq("room_id", roomId);

    const { data, error } = await q;
    if (error) return res.status(500).json({ error: error.message });

    return res.json({
      ok: true,
      contract: (data && data[0]) || null,
      contracts: data || [],
    });
  } catch (e) {
    return res.status(500).json({ error: e?.message || "server_error" });
  }
});


/* =========================
   Meters (มิเตอร์น้ำ/ไฟ)
   ========================= */

// GET /api/v1/condos/:id/meters — ดึงข้อมูลมิเตอร์ล่าสุดของทุกห้อง
app.get("/api/v1/condos/:id/meters", authRequired, async (req, res) => {
  try {
    const ownerId = req.ownerId;
    const condoId = req.params.id;

    const own = await assertOwnsCondo(ownerId, condoId);
    if (!own.ok) return res.status(own.status).json({ error: own.error });

    const type = req.query.type || null; // water | electricity
    const roomId = req.query.roomId || null;
    const month = req.query.month || null; // YYYY-MM

    let query = supabaseAdmin
      .schema("public")
      .from("meter_readings")
      .select("id, room_id, condo_id, type, previous_reading, current_reading, units_used, recorded_at, rooms(room_no, floor)")
      .eq("condo_id", condoId)
      .order("recorded_at", { ascending: false });

    if (type) query = query.eq("type", type.toLowerCase());
    if (roomId) query = query.eq("room_id", roomId);
    if (month) {
      const startISO = new Date(`${month}-01T00:00:00+07:00`).toISOString();
      const [y, m2] = month.split("-").map(Number);
      const next = new Date(y, m2, 1);
      const endISO = new Date(`${next.getFullYear()}-${String(next.getMonth() + 1).padStart(2, "0")}-01T00:00:00+07:00`).toISOString();
      query = query.gte("recorded_at", startISO).lt("recorded_at", endISO);
    }

    const { data, error } = await query;
    if (error) return res.status(500).json({ error: error.message });

    return res.json({
      ok: true,
      meters: (data || []).map(m => ({
        id: m.id,
        roomId: m.room_id,
        roomNo: m.rooms?.room_no,
        floor: m.rooms?.floor,
        type: m.type,
        previousReading: m.previous_reading,
        currentReading: m.current_reading,
        unitsUsed: m.units_used,
        recordedAt: m.recorded_at,
      })),
    });
  } catch (e) {
    return res.status(500).json({ error: e?.message || "server_error" });
  }
});

// POST /api/v1/condos/:id/meters — บันทึกมิเตอร์ใหม่
app.post("/api/v1/condos/:id/meters", authRequired, async (req, res) => {
  try {
    const ownerId = req.ownerId;
    const condoId = req.params.id;

    const own = await assertOwnsCondo(ownerId, condoId);
    if (!own.ok) return res.status(own.status).json({ error: own.error });

    const room_id = String(req.body?.roomId || "").trim();
    const type = String(req.body?.type || "").toLowerCase(); // water | electricity
    const previous_reading = Number(req.body?.previousReading ?? 0);
    const current_reading = Number(req.body?.currentReading ?? 0);
    const recorded_at = req.body?.recordedAt || new Date().toISOString();

    if (!room_id) return res.status(400).json({ error: "roomId_required" });
    if (!["water", "electricity"].includes(type)) return res.status(400).json({ error: "type_must_be_water_or_electricity" });
    if (current_reading < previous_reading) return res.status(400).json({ error: "current_reading_must_be_gte_previous" });

    const units_used = current_reading - previous_reading;

    const { data, error } = await supabaseAdmin
      .schema("public")
      .from("meter_readings")
      .insert([{ condo_id: condoId, room_id, type, previous_reading, current_reading, units_used, recorded_at }])
      .select("*")
      .single();

    if (error) return res.status(500).json({ error: error.message });

    return res.status(201).json({ ok: true, meter: data });
  } catch (e) {
    return res.status(500).json({ error: e?.message || "server_error" });
  }
});

/* =========================
   Invoices (หน้าแจ้งชำระ + หน้ารายงาน)
   ========================= */

// GET /api/v1/condos/:id/invoices — ดึงบิลทั้งหมด (หน้าแจ้งชำระ + หน้ารายงาน)
// query: ?status=UNPAID|PAID|OVERDUE&month=YYYY-MM&roomId=xxx&page=1&limit=20
app.get("/api/v1/condos/:id/invoices", authRequired, async (req, res) => {
  try {
    const ownerId = req.ownerId;
    const condoId = req.params.id;

    const own = await assertOwnsCondo(ownerId, condoId);
    if (!own.ok) return res.status(own.status).json({ error: own.error });

    const status = req.query.status || null;
    const month = req.query.month || null; // YYYY-MM
    const roomId = req.query.roomId || null;
    const page = Math.max(1, Number(req.query.page || 1));
    const limit = Math.min(100, Number(req.query.limit || 20));
    const offset = (page - 1) * limit;

    let query = supabaseAdmin
      .schema("public")
      .from("invoices")
      .select(
        "id, room_id, condo_id, status, total_amount, due_date, paid_at, note, created_at, updated_at, rooms(room_no, floor)",
        { count: "exact" }
      )
      .eq("condo_id", condoId)
      .order("created_at", { ascending: false })
      .range(offset, offset + limit - 1);

    if (status) query = query.eq("status", status.toUpperCase());
    if (roomId) query = query.eq("room_id", roomId);
    if (month) {
      const startISO = new Date(`${month}-01T00:00:00+07:00`).toISOString();
      const [y, m2] = month.split("-").map(Number);
      const next = new Date(y, m2, 1);
      const endISO = new Date(`${next.getFullYear()}-${String(next.getMonth() + 1).padStart(2, "0")}-01T00:00:00+07:00`).toISOString();
      query = query.gte("created_at", startISO).lt("created_at", endISO);
    }

    const { data, error, count } = await query;
    if (error) return res.status(500).json({ error: error.message });

    return res.json({
      ok: true,
      total: count || 0,
      page,
      limit,
      invoices: (data || []).map(inv => ({
        id: inv.id,
        roomId: inv.room_id,
        roomNo: inv.rooms?.room_no,
        floor: inv.rooms?.floor,
        status: inv.status,
        totalAmount: inv.total_amount,
        dueDate: inv.due_date,
        paidAt: inv.paid_at,
        note: inv.note,
        createdAt: inv.created_at,
        updatedAt: inv.updated_at,
      })),
    });
  } catch (e) {
    return res.status(500).json({ error: e?.message || "server_error" });
  }
});

// GET /api/v1/condos/:id/invoices/:invoiceId — ดูรายละเอียดบิลเดียว
app.get("/api/v1/condos/:id/invoices/:invoiceId", authRequired, async (req, res) => {
  try {
    const ownerId = req.ownerId;
    const condoId = req.params.id;
    const invoiceId = req.params.invoiceId;

    const own = await assertOwnsCondo(ownerId, condoId);
    if (!own.ok) return res.status(own.status).json({ error: own.error });

    const { data, error } = await supabaseAdmin
      .schema("public")
      .from("invoices")
      .select("*, rooms(room_no, floor)")
      .eq("id", invoiceId)
      .eq("condo_id", condoId)
      .maybeSingle();

    if (error) return res.status(500).json({ error: error.message });
    if (!data) return res.status(404).json({ error: "invoice_not_found" });

    return res.json({
      ok: true, invoice: {
        id: data.id,
        roomId: data.room_id,
        roomNo: data.rooms?.room_no,
        floor: data.rooms?.floor,
        status: data.status,
        totalAmount: data.total_amount,
        dueDate: data.due_date,
        paidAt: data.paid_at,
        note: data.note,
        createdAt: data.created_at,
        updatedAt: data.updated_at,
      }
    });
  } catch (e) {
    return res.status(500).json({ error: e?.message || "server_error" });
  }
});

// POST /api/v1/condos/:id/invoices — สร้างบิลใหม่ (หน้าแจ้งชำระ)
// body: { roomId, totalAmount, dueDate, note? }
app.post("/api/v1/condos/:id/invoices", authRequired, async (req, res) => {
  try {
    const ownerId = req.ownerId;
    const condoId = req.params.id;

    const own = await assertOwnsCondo(ownerId, condoId);
    if (!own.ok) return res.status(own.status).json({ error: own.error });

    const room_id = String(req.body?.roomId || "").trim();
    const total_amount = Number(req.body?.totalAmount ?? 0);
    const due_date = req.body?.dueDate || null; // YYYY-MM-DD
    const note = req.body?.note || null;

    if (!room_id) return res.status(400).json({ error: "roomId_required" });
    if (total_amount <= 0) return res.status(400).json({ error: "totalAmount_must_be_positive" });

    // ตรวจว่าห้องอยู่ในคอนโดนี้จริง
    const { data: room } = await supabaseAdmin
      .schema("public").from("rooms")
      .select("id").eq("id", room_id).eq("condo_id", condoId).maybeSingle();
    if (!room) return res.status(404).json({ error: "room_not_found_in_condo" });

    const { data, error } = await supabaseAdmin
      .schema("public")
      .from("invoices")
      .insert([{ condo_id: condoId, room_id, total_amount, due_date, note, status: "UNPAID" }])
      .select("*, rooms(room_no, floor)")
      .single();

    if (error) return res.status(500).json({ error: error.message });

    return res.status(201).json({
      ok: true, invoice: {
        id: data.id,
        roomId: data.room_id,
        roomNo: data.rooms?.room_no,
        floor: data.rooms?.floor,
        status: data.status,
        totalAmount: data.total_amount,
        dueDate: data.due_date,
        note: data.note,
        createdAt: data.created_at,
      }
    });
  } catch (e) {
    return res.status(500).json({ error: e?.message || "server_error" });
  }
});

// PATCH /api/v1/condos/:id/invoices/:invoiceId/pay — บันทึกการชำระ (หน้าแจ้งชำระ)
app.patch("/api/v1/condos/:id/invoices/:invoiceId/pay", authRequired, async (req, res) => {
  try {
    const ownerId = req.ownerId;
    const condoId = req.params.id;
    const invoiceId = req.params.invoiceId;

    const own = await assertOwnsCondo(ownerId, condoId);
    if (!own.ok) return res.status(own.status).json({ error: own.error });

    const paid_at = req.body?.paidAt || new Date().toISOString();
    const note = req.body?.note || null;

    const { data: existing } = await supabaseAdmin
      .schema("public").from("invoices")
      .select("id, status").eq("id", invoiceId).eq("condo_id", condoId).maybeSingle();

    if (!existing) return res.status(404).json({ error: "invoice_not_found" });
    if (existing.status === "PAID") return res.json({ ok: true, already_paid: true });
    if (existing.status === "CANCELLED") return res.status(400).json({ error: "invoice_cancelled" });

    const updates = { status: "PAID", paid_at, updated_at: new Date().toISOString() };
    if (note) updates.note = note;

    const { data, error } = await supabaseAdmin
      .schema("public").from("invoices")
      .update(updates)
      .eq("id", invoiceId).eq("condo_id", condoId)
      .select("id, status, paid_at, total_amount, updated_at")
      .single();

    if (error) return res.status(500).json({ error: error.message });

    return res.json({ ok: true, invoice: data });
  } catch (e) {
    return res.status(500).json({ error: e?.message || "server_error" });
  }
});

// PATCH /api/v1/condos/:id/invoices/:invoiceId/overdue — ทำเครื่องหมายค้างชำระ
app.patch("/api/v1/condos/:id/invoices/:invoiceId/overdue", authRequired, async (req, res) => {
  try {
    const ownerId = req.ownerId;
    const condoId = req.params.id;
    const invoiceId = req.params.invoiceId;

    const own = await assertOwnsCondo(ownerId, condoId);
    if (!own.ok) return res.status(own.status).json({ error: own.error });

    const { data: existing } = await supabaseAdmin
      .schema("public").from("invoices")
      .select("id, status").eq("id", invoiceId).eq("condo_id", condoId).maybeSingle();

    if (!existing) return res.status(404).json({ error: "invoice_not_found" });
    if (existing.status === "PAID") return res.status(400).json({ error: "already_paid" });
    if (existing.status === "CANCELLED") return res.status(400).json({ error: "invoice_cancelled" });

    const { data, error } = await supabaseAdmin
      .schema("public").from("invoices")
      .update({ status: "OVERDUE", updated_at: new Date().toISOString() })
      .eq("id", invoiceId).eq("condo_id", condoId)
      .select("id, status, updated_at")
      .single();

    if (error) return res.status(500).json({ error: error.message });
    return res.json({ ok: true, invoice: data });
  } catch (e) {
    return res.status(500).json({ error: e?.message || "server_error" });
  }
});

// DELETE /api/v1/condos/:id/invoices/:invoiceId — ยกเลิกบิล
app.delete("/api/v1/condos/:id/invoices/:invoiceId", authRequired, async (req, res) => {
  try {
    const ownerId = req.ownerId;
    const condoId = req.params.id;
    const invoiceId = req.params.invoiceId;

    const own = await assertOwnsCondo(ownerId, condoId);
    if (!own.ok) return res.status(own.status).json({ error: own.error });

    const { data: existing } = await supabaseAdmin
      .schema("public").from("invoices")
      .select("id, status").eq("id", invoiceId).eq("condo_id", condoId).maybeSingle();

    if (!existing) return res.status(404).json({ error: "invoice_not_found" });
    if (existing.status === "PAID") return res.status(400).json({ error: "cannot_cancel_paid_invoice" });

    const { error } = await supabaseAdmin
      .schema("public").from("invoices")
      .update({ status: "CANCELLED", updated_at: new Date().toISOString() })
      .eq("id", invoiceId).eq("condo_id", condoId);

    if (error) return res.status(500).json({ error: error.message });
    return res.json({ ok: true });
  } catch (e) {
    return res.status(500).json({ error: e?.message || "server_error" });
  }
});

/* =========================
   Invoice LINE Notification
   ========================= */

// POST /api/v1/condos/:id/invoices/:invoiceId/notify
// — ส่งใบแจ้งหนี้ผ่าน LINE ให้ผู้เช่าของห้องนั้น
app.post("/api/v1/condos/:id/invoices/:invoiceId/notify", authRequired, async (req, res) => {
  try {
    const ownerId = req.ownerId;
    const condoId = req.params.id;
    const invoiceId = req.params.invoiceId;

    const own = await assertOwnsCondo(ownerId, condoId);
    if (!own.ok) return res.status(own.status).json({ error: own.error });

    // 1. ดึง invoice
    const { data: invoice, error: invErr } = await supabaseAdmin
      .schema("public")
      .from("invoices")
      .select("id, room_id, total_amount, due_date, status, note, created_at, rooms(room_no, floor)")
      .eq("id", invoiceId)
      .eq("condo_id", condoId)
      .maybeSingle();

    if (invErr) return res.status(500).json({ error: invErr.message });
    if (!invoice) return res.status(404).json({ error: "invoice_not_found" });

    const roomNo = invoice.rooms?.room_no || "—";

    // 2. ดึงข้อมูลคอนโด
    const { data: condo } = await supabaseAdmin
      .schema("public")
      .from("condos")
      .select("name_th")
      .eq("id", condoId)
      .maybeSingle();

    const condoName = condo?.name_th || "RentSphere";

    // 2.5 ดึงบัญชีธนาคาร
    const { data: bankAccounts } = await supabaseAdmin
      .schema("public")
      .from("condo_bank_accounts")
      .select("bank, account_name, account_no")
      .eq("condo_id", condoId)
      .order("created_at", { ascending: true });

    // 3. หาผู้เช่าจาก dorm_users ที่ room ตรงกับ room_no + condo_id
    const { data: tenants, error: tErr } = await supabaseAdmin
      .schema("public")
      .from("dorm_users")
      .select("id, full_name, room, line_user_id, condo_id")
      .eq("room", roomNo)
      .eq("condo_id", condoId)
      .not("line_user_id", "is", null);

    if (tErr) return res.status(500).json({ error: tErr.message });

    if (!tenants || tenants.length === 0) {
      return res.status(404).json({ error: "no_tenant_with_line_found", roomNo });
    }

    // 4. สร้างข้อความ
    const amount = Number(invoice.total_amount || 0).toLocaleString("th-TH", { minimumFractionDigits: 2 });
    const dueDate = invoice.due_date
      ? new Date(invoice.due_date).toLocaleDateString("th-TH", { timeZone: "Asia/Bangkok", day: "numeric", month: "long", year: "numeric" })
      : "ไม่ระบุ";
    const statusText = invoice.status === "PAID" ? "✅ ชำระแล้ว" : "⏳ รอชำระ";

    // สร้างข้อมูลบัญชีธนาคาร
    let bankSection = "";
    if (bankAccounts && bankAccounts.length > 0) {
      bankSection = `\n💳 ช่องทางชำระเงิน:\n`;
      for (const acc of bankAccounts) {
        bankSection += `🏦 ${acc.bank}\n   ชื่อ: ${acc.account_name}\n   เลขบัญชี: ${acc.account_no}\n`;
      }
      bankSection += `━━━━━━━━━━━━━━━\n`;
    }

    const text =
      `🏢 ${condoName}\n` +
      `📋 ใบแจ้งหนี้ประจำเดือน\n` +
      `━━━━━━━━━━━━━━━\n` +
      `🚪 ห้อง: ${roomNo}\n` +
      `💰 ยอดชำระ: ฿${amount}\n` +
      `📅 กำหนดชำระ: ${dueDate}\n` +
      `📌 สถานะ: ${statusText}\n` +
      `━━━━━━━━━━━━━━━\n` +
      (invoice.note ? `📝 หมายเหตุ: ${invoice.note}\n` : "") +
      bankSection +
      `\n📸 โอนแล้วส่งรูป slip มาที่นี่\nระบบจะตรวจอัตโนมัติค่ะ ✅\n` +
      `\nขอบคุณครับ/ค่ะ 🙏`;

    // 5. ส่ง LINE ให้ทุก tenant ที่อยู่ห้องนี้
    const results = [];
    for (const t of tenants) {
      try {
        await pushLineMessage(t.line_user_id, text);
        results.push({ tenantName: t.full_name, lineUserId: t.line_user_id, status: "sent" });

        // บันทึก log (ถ้ามีตาราง)
        try {
          await supabaseAdmin.from("invoice_notifications").insert([{
            invoice_id: invoiceId,
            condo_id: condoId,
            room_id: invoice.room_id,
            line_user_id: t.line_user_id,
            tenant_name: t.full_name,
            channel: "LINE",
            status: "sent",
            message: text,
          }]);
        } catch { /* ถ้าไม่มีตาราง ก็ข้ามไป */ }

      } catch (e) {
        console.error(`LINE push invoice error for ${t.line_user_id}:`, e);
        results.push({ tenantName: t.full_name, lineUserId: t.line_user_id, status: "failed", error: e.message });
      }
    }

    return res.json({ ok: true, sent: results.length, results });
  } catch (e) {
    return res.status(500).json({ error: e?.message || "server_error" });
  }
});

/* =========================
   SlipOK — ตรวจ slip ผ่าน LINE Webhook
   ========================= */

const SLIPOK_BRANCH_ID = process.env.SLIPOK_BRANCH_ID || "";
const SLIPOK_API_KEY = process.env.SLIPOK_API_KEY || "";
const LINE_CHANNEL_TOKEN = process.env.LINE_MESSAGING_ACCESS_TOKEN || "";

// ✅ ดาวน์โหลดรูปจาก LINE
async function downloadLineImage(messageId) {
  const res = await fetchFn(
    `https://api-data.line.me/v2/bot/message/${messageId}/content`,
    { headers: { Authorization: `Bearer ${LINE_CHANNEL_TOKEN}` } }
  );
  if (!res.ok) throw new Error(`LINE download failed: ${res.status}`);
  return Buffer.from(await res.arrayBuffer());
}

// ✅ ตรวจ slip ด้วย SlipOK API
async function verifySlipWithSlipOK(imageBuffer) {
  // SlipOK ใช้ multipart/form-data -> ส่ง file ผ่าน Blob
  const formData = new FormData();
  const blob = new Blob([imageBuffer], { type: "image/jpeg" });
  formData.append("files", blob, "slip.jpg");
  formData.append("log", "true");

  const res = await fetchFn(
    `https://api.slipok.com/api/line/apikey/${SLIPOK_BRANCH_ID}`,
    {
      method: "POST",
      headers: { "x-authorization": SLIPOK_API_KEY },
      body: formData,
    }
  );

  const json = await res.json();
  return json;
}

// ✅ ตอบกลับ LINE ด้วย replyToken
async function replyLineMessage(replyToken, text) {
  await fetchFn("https://api.line.me/v2/bot/message/reply", {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      Authorization: `Bearer ${LINE_CHANNEL_TOKEN}`,
    },
    body: JSON.stringify({
      replyToken,
      messages: [{ type: "text", text }],
    }),
  });
}

// ✅ หา invoice ค้างชำระจาก lineUserId
async function findPendingInvoiceByLineUser(lineUserId) {
  // 1. หา dorm_user จาก line_user_id
  const { data: dormUser } = await supabaseAdmin
    .from("dorm_users")
    .select("id, room, condo_id, full_name")
    .eq("line_user_id", String(lineUserId))
    .maybeSingle();

  if (!dormUser || !dormUser.room || !dormUser.condo_id) return null;

  // 2. หา room_id จาก room_no + condo_id
  const { data: room } = await supabaseAdmin
    .from("rooms")
    .select("id, room_no")
    .eq("room_no", dormUser.room)
    .eq("condo_id", dormUser.condo_id)
    .maybeSingle();

  if (!room) return null;

  // 3. หา invoice ล่าสุดที่ยังไม่จ่าย
  const { data: invoice } = await supabaseAdmin
    .from("invoices")
    .select("id, total_amount, status, condo_id, room_id, created_at")
    .eq("room_id", room.id)
    .eq("condo_id", dormUser.condo_id)
    .in("status", ["UNPAID", "OVERDUE"])
    .order("created_at", { ascending: false })
    .limit(1)
    .maybeSingle();

  if (!invoice) return null;

  return {
    invoiceId: invoice.id,
    condoId: invoice.condo_id,
    roomId: invoice.room_id,
    roomNo: room.room_no,
    totalAmount: Number(invoice.total_amount || 0),
    tenantName: dormUser.full_name || "ผู้เช่า",
  };
}

// ✅ LINE Webhook — รับ slip จากผู้เช่าผ่าน LINE
app.post("/webhook/line", async (req, res) => {
  // ตอบ LINE ทันที (ถ้าไม่ตอบภายใน 1 วิ LINE จะ retry)
  res.status(200).json({ ok: true });

  const events = req.body?.events || [];

  for (const event of events) {
    // ข้าม event ที่ไม่ใช่ message
    if (event.type !== "message") continue;

    const replyToken = event.replyToken;
    const lineUserId = event.source?.userId;

    // ถ้าไม่ใช่รูป → บอกให้ส่งรูป
    if (event.message?.type !== "image") {
      try {
        await replyLineMessage(replyToken, "📸 กรุณาส่งรูป slip โอนเงินเพื่อตรวจสอบค่ะ");
      } catch (e) {
        console.error("[SLIP] reply non-image error:", e.message);
      }
      continue;
    }

    try {
      console.log("[SLIP] Processing slip from:", lineUserId);

      // 1. ดาวน์โหลดรูป slip จาก LINE
      const imageBuffer = await downloadLineImage(event.message.id);
      console.log("[SLIP] Downloaded image:", imageBuffer.length, "bytes");

      // 2. ส่งให้ SlipOK ตรวจ
      const slipResult = await verifySlipWithSlipOK(imageBuffer);
      console.log("[SLIP] SlipOK result:", JSON.stringify(slipResult).slice(0, 300));

      // 3. ตรวจผล
      if (!slipResult?.success) {
        const errMsg = slipResult?.message || "ตรวจ slip ไม่สำเร็จ";
        await replyLineMessage(replyToken,
          `❌ ตรวจ slip ไม่สำเร็จ\n📝 ${errMsg}\n\nกรุณาส่งรูป slip ที่ชัดเจนอีกครั้ง`
        );
        continue;
      }

      // ✅ slip ถูกต้อง — ดึงข้อมูลจาก SlipOK
      const slipData = slipResult.data || {};
      const slipAmount = Number(slipData.amount?.amount || slipData.amount || 0);
      const slipRef = slipData.transRef || slipData.transactionId || "";
      const slipBank = slipData.sendingBank || slipData.sender?.bank?.name || "";
      const slipDate = slipData.transDate || slipData.date || "";

      // 4. หา invoice ค้างชำระ
      const pendingInvoice = lineUserId ? await findPendingInvoiceByLineUser(lineUserId) : null;

      if (pendingInvoice) {
        const invoiceAmount = pendingInvoice.totalAmount;
        const amountMatch = slipAmount >= invoiceAmount;
        const amountDiff = Math.abs(slipAmount - invoiceAmount);

        if (amountMatch) {
          // ✅ ยอดตรง/มากกว่า → อัปเดต PAID
          const { error: payErr } = await supabaseAdmin
            .from("invoices")
            .update({
              status: "PAID",
              paid_at: new Date().toISOString(),
              note: `ตรวจ slip อัตโนมัติ | Ref: ${slipRef} | ยอด: ${slipAmount} | ธนาคาร: ${slipBank}`,
              updated_at: new Date().toISOString(),
            })
            .eq("id", pendingInvoice.invoiceId);

          if (payErr) {
            console.error("[SLIP] Update invoice error:", payErr.message);
          }

          // บันทึก log
          try {
            await supabaseAdmin.from("slip_verifications").insert([{
              invoice_id: pendingInvoice.invoiceId,
              condo_id: pendingInvoice.condoId,
              room_id: pendingInvoice.roomId,
              line_user_id: lineUserId,
              slip_ref: slipRef,
              slip_amount: slipAmount,
              slip_bank: slipBank,
              slip_date: slipDate,
              slip_raw: slipData,
              verified_at: new Date().toISOString(),
            }]);
          } catch { /* ถ้าไม่มีตาราง ก็ข้ามไป */ }

          await replyLineMessage(replyToken,
            `✅ ตรวจ slip สำเร็จ!\n` +
            `━━━━━━━━━━━━━━━\n` +
            `💰 ยอดโอน: ${slipAmount.toLocaleString()} บาท\n` +
            `📋 ยอดบิล: ${invoiceAmount.toLocaleString()} บาท\n` +
            `🏦 ธนาคาร: ${slipBank}\n` +
            `📝 Ref: ${slipRef}\n` +
            `━━━━━━━━━━━━━━━\n` +
            `🚪 ห้อง ${pendingInvoice.roomNo} บันทึกชำระแล้ว ✅\n` +
            `ขอบคุณที่ชำระค่าเช่าครับ/ค่ะ 🙏`
          );
        } else {
          // ⚠️ ยอดไม่ตรง → แจ้งเตือนแต่ไม่ mark PAID
          // บันทึก log เป็น pending
          try {
            await supabaseAdmin.from("slip_verifications").insert([{
              invoice_id: pendingInvoice.invoiceId,
              condo_id: pendingInvoice.condoId,
              room_id: pendingInvoice.roomId,
              line_user_id: lineUserId,
              slip_ref: slipRef,
              slip_amount: slipAmount,
              slip_bank: slipBank,
              slip_date: slipDate,
              slip_raw: slipData,
              verified_at: new Date().toISOString(),
            }]);
          } catch { }

          await replyLineMessage(replyToken,
            `⚠️ ยอดโอนไม่ตรงกับบิล\n` +
            `━━━━━━━━━━━━━━━\n` +
            `💰 ยอดโอน: ${slipAmount.toLocaleString()} บาท\n` +
            `📋 ยอดบิล: ${invoiceAmount.toLocaleString()} บาท\n` +
            `📊 ขาดอีก: ${amountDiff.toLocaleString()} บาท\n` +
            `🏦 ธนาคาร: ${slipBank}\n` +
            `📝 Ref: ${slipRef}\n` +
            `━━━━━━━━━━━━━━━\n` +
            `กรุณาโอนเพิ่มหรือติดต่อเจ้าของหอพัก`
          );
        }
      } else {
        // ไม่เจอ invoice ค้าง → แจ้งว่า slip ถูกแต่ไม่มีบิล
        await replyLineMessage(replyToken,
          `✅ slip ถูกต้อง!\n` +
          `💰 ยอด: ${slipAmount.toLocaleString()} บาท\n` +
          `🏦 ธนาคาร: ${slipBank}\n` +
          `📝 Ref: ${slipRef}\n\n` +
          `⚠️ ไม่พบใบแจ้งหนี้ค้างชำระ\nกรุณาติดต่อเจ้าของหอพักเพื่อยืนยัน`
        );
      }
    } catch (err) {
      console.error("[SLIP] Verify error:", err.message);
      try {
        await replyLineMessage(replyToken,
          `❌ เกิดข้อผิดพลาดในการตรวจ slip\nกรุณาลองใหม่อีกครั้ง`
        );
      } catch { }
    }
  }
});

// ✅ API สำหรับ frontend ดูประวัติตรวจ slip
app.get("/api/v1/condos/:condoId/slip-verifications", authRequired, async (req, res) => {
  try {
    const ownerId = req.ownerId;
    const condoId = req.params.condoId;

    const own = await assertOwnsCondo(ownerId, condoId);
    if (!own.ok) return res.status(own.status).json({ error: own.error });

    const { data, error } = await supabaseAdmin
      .from("slip_verifications")
      .select("*")
      .eq("condo_id", condoId)
      .order("verified_at", { ascending: false })
      .limit(50);

    if (error) return res.status(500).json({ error: error.message });
    return res.json({ ok: true, items: data || [] });
  } catch (e) {
    return res.status(500).json({ error: e?.message || "server_error" });
  }
});

/* =========================
   Routes ready
   ========================= */
console.log("Routes ready:", [
  "GET /health",
  "POST /dorm/register",
  "POST /dorm/link-line",
  "GET /dorm/status",
  "GET /auth/line/login",
  "GET /auth/line/callback",

  "POST /repair/create",
  "GET /repair/my",
  "GET /repair/:id",

  "GET /admin/tenants",
  "GET /admin/repairs",
  "PATCH /admin/repair/:id/status",

  "POST /admin/parcel/create",
  "GET /admin/parcel/history",

  "GET /parcels/my",
  "GET /parcels/:id",
  "PATCH /parcels/:id/pickup",

  "GET /admin/facilities",
  "POST /admin/facilities",

  "GET /tenant/facilities",
  "GET /tenant/facility-bookings/my",
  "GET /tenant/facility-bookings/availability",
  "POST /tenant/facility-bookings",
  "POST /tenant/facility-bookings/:id/check-in",
  "POST /tenant/facility-bookings/:id/cancel",
  "POST /tenant/facility-bookings/:id/finish",
  "PUT /api/v1/condos/:condoId/rooms/access-code",
  "POST /api/v1/tenant/link-room",
  "POST /api/v1/condos/:id/invoices/:invoiceId/notify",
  "DELETE /admin/terminate-contract",

  "POST /webhook/line (SlipOK verify)",
  "GET /api/v1/condos/:condoId/slip-verifications",
]);

const PORT = Number(process.env.PORT || 3001);
app.listen(PORT, () => console.log(`Backend running on http://localhost:${PORT}`));
