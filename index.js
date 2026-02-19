// index.js (FULL FILE) — RentSphere LINE Backend (Web-only “B”: LINE = แจ้งเตือนอย่างเดียว)
// ✅ ไม่มี LINE webhook / ไม่มีปุ่มใน LINE (ยืนยัน/จบทำในเว็บ)
// ✅ CRON: เตือนก่อนหมด 15 นาที + แจ้งหมดเวลา (ข้อความล้วน)
//
// ✅ FIX รอบนี้:
// - แก้ TIMEZONE (Bangkok) ให้ไม่เพี้ยนเวลา/วัน (ทำให้ “จองแล้วไม่ขึ้น / lock ไม่ตรง” หาย)
// - ใช้ขอบเขตวันแบบ explicit +07:00 (ไม่ลบ 7 ชั่วโมงซ้ำ)
// - availability key HH:mm ใช้ Asia/Bangkok เสถียร ไม่ขึ้นกับ timezone เครื่อง
// - เพิ่ม route cancel ใน Routes ready

import express from "express";
import cors from "cors";
import "dotenv/config";
import { createClient } from "@supabase/supabase-js";
import multer from "multer";
import { randomUUID } from "crypto";
import cron from "node-cron";
import crypto from "crypto";

const app = express();

// ✅ CORS (รองรับ header x-admin-secret)
app.use(
  cors({
    origin: true,
    credentials: true,
    allowedHeaders: [
      "Content-Type",
      "x-line-user-id",
      "x-admin-secret",
      "Cache-Control",
      "cache-control",
      "Pragma",
      "pragma",
    ],
    methods: ["GET", "POST", "PATCH", "OPTIONS"],
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
console.log("HAS_ADMIN_DEV_SECRET:", !!process.env.ADMIN_DEV_SECRET);

// ---- Supabase Admin Client ----
const supabaseAdmin = createClient(
  process.env.SUPABASE_URL,
  process.env.SUPABASE_SERVICE_ROLE_KEY,
  { auth: { persistSession: false } }
);

// ✅ health check
app.get("/health", (req, res) => res.json({ ok: true }));

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

async function requireAdmin(req, res, next) {
  try {
    const secret = req.headers["x-admin-secret"] || req.query.adminSecret || req.body?.adminSecret;

    // ✅ dev secret ผ่านเลย
    if (secret && process.env.ADMIN_DEV_SECRET && String(secret) === String(process.env.ADMIN_DEV_SECRET)) {
      req.adminLineUserId = "dev-admin";
      return next();
    }

    // ✅ โหมดจริง
    const adminLineUserId = req.headers["x-line-user-id"] || req.query.adminLineUserId || req.body?.adminLineUserId;
    if (!adminLineUserId) return res.status(401).json({ error: "adminLineUserId required" });

    const ok = await isAdminLineUser(String(adminLineUserId));
    if (!ok) return res.status(403).json({ error: "forbidden_not_admin" });

    req.adminLineUserId = String(adminLineUserId);
    next();
  } catch (e) {
    return res.status(500).json({ error: e.message || "admin_check_failed" });
  }
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
app.get("/admin/tenants", requireAdmin, async (req, res) => {
  try {
    const { data, error } = await supabaseAdmin
      .schema("public")
      .from("dorm_users")
      .select("id, full_name, room, phone, email, line_user_id, registered_at")
      .not("line_user_id", "is", null)
      .order("registered_at", { ascending: false });

    if (error) return res.status(500).json({ error: pickErr(error) });
    return res.json({ ok: true, items: data || [] });
  } catch (e) {
    return res.status(500).json({ error: e.message || "server error" });
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
app.get("/admin/parcel/history", requireAdmin, async (req, res) => {
  try {
    const { data, error } = await supabaseAdmin
      .schema("public")
      .from("parcels")
      .select("id, dorm_user_id, note, image_url, created_at, status, dorm_users(full_name, room)")
      .order("created_at", { ascending: false })
      .limit(200);

    if (error) return res.status(500).json({ error: pickErr(error) });

    const items = (data || []).map((p) => ({
      id: p.id,
      dormUserId: p.dorm_user_id,
      tenantName: p.dorm_users?.full_name || "-",
      room: p.dorm_users?.room || null,
      note: p.note || null,
      imageUrl: p.image_url || null,
      createdAt: p.created_at,
      status: p.status || "sent",
    }));

    return res.json({ ok: true, items });
  } catch (e) {
    return res.status(500).json({ error: pickErr(e) });
  }
});

/* =========================
   Admin Repairs
   ========================= */
app.get("/admin/repairs", requireAdmin, async (req, res) => {
  try {
    const { status } = req.query;

    let q = supabaseAdmin
      .schema("public")
      .from("repair_request")
      .select("id, created_at, problem_type, description, status, location, room, image_url, line_user_id")
      .order("created_at", { ascending: false });

    if (status) q = q.eq("status", String(status));

    const { data, error } = await q;
    if (error) return res.status(500).json({ error: pickErr(error) });

    return res.json({ ok: true, items: data || [] });
  } catch (e) {
    return res.status(500).json({ error: e.message || "server error" });
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
    const { data, error } = await supabaseAdmin
      .schema("public")
      .from("facilities")
      .select("*")
      .eq("active", true)
      .order("created_at", { ascending: false });

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
   Facility Bookings (Admin/Owner by x-admin-secret)
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
]);

const PORT = Number(process.env.PORT || 3001);
app.listen(PORT, () => console.log(`Backend running on http://localhost:${PORT}`));
