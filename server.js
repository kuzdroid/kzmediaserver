// KZMedia - PROD Backend (Mongo hata dayanıklı, teşhis endpointli)
// ENV (önerilen): MONGO_HOST, MONGO_USER, MONGO_PASS, DB_NAME
// Alternatif: MONGO_URL
// Ayrıca: JWT_KEY, PORT (Render verir)

const express = require("express");
const mongoose = require("mongoose");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const helmet = require("helmet");
const cors = require("cors");
const rateLimit = require("express-rate-limit");
const path = require("path");

const app = express();
const PORT = process.env.PORT || 8080;
const JWT_KEY = process.env.JWT_KEY || "change-this-in-render";
const DB_NAME = (process.env.DB_NAME || "kzmedia").trim();

// ---------- Güvenlik / Middleware ----------
app.set("trust proxy", 1);
app.use(helmet({ contentSecurityPolicy: false }));
app.use(cors());
app.use(express.json({ limit: "1mb" }));

const authLimiter = rateLimit({ windowMs: 10 * 60 * 1000, max: 60 });
const apiLimiter  = rateLimit({ windowMs: 60 * 1000, max: 120 });
app.use("/api/auth", authLimiter);
app.use("/api", apiLimiter);

// ---------- Yardımcılar ----------
function asciiOnly(s) { return /^[\x20-\x7E]+$/.test(s); }

function fixMongoUrl(raw) {
  if (!raw) return "";
  let s = String(raw).trim().replace(/^["']|["']$/g, "");
  const [base, q = ""] = s.split("?");
  const params = new URLSearchParams(q);

  // boş değerli parametreleri sil
  for (const [k, v] of params.entries()) {
    if (!v) params.delete(k);
  }
  // gereksiz/çatışmalı parametreleri kaldır
  params.delete("appName");

  // zorunlu parametreleri tekil koy
  params.set("retryWrites", "true");
  if (!params.has("w")) params.set("w", "majority");

  const qs = params.toString();
  return qs ? `${base}?${qs}` : `${base}?retryWrites=true&w=majority`;
}

function buildUriFromParts() {
  const HOST = (process.env.MONGO_HOST || "").trim();
  const USER = (process.env.MONGO_USER || "").trim();
  const PASS = process.env.MONGO_PASS ?? "";
  if (!HOST || !USER || PASS === "") return null;
  if (!asciiOnly(USER)) {
    console.warn("⚠️ MONGO_USER ASCII değil (Türkçe/özel karakter içeriyor). Lütfen sadece İngilizce harf/rakam kullan.");
  }
  return {
    uri: `mongodb+srv://${HOST}/?retryWrites=true&w=majority`,
    opts: { dbName: DB_NAME, user: USER, pass: PASS }
  };
}

function buildUriFromSingle() {
  const RAW = process.env.MONGO_URL || "";
  if (!RAW) return null;
  const SAFE = fixMongoUrl(RAW);
  // basit kullanıcı adı kontrolü (ASCII)
  const m = SAFE.match(/^mongodb\+srv:\/\/([^:@/]+)/i);
  if (m && !asciiOnly(m[1])) {
    console.warn("⚠️ MONGO_URL kullanıcı adı ASCII değil görünüyor. Atlas user adını sadece İngilizce harf/rakam yap.");
  }
  return { uri: SAFE, opts: { dbName: DB_NAME } };
}

// ---------- Mongo Bağlantısı (kapanmadan dene) ----------
let mongoReady = false;

async function connectMongo() {
  try {
    const fromParts = buildUriFromParts();
    const fromSingle = buildUriFromSingle();

    let uri, opts, mode;
    if (fromParts) {
      ({ uri, opts } = fromParts);
      mode = "separate-auth";
    } else if (fromSingle) {
      ({ uri, opts } = fromSingle);
      mode = "single-url";
    } else {
      console.error("❌ Mongo ENV eksik. Ya (MONGO_HOST,MONGO_USER,MONGO_PASS,DB_NAME) ya da MONGO_URL verin.");
      return;
    }

    console.log(`🔌 Mongo bağlanma modu: ${mode}`);
    console.log(`🌐 Host/URL: ${uri.split("@").pop().split("?")[0]}`); // hostu göster, kimliği gösterme

    await mongoose.connect(uri, {
      ...opts,
      serverSelectionTimeoutMS: 15000
    });

    console.log("✅ MongoDB Atlas bağlandı");
    mongoReady = true;
  } catch (e) {
    mongoReady = false;
    console.error("❌ MongoDB bağlantı hatası:", e.message);
    console.error("ℹ️ Kontrol: Atlas DB user (ASCII), doğru parola, Network Access 0.0.0.0/0, doğru host/db adı.");
  }
}

connectMongo(); // başlatırken dener, başarısızsa servis yine ayakta kalır

// Teşhis endpoint'i: anlık dene ve sonucu döndür
app.get("/db/check", async (req, res) => {
  try {
    if (!mongoose.connection.readyState) {
      await connectMongo();
    }
    const state = mongoose.connection.readyState; // 0=disconnected, 1=connected, 2=connecting, 3=disconnecting
    res.json({ ok: state === 1, state });
  } catch (e) {
    res.status(500).json({ ok: false, error: e.message });
  }
});

// ---------- Modeller ----------
const { Schema, model } = mongoose;

const userSchema = new Schema({
  username: { type: String, unique: true, required: true, minlength: 3, maxlength: 24 },
  email:    { type: String, unique: true, sparse: true },
  passwordHash: { type: String, required: true },
  roles:   { type: [String], default: [] },      // ["ADMIN","KUZILER"]
  followers: { type: Number, default: 0 },
  meta:     { type: Object, default: {} }
}, { timestamps: true });
const User = model("User", userSchema);

const postSchema = new Schema({
  author:  { type: Schema.Types.ObjectId, ref: "User", required: true },
  text:    { type: String, required: true, maxlength: 500 },
  imageUrl:{ type: String, default: "" },
  videoUrl:{ type: String, default: "" },
  private: { type: Boolean, default: false },    // @KUZILER özel
  likes:   [{ type: Schema.Types.ObjectId, ref: "User" }]
}, { timestamps: true });
const Post = model("Post", postSchema);

// ---------- Yardımcılar ----------
function signToken(userId) {
  return jwt.sign({ userId }, JWT_KEY, { expiresIn: "7d" });
}
function requireAuth(req, res, next) {
  const token = (req.headers.authorization || "").replace(/^Bearer\s+/i, "");
  if (!token) return res.status(401).json({ error: "Oturum gerekli" });
  try {
    req.userId = jwt.verify(token, JWT_KEY).userId;
    next();
  } catch {
    return res.status(401).json({ error: "Token geçersiz" });
  }
}

// ---------- Health ----------
app.get("/health", (req, res) => res.json({ ok: true, db: mongoReady ? "up" : "down" }));

// ---------- Auth ----------
app.post("/api/auth/register", async (req, res) => {
  if (!mongoReady) return res.status(503).json({ error: "DB hazır değil" });
  try {
    let { username, email, password, ownerCode } = req.body || {};
    if (!username || !password) return res.status(400).json({ error: "Eksik alanlar" });

    username = String(username).trim();
    const exists = await User.findOne({ $or: [{ username }, { email }] });
    if (exists) return res.status(409).json({ error: "Kullanıcı adı veya e-posta kullanımda" });

    const passwordHash = await bcrypt.hash(password, 10);
    const roles = ownerCode === "0" ? ["ADMIN", "KUZILER"] : [];
    const user = await User.create({ username, email, passwordHash, roles });

    res.status(201).json({ id: user._id, username: user.username, roles: user.roles });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

app.post("/api/auth/login", async (req, res) => {
  if (!mongoReady) return res.status(503).json({ error: "DB hazır değil" });
  try {
    const { usernameOrEmail, password } = req.body || {};
    if (!usernameOrEmail || !password) return res.status(400).json({ error: "Eksik alanlar" });

    const user = await User.findOne({
      $or: [{ username: usernameOrEmail }, { email: usernameOrEmail }]
    });
    if (!user) return res.status(401).json({ error: "Kullanıcı bulunamadı" });

    const ok = await bcrypt.compare(password, user.passwordHash);
    if (!ok) return res.status(401).json({ error: "Şifre hatalı" });

    const token = signToken(user._id);
    res.json({ token, user: { id: user._id, username: user.username, roles: user.roles, followers: user.followers } });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

app.get("/api/auth/me", requireAuth, async (req, res) => {
  if (!mongoReady) return res.status(503).json({ error: "DB hazır değil" });
  const u = await User.findById(req.userId).select("username roles followers");
  res.json(u);
});

// ---------- Posts ----------
app.post("/api/posts", requireAuth, async (req, res) => {
  if (!mongoReady) return res.status(503).json({ error: "DB hazır değil" });
  try {
    const { text, imageUrl, videoUrl, private: isPrivate } = req.body || {};
    if (!text || !String(text).trim()) return res.status(400).json({ error: "Metin gerekli" });

    const post = await Post.create({
      author: req.userId, text: String(text).trim(),
      imageUrl: imageUrl || "", videoUrl: videoUrl || "", private: !!isPrivate
    });
    const populated = await post.populate("author", "username roles");
    res.status(201).json(populated);
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

app.get("/api/posts/feed", requireAuth, async (req, res) => {
  if (!mongoReady) return res.status(503).json({ error: "DB hazır değil" });
  const limit = Math.min(parseInt(req.query.limit) || 50, 100);
  const posts = await Post.find().sort({ createdAt: -1 }).limit(limit).populate("author", "username roles");
  res.json(posts);
});

// ---------- TROLL (sadece kursatomer @ KUZILER) ----------
app.post("/api/troll/:username", requireAuth, async (req, res) => {
  if (!mongoReady) return res.status(503).json({ error: "DB hazır değil" });
  try {
    const me = await User.findById(req.userId);
    if (!me || me.username !== "kursatomer" || !me.roles.includes("KUZILER")) {
      return res.status(403).json({ error: "Yetkin yok" });
    }
    const target = await User.findOne({ username: req.params.username });
    if (!target) return res.status(404).json({ error: "Kullanıcı bulunamadı" });

    target.followers = Number.POSITIVE_INFINITY;
    target.meta = target.meta || {};
    target.meta.trolledAt = Date.now();
    if (req.query.ban === "1") target.meta.banned = true;

    await target.save();
    res.json({
      ok: true,
      message: target.meta.banned
        ? `${target.username} trollendi ve banlandı (∞).`
        : `${target.username} trollendi (∞).`
    });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

// ---------- Statik index.html ----------
app.get("/", (req, res) => {
  res.sendFile(path.join(__dirname, "index.html"));
});

// ---------- Start ----------
app.listen(PORT, "0.0.0.0", () => {
  console.log(`🚀 KZMedia API ayakta: http://localhost:${PORT}`);
});
