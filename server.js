// KZMedia - Prod Backend (tek MONGO_URL ile; JWT_KEY dahili; teşhis endpoint'li)

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

// JWT_KEY: İstersen ENV'den gelir, yoksa alttaki güçlü varsayılan kullanılır.
const JWT_KEY = (process.env.JWT_KEY || "kzmedia_prod_" +
  "f2d8c7f9c0a14a5ab2c4b8e9d1e3f5a7b9c2d4e6f8a0b1c2d3e4f5061728394").slice(0, 64);

const DB_NAME = process.env.DB_NAME || "kzmedia";

app.set("trust proxy", 1);
app.use(helmet({ contentSecurityPolicy: false }));
app.use(cors());
app.use(express.json({ limit: "1mb" }));

const authLimiter = rateLimit({ windowMs: 10 * 60 * 1000, max: 60 });
const apiLimiter  = rateLimit({ windowMs: 60 * 1000, max: 120 });
app.use("/api/auth", authLimiter);
app.use("/api", apiLimiter);

/* ----------------------- MONGO URL FIXER + CONNECT ----------------------- */
function fixMongoUrl(raw) {
  if (!raw) return "";
  let s = String(raw).trim().replace(/^["']|["']$/g, ""); // tırnakları/boşlukları temizle
  const [base, q = ""] = s.split("?");
  const params = new URLSearchParams(q);

  // boş değerli veya gereksiz parametreleri temizle
  for (const [k, v] of params.entries()) { if (!v) params.delete(k); }
  params.delete("appName");

  // zorunlular
  params.set("retryWrites", "true");
  if (!params.has("w")) params.set("w", "majority");

  const qs = params.toString();
  return qs ? `${base}?${qs}` : `${base}?retryWrites=true&w=majority`;
}

function getUrlInfo(url) {
  try {
    // mongodb+srv://USER:PASSWORD@HOST/DB?...
    const m = url.match(/^mongodb\+srv:\/\/([^:@/]+)(?::[^@]*)?@([^/]+)\/?([^?]*)/i);
    return {
      user: m?.[1] || "(yok)",
      host: m?.[2] || "(yok)",
      db: (m?.[3] || "").split("?")[0] || "(yok)"
    };
  } catch { return { user: "(?)", host: "(?)", db: "(?)" }; }
}

let mongoReady = false;
let lastMongoErr = "";

async function connectMongo() {
  try {
    const raw = process.env.MONGO_URL || "";
    if (!raw) { lastMongoErr = "MONGO_URL env yok"; console.error("❌", lastMongoErr); return; }
    const safe = fixMongoUrl(raw);

    const info = getUrlInfo(safe);
    // Kullanıcı adı ASCII olmalı (Türkçe karakter hata çıkarır)
    if (/[^ -~]/.test(info.user)) {
      lastMongoErr = "Kullanıcı adında Türkçe/özel karakter var. ASCII kullan (örn: KZMedia).";
      console.error("❌", lastMongoErr);
      return;
    }

    await mongoose.connect(safe, { dbName: DB_NAME, serverSelectionTimeoutMS: 15000 });
    console.log("✅ MongoDB Atlas bağlandı");
    mongoReady = true;
    lastMongoErr = "";
  } catch (e) {
    mongoReady = false;
    lastMongoErr = e.message;
    console.error("❌ MongoDB bağlantı hatası:", e.message);
    console.error("ℹ️ Kontrol: Atlas DB user ASCII, doğru parola, Network Access 0.0.0.0/0, host/doğru DB adı.");
  }
}

connectMongo();

/* ----------------------- DEBUG ENDPOINT'LER ----------------------- */
// Şifre sızdırmaz, sadece kim bağlanmaya çalıştığını gösterir
app.get("/debug/mongo", (req, res) => {
  const raw = process.env.MONGO_URL || "";
  const safe = fixMongoUrl(raw);
  const info = getUrlInfo(safe);
  res.json({
    ok: mongoReady,
    lastError: lastMongoErr || null,
    parsed: { user: info.user, host: info.host, db: info.db },
    hasPassword: /:\/\/[^:@/]+:[^@]+@/.test(safe), // sadece var/yok
  });
});

// Anlık tekrar bağlanmayı dener
app.get("/db/check", async (req, res) => {
  if (mongoose.connection.readyState !== 1) {
    await connectMongo();
  }
  res.json({ ok: mongoose.connection.readyState === 1, state: mongoose.connection.readyState, lastError: lastMongoErr || null });
});

/* ----------------------- MODELLER ----------------------- */
const { Schema, model } = mongoose;

const userSchema = new Schema({
  username: { type: String, unique: true, required: true, minlength: 3, maxlength: 24 },
  email:    { type: String, unique: true, sparse: true },
  passwordHash: { type: String, required: true },
  roles:   { type: [String], default: [] },  // ["ADMIN","KUZILER"]
  followers: { type: Number, default: 0 },
  meta:     { type: Object, default: {} }
}, { timestamps: true });
const User = model("User", userSchema);

const postSchema = new Schema({
  author:  { type: Schema.Types.ObjectId, ref: "User", required: true },
  text:    { type: String, required: true, maxlength: 500 },
  imageUrl:{ type: String, default: "" },
  videoUrl:{ type: String, default: "" },
  private: { type: Boolean, default: false }, // @KUZILER özel
  likes:   [{ type: Schema.Types.ObjectId, ref: "User" }]
}, { timestamps: true });
const Post = model("Post", postSchema);

/* ----------------------- YARDIMCI ----------------------- */
function signToken(userId) { return jwt.sign({ userId }, JWT_KEY, { expiresIn: "7d" }); }
function requireAuth(req, res, next) {
  const token = (req.headers.authorization || "").replace(/^Bearer\s+/i, "");
  if (!token) return res.status(401).json({ error: "Oturum gerekli" });
  try { req.userId = jwt.verify(token, JWT_KEY).userId; next(); }
  catch { return res.status(401).json({ error: "Token geçersiz" }); }
}

/* ----------------------- ROUTES ----------------------- */
app.get("/health", (req, res) => res.json({ ok: true, db: mongoReady ? "up" : "down" }));

app.post("/api/auth/register", async (req, res) => {
  if (!mongoReady) return res.status(503).json({ error: "DB hazır değil" });
  try {
    const { username, email, password, ownerCode } = req.body || {};
    if (!username || !password) return res.status(400).json({ error: "Eksik alanlar" });

    const exists = await User.findOne({ $or: [{ username }, { email }] });
    if (exists) return res.status(409).json({ error: "Kullanıcı adı veya e-posta kullanımda" });

    const passwordHash = await bcrypt.hash(password, 10);
    const roles = ownerCode === "0" ? ["ADMIN", "KUZILER"] : [];
    const user = await User.create({ username, email, passwordHash, roles });
    res.status(201).json({ id: user._id, username: user.username, roles: user.roles });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.post("/api/auth/login", async (req, res) => {
  if (!mongoReady) return res.status(503).json({ error: "DB hazır değil" });
  try {
    const { usernameOrEmail, password } = req.body || {};
    const user = await User.findOne({ $or: [{ username: usernameOrEmail }, { email: usernameOrEmail }] });
    if (!user) return res.status(401).json({ error: "Kullanıcı bulunamadı" });
    const ok = await bcrypt.compare(password, user.passwordHash);
    if (!ok) return res.status(401).json({ error: "Şifre hatalı" });
    const token = signToken(user._id);
    res.json({ token, user: { id: user._id, username: user.username, roles: user.roles, followers: user.followers } });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.post("/api/posts", requireAuth, async (req, res) => {
  if (!mongoReady) return res.status(503).json({ error: "DB hazır değil" });
  try {
    const { text, imageUrl, videoUrl, private: isPrivate } = req.body || {};
    if (!text || !String(text).trim()) return res.status(400).json({ error: "Metin gerekli" });
    const post = await Post.create({ author: req.userId, text: String(text).trim(), imageUrl: imageUrl||"", videoUrl: videoUrl||"", private: !!isPrivate });
    const populated = await post.populate("author", "username roles");
    res.status(201).json(populated);
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.get("/api/posts/feed", requireAuth, async (req, res) => {
  if (!mongoReady) return res.status(503).json({ error: "DB hazır değil" });
  const limit = Math.min(parseInt(req.query.limit) || 50, 100);
  const posts = await Post.find().sort({ createdAt: -1 }).limit(limit).populate("author", "username roles");
  res.json(posts);
});

// Statik index.html (senin dosyan)
app.get("/", (req, res) => { res.sendFile(path.join(__dirname, "index.html")); });

app.listen(PORT, "0.0.0.0", () => { console.log(`🚀 KZMedia API ayakta: http://localhost:${PORT}`); });
