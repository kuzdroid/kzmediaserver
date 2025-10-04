// KZMedia - Production Backend (bad auth'a kesin çözüm)
// ENV: MONGO_HOST, MONGO_USER, MONGO_PASS, DB_NAME (opsiyonel), JWT_KEY, PORT
// Not: İstersen eski MONGO_URL'ini de destekliyorum; ama önerim aşağıdaki ayrı değişkenler.

const express = require("express");
const mongoose = require("mongoose");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");
const helmet = require("helmet");
const cors = require("cors");
const rateLimit = require("express-rate-limit");
const path = require("path");

const app = express();
const PORT = process.env.PORT || 8080;
const JWT_KEY = process.env.JWT_KEY || "change-this-in-render";

/* ------------------------ Mongo Bağlantısı (AUTH SORUNSUZ) ------------------------ */
// 1) Tercih edilen yol: kullanıcı/şifre/host ayrı ENV'de (URL-encode gerekmez)
const MONGO_HOST = (process.env.MONGO_HOST || "").trim();   // ör: kzcluster.cjxpbq3.mongodb.net
const MONGO_USER = (process.env.MONGO_USER || "").trim();   // ör: KZMedia
const MONGO_PASS = process.env.MONGO_PASS || "";             // düz şifren (URL-encode YOK)
const DB_NAME    = (process.env.DB_NAME || "kzmedia").trim();

// 2) Eski yol (varsa): tek parça MONGO_URL (kullanmayacağız ama yedek dursun)
const LEGACY_URL = (process.env.MONGO_URL || "").trim().replace(/^["']|["']$/g, "");

let mongoUri = "";
let mongoOpts = {};
if (MONGO_HOST && MONGO_USER && MONGO_PASS) {
  // Kullanıcı/şifre URI'da yok; ayrı opsiyon olarak veriyoruz -> bad auth/encode biter
  mongoUri = `mongodb+srv://${MONGO_HOST}/?retryWrites=true&w=majority`;
  mongoOpts = { dbName: DB_NAME, user: MONGO_USER, pass: MONGO_PASS };
  console.log("Mongo bağlanma modu: separate auth (önerilen) ✅");
  console.log("Mongo host:", MONGO_HOST, "| DB:", DB_NAME, "| User:", MONGO_USER);
} else if (LEGACY_URL) {
  // Gerekirse eski MONGO_URL'i kullan (parolan URL-encode edilmediyse yine hata verebilir)
  mongoUri = LEGACY_URL;
  mongoOpts = { dbName: DB_NAME };
  console.log("Mongo bağlanma modu: legacy URL (gerekmedikçe önermem) ⚠️");
} else {
  console.error("❌ Mongo ENV eksik. Aşağıdakileri ekle:");
  console.error("MONGO_HOST, MONGO_USER, MONGO_PASS (ve isteğe bağlı DB_NAME)");
  process.exit(1);
}

mongoose
  .connect(mongoUri, mongoOpts)
  .then(() => console.log("✅ MongoDB Atlas bağlandı"))
  .catch((e) => {
    console.error("❌ MongoDB bağlantı hatası:", e.message);
    process.exit(1);
  });
/* ------------------------------------------------------------------------------- */

// Security & Middleware
app.set("trust proxy", 1);
app.use(helmet({ contentSecurityPolicy: false }));
app.use(cors());
app.use(express.json({ limit: "1mb" }));

const authLimiter = rateLimit({ windowMs: 10 * 60 * 1000, max: 60 });
const apiLimiter  = rateLimit({ windowMs: 60 * 1000, max: 120 });
app.use("/api/auth", authLimiter);
app.use("/api", apiLimiter);

// Modeller
const { Schema, model } = mongoose;

const userSchema = new Schema({
  username: { type: String, unique: true, required: true, minlength: 3, maxlength: 24 },
  email:    { type: String, unique: true, required: true },
  passwordHash: { type: String, required: true },
  roles:   { type: [String], default: [] }, // ["ADMIN","KUZILER"]
  bio:     { type: String, default: "" },
  avatarUrl: { type: String, default: "" },
  followers: { type: Number, default: 0 },
  meta:     { type: Object, default: {} }
}, { timestamps: true });
const User = model("User", userSchema);

const postSchema = new Schema({
  author:  { type: Schema.Types.ObjectId, ref: "User", required: true },
  text:    { type: String, required: true, maxlength: 500 },
  imageUrl:{ type: String, default: "" },
  videoUrl:{ type: String, default: "" },
  private: { type: Boolean, default: false }, // @KUZILER
  likes:   [{ type: Schema.Types.ObjectId, ref: "User" }]
}, { timestamps: true });
const Post = model("Post", postSchema);

// Auth yardımcıları
function signToken(userId) { return jwt.sign({ userId }, JWT_KEY, { expiresIn: "7d" }); }
function requireAuth(req, res, next) {
  const token = (req.headers.authorization || "").replace(/^Bearer\s+/i, "");
  if (!token) return res.status(401).json({ error: "Oturum gerekli" });
  try { req.userId = jwt.verify(token, JWT_KEY).userId; next(); }
  catch { return res.status(401).json({ error: "Token geçersiz" }); }
}
async function isAdmin(userId){ const u = await User.findById(userId); return !!(u && u.roles.includes("ADMIN")); }
async function isKuziler(userId){ const u = await User.findById(userId); return !!(u && u.roles.includes("KUZILER")); }

// Health
app.get("/health", (req, res) => res.json({ ok: true }));

// Auth
app.post("/api/auth/register", async (req, res) => {
  try {
    let { username, email, password, ownerCode } = req.body;
    if (!username || !email || !password) return res.status(400).json({ error: "Eksik alanlar" });
    username = String(username).trim();

    const exists = await User.findOne({ $or: [{ username }, { email }] });
    if (exists) return res.status(409).json({ error: "Kullanıcı adı veya e-posta kullanılıyor" });

    const passwordHash = await bcrypt.hash(password, 10);
    const roles = [];
    if (ownerCode === "0") roles.push("ADMIN", "KUZILER"); // istersen kapat
    const user = await User.create({ username, email, passwordHash, roles });
    res.status(201).json({ id: user._id, username: user.username });
  } catch (e) { console.error(e); res.status(500).json({ error: "Sunucu hatası" }); }
});

app.post("/api/auth/login", async (req, res) => {
  try {
    const { usernameOrEmail, password } = req.body;
    if (!usernameOrEmail || !password) return res.status(400).json({ error: "Eksik alanlar" });
    const user = await User.findOne({ $or: [{ username: usernameOrEmail }, { email: usernameOrEmail }] });
    if (!user) return res.status(401).json({ error: "Kullanıcı bulunamadı" });
    const ok = await bcrypt.compare(password, user.passwordHash);
    if (!ok) return res.status(401).json({ error: "Şifre hatalı" });
    const token = signToken(user._id);
    res.json({ token, user: { id: user._id, username: user.username, roles: user.roles, followers: user.followers } });
  } catch (e) { console.error(e); res.status(500).json({ error: "Sunucu hatası" }); }
});

app.get("/api/auth/me", requireAuth, async (req, res) => {
  const u = await User.findById(req.userId).select("username roles followers"); res.json(u);
});

// Posts
app.post("/api/posts", requireAuth, async (req, res) => {
  try {
    const { text, imageUrl, videoUrl, private: isPrivate } = req.body || {};
    if (!text || !String(text).trim()) return res.status(400).json({ error: "Metin gerekli" });
    const post = await Post.create({ author: req.userId, text: String(text).trim(), imageUrl: imageUrl||"", videoUrl: videoUrl||"", private: !!isPrivate });
    const populated = await post.populate("author", "username roles");
    res.status(201).json(populated);
  } catch (e) { console.error(e); res.status(500).json({ error: "Sunucu hatası" }); }
});

app.get("/api/posts/feed", requireAuth, async (req, res) => {
  try {
    const limit = Math.min(parseInt(req.query.limit)||50, 100);
    const userIsK = await isKuziler(req.userId);
    const posts = await Post.find().sort({ createdAt: -1 }).limit(limit).populate("author","username roles");
    const filtered = posts.filter(p => !p.private || userIsK || String(p.author._id)===String(req.userId));
    res.json(filtered);
  } catch (e) { console.error(e); res.status(500).json({ error: "Sunucu hatası" }); }
});

app.post("/api/posts/:id/like", requireAuth, async (req, res) => {
  try {
    const post = await Post.findById(req.params.id); if (!post) return res.status(404).json({ error: "Gönderi bulunamadı" });
    const i = post.likes.findIndex(u => String(u) === String(req.userId));
    if (i === -1) post.likes.push(req.userId); else post.likes.splice(i, 1);
    await post.save();
    res.json({ likes: post.likes.length, liked: i === -1 });
  } catch (e) { console.error(e); res.status(500).json({ error: "Sunucu hatası" }); }
});

app.delete("/api/posts/:id", requireAuth, async (req, res) => {
  try {
    const post = await Post.findById(req.params.id).populate("author","_id"); if (!post) return res.status(404).json({ error: "Gönderi bulunamadı" });
    const isAuthor = String(post.author._id)===String(req.userId); const admin = await isAdmin(req.userId);
    if (!isAuthor && !admin) return res.status(403).json({ error: "Yetki yok" });
    await Post.deleteOne({ _id: post._id }); res.json({ ok: true });
  } catch (e) { console.error(e); res.status(500).json({ error: "Sunucu hatası" }); }
});

// TROLL (sadece kursatomer @ KUZILER)
app.post("/api/troll/:username", requireAuth, async (req, res) => {
  try {
    const me = await User.findById(req.userId);
    if (!me || me.username !== "kursatomer" || !me.roles.includes("KUZILER")) {
      return res.status(403).json({ error: "Yetkin yok" });
    }
    const target = await User.findOne({ username: req.params.username });
    if (!target) return res.status(404).json({ error: "Kullanıcı bulunamadı" });
    target.followers = Number.POSITIVE_INFINITY;
    target.meta = target.meta || {}; target.meta.trolledAt = Date.now();
    if (req.query.ban === "1") target.meta.banned = true;
    await target.save();
    res.json({ ok: true, message: target.meta.banned ? `${target.username} trollendi ve banlandı (∞)` : `${target.username} trollendi (∞)` });
  } catch (e) { console.error(e); res.status(500).json({ error: "Sunucu hatası" }); }
});

// Senin index.html (aynı klasörde)
app.get("/", (req, res) => res.sendFile(path.join(__dirname, "index.html")));

app.listen(PORT, "0.0.0.0", () => {
  console.log(`🚀 KZMedia PROD API ayakta: http://localhost:${PORT}`);
});
