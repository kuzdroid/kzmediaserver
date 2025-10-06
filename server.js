// KZMedia - PROD Backend (MongoDB Atlas, separate auth; MONGO_URL YOK)
// Gerekli ENV (Render → Settings → Environment):
// MONGO_HOST=kzcluster.cjxpbq3.mongodb.net
// MONGO_USER=KZMedia                // Atlas Database Access'teki DB User (CASE-SENSITIVE)
// MONGO_PASS=ParolanHarfRakam       // (öneri: sadece harf+rakam; encode derdi yok)
// DB_NAME=kzmedia
// JWT_KEY=kzmedia-ProdSecret-2025!! // uzun bir gizli anahtar
//
// Build: npm install
// Start: npm start

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
const JWT_KEY =
  process.env.JWT_KEY ||
  "kzmedia_prod_f2d8c7f9c0a14a5ab2c4b8e9d1e3f5a7b9c2d4e6f8a0b1c2d3e4f5061728394".slice(
    0,
    64
  );

// Güvenlik / middleware
app.set("trust proxy", 1);
app.use(helmet({ contentSecurityPolicy: false }));
app.use(cors());
app.use(express.json({ limit: "1mb" }));

const authLimiter = rateLimit({ windowMs: 10 * 60 * 1000, max: 60 });
const apiLimiter = rateLimit({ windowMs: 60 * 1000, max: 120 });
app.use("/api/auth", authLimiter);
app.use("/api", apiLimiter);

// ---- MONGO: SEPARATE AUTH ----
const HOST = (process.env.MONGO_HOST || "").trim();
const USER = (process.env.MONGO_USER || "").trim();   // CASE-SENSITIVE
const PASS = process.env.MONGO_PASS ?? "";
const DB   = (process.env.DB_NAME || "kzmedia").trim();

if (!HOST || !USER || PASS === "") {
  console.error("❌ Mongo ENV eksik. Gerekli: MONGO_HOST, MONGO_USER, MONGO_PASS, DB_NAME");
  process.exit(1);
}

const baseUri = `mongodb+srv://${HOST}/?retryWrites=true&w=majority`;
mongoose.connect(baseUri, {
  dbName: DB,
  user: USER,
  pass: PASS,
  authSource: "admin",            // Atlas DB kullanıcıları admin DB’de tutulur
  authMechanism: "SCRAM-SHA-256",
  serverSelectionTimeoutMS: 15000
}).then(() => {
  console.log("✅ MongoDB Atlas bağlandı (separate auth)");
}).catch(err => {
  console.error("❌ MongoDB bağlantı hatası:", err.message);
  console.error("ℹ️ Kontrol: DB Access'te DB User, CASE doğru, şifre doğru, Network Access 0.0.0.0/0, host & DB adı doğru.");
  process.exit(1);
});

// ---- MODELLER ----
const { Schema, model } = mongoose;

const userSchema = new Schema({
  username: { type: String, unique: true, required: true, minlength: 3, maxlength: 24 },
  email:    { type: String, unique: true, sparse: true },
  passwordHash: { type: String, required: true },
  roles: { type: [String], default: [] },     // ["ADMIN","KUZILER"]
  followers: { type: Number, default: 0 },
  meta: { type: Object, default: {} }
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

// ---- Yardımcılar ----
function signToken(userId) { return jwt.sign({ userId }, JWT_KEY, { expiresIn: "7d" }); }
function requireAuth(req, res, next) {
  const token = (req.headers.authorization || "").replace(/^Bearer\s+/i, "");
  if (!token) return res.status(401).json({ error: "Oturum gerekli" });
  try { req.userId = jwt.verify(token, JWT_KEY).userId; next(); }
  catch { return res.status(401).json({ error: "Token geçersiz" }); }
}
async function isAdmin(userId) {
  const u = await User.findById(userId);
  return !!(u && u.roles && u.roles.includes("ADMIN"));
}
async function isKuziler(userId) {
  const u = await User.findById(userId);
  return !!(u && u.roles && u.roles.includes("KUZILER"));
}

// ---- Health/Diag ----
app.get("/health", (req, res) =>
  res.json({ ok: true, db: mongoose.connection.readyState === 1 ? "up" : "down" })
);
app.get("/db/check", async (req, res) => {
  try {
    const state = mongoose.connection.readyState; // 0 d,1 c,2 ing,3 dis-ing
    if (state !== 1) await mongoose.connection.asPromise();
    res.json({ ok: mongoose.connection.readyState === 1, state: mongoose.connection.readyState });
  } catch (e) {
    res.status(500).json({ ok: false, error: e.message });
  }
});

// ---- Auth ----
app.post("/api/auth/register", async (req, res) => {
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
  try {
    const { usernameOrEmail, password } = req.body || {};
    if (!usernameOrEmail || !password) return res.status(400).json({ error: "Eksik alanlar" });

    const user = await User.findOne({ $or: [{ username: usernameOrEmail }, { email: usernameOrEmail }] });
    if (!user) return res.status(401).json({ error: "Kullanıcı bulunamadı" });

    const ok = await bcrypt.compare(password, user.passwordHash);
    if (!ok) return res.status(401).json({ error: "Şifre hatalı" });

    const token = signToken(user._id);
    res.json({ token, user: { id: user._id, username: user.username, roles: user.roles, followers: user.followers } });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.get("/api/auth/me", requireAuth, async (req, res) => {
  const u = await User.findById(req.userId).select("username roles followers");
  res.json(u);
});

// ---- Posts ----
app.post("/api/posts", requireAuth, async (req, res) => {
  try {
    const { text, imageUrl, videoUrl, private: isPrivate } = req.body || {};
    if (!text || !String(text).trim()) return res.status(400).json({ error: "Metin gerekli" });

    const post = await Post.create({
      author: req.userId,
      text: String(text).trim(),
      imageUrl: imageUrl || "",
      videoUrl: videoUrl || "",
      private: !!isPrivate
    });
    const populated = await post.populate("author", "username roles");
    res.status(201).json(populated);
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.get("/api/posts/feed", requireAuth, async (req, res) => {
  try {
    const limit = Math.min(parseInt(req.query.limit) || 50, 100);
    const userIsK = await isKuziler(req.userId);
    const posts = await Post.find().sort({ createdAt: -1 }).limit(limit).populate("author", "username roles");
    const filtered = posts.filter(p => !p.private || userIsK || String(p.author._id) === String(req.userId));
    res.json(filtered);
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.post("/api/posts/:id/like", requireAuth, async (req, res) => {
  try {
    const post = await Post.findById(req.params.id);
    if (!post) return res.status(404).json({ error: "Gönderi bulunamadı" });

    const idx = post.likes.findIndex(u => String(u) === String(req.userId));
    if (idx === -1) post.likes.push(req.userId);
    else post.likes.splice(idx, 1);

    await post.save();
    res.json({ likes: post.likes.length, liked: idx === -1 });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.delete("/api/posts/:id", requireAuth, async (req, res) => {
  try {
    const post = await Post.findById(req.params.id).populate("author", "_id");
    if (!post) return res.status(404).json({ error: "Gönderi bulunamadı" });

    const isAuthor = String(post.author._id) === String(req.userId);
    const admin = await isAdmin(req.userId);
    if (!isAuthor && !admin) return res.status(403).json({ error: "Yetki yok" });

    await Post.deleteOne({ _id: post._id });
    res.json({ ok: true });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// ---- TROLL (sadece kursatomer @ KUZILER) ----
app.post("/api/troll/:username", requireAuth, async (req, res) => {
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
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// ---- Statik index.html ----
app.get("/", (req, res) => {
  res.sendFile(path.join(__dirname, "index.html"));
});

// ---- Start ----
app.listen(PORT, "0.0.0.0", () => {
  console.log(`🚀 KZMedia API ayakta: http://localhost:${PORT}`);
});
