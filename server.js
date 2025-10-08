// KZMedia - PROD Backend (MongoDB Atlas, tek MONGO_URL ile)
// Gerekli ENV (Render → Settings → Environment):
// - MONGO_URL = mongodb+srv://USER:PASS@HOST/DBNAME?retryWrites=true&w=majority
// - JWT_KEY   = uzun-bir-gizli-anahtar
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
const JWT_KEY = (process.env.JWT_KEY || "dummy-secret-kzmedia").trim();

/* ---------------- MIDDLEWARE ---------------- */
app.set("trust proxy", 1);
app.use(helmet({ contentSecurityPolicy: false }));
app.use(cors());
app.use(express.json({ limit: "1mb" }));

// Rate limits
app.use("/api/auth", rateLimit({ windowMs: 10 * 60 * 1000, max: 60 }));
app.use("/api", rateLimit({ windowMs: 60 * 1000, max: 120 }));

/* ---------------- MONGO (MONGO_URL + retry) ---------------- */
const MONGO_URL = (process.env.MONGO_URL || "").trim();
if (!MONGO_URL) console.error("❌ MONGO_URL yok. Environment'a ekleyin.");

let mongoReady = false;
async function connectMongo() {
  try {
    await mongoose.connect(MONGO_URL, { serverSelectionTimeoutMS: 15000 });
    mongoReady = true;
    console.log("✅ MongoDB Atlas bağlandı (MONGO_URL)");
  } catch (err) {
    mongoReady = false;
    console.error("❌ MongoDB bağlantı hatası:", err.message);
    setTimeout(connectMongo, 10_000); // 10 sn sonra tekrar dene (uygulama kapanmaz)
  }
}
connectMongo();

/* ---------------- MODELLER ---------------- */
const { Schema, model } = mongoose;

const User = model(
  "User",
  new Schema(
    {
      username: { type: String, unique: true, required: true, minlength: 3, maxlength: 24 },
      email: { type: String, unique: true, sparse: true },
      passwordHash: { type: String, required: true },
      roles: { type: [String], default: [] }, // ["ADMIN","KUZILER"]
      followers: { type: Number, default: 0 },
      meta: { type: Object, default: {} },
    },
    { timestamps: true }
  )
);

const Post = model(
  "Post",
  new Schema(
    {
      author: { type: Schema.Types.ObjectId, ref: "User", required: true },
      text: { type: String, required: true, maxlength: 500 },
      imageUrl: { type: String, default: "" },
      videoUrl: { type: String, default: "" },
      private: { type: Boolean, default: false }, // @KUZILER özel
      likes: [{ type: Schema.Types.ObjectId, ref: "User" }],
    },
    { timestamps: true }
  )
);

/* ---------------- YARDIMCI ---------------- */
function signToken(id) {
  return jwt.sign({ userId: id }, JWT_KEY, { expiresIn: "7d" });
}
function requireAuth(req, res, next) {
  const t = (req.headers.authorization || "").replace(/^Bearer\s+/i, "");
  if (!t) return res.status(401).json({ error: "Oturum gerekli" });
  try {
    req.userId = jwt.verify(t, JWT_KEY).userId;
    next();
  } catch {
    return res.status(401).json({ error: "Token geçersiz" });
  }
}
async function isAdmin(userId) {
  const u = await User.findById(userId);
  return !!(u && u.roles && u.roles.includes("ADMIN"));
}
async function isKuziler(userId) {
  const u = await User.findById(userId);
  return !!(u && u.roles && u.roles.includes("KUZILER"));
}

/* ---------------- HEALTH ---------------- */
app.get("/health", (req, res) => {
  const states = ["disconnected", "connected", "connecting", "disconnecting"];
  res.json({ ok: true, db: states[mongoose.connection.readyState] || "unknown" });
});
app.get("/db/check", (req, res) => {
  res.json({ ok: mongoose.connection.readyState === 1, state: mongoose.connection.readyState });
});

/* ---------------- AUTH ---------------- */
app.post("/api/auth/register", async (req, res) => {
  if (!mongoReady) return res.status(503).json({ error: "DB hazır değil" });
  try {
    let { username, email, password, ownerCode } = req.body || {};
    if (!username || !password) return res.status(400).json({ error: "Eksik alanlar" });
    username = String(username).trim();

    const dupe = await User.findOne({ $or: [{ username }, { email }] });
    if (dupe) return res.status(409).json({ error: "Kullanıcı adı veya e-posta kullanımda" });

    const passwordHash = await bcrypt.hash(password, 10);
    const roles = ownerCode === "0" ? ["ADMIN", "KUZILER"] : [];
    const u = await User.create({ username, email, passwordHash, roles });

    res.status(201).json({ id: u._id, username: u.username, roles: u.roles });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

app.post("/api/auth/login", async (req, res) => {
  if (!mongoReady) return res.status(503).json({ error: "DB hazır değil" });
  try {
    const { usernameOrEmail, password } = req.body || {};
    if (!usernameOrEmail || !password) return res.status(400).json({ error: "Eksik alanlar" });

    const u = await User.findOne({ $or: [{ username: usernameOrEmail }, { email: usernameOrEmail }] });
    if (!u) return res.status(401).json({ error: "Kullanıcı bulunamadı" });

    const ok = await bcrypt.compare(password, u.passwordHash);
    if (!ok) return res.status(401).json({ error: "Şifre hatalı" });

    const token = signToken(u._id);
    res.json({
      token,
      user: { id: u._id, username: u.username, roles: u.roles, followers: u.followers },
    });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

app.get("/api/auth/me", requireAuth, async (req, res) => {
  if (!mongoReady) return res.status(503).json({ error: "DB hazır değil" });
  const u = await User.findById(req.userId).select("username roles followers");
  res.json(u);
});

/* ---------------- POSTS ---------------- */
app.post("/api/posts", requireAuth, async (req, res) => {
  if (!mongoReady) return res.status(503).json({ error: "DB hazır değil" });
  try {
    const { text, imageUrl, videoUrl, private: isPrivate } = req.body || {};
    if (!text || !String(text).trim()) return res.status(400).json({ error: "Metin gerekli" });

    const p = await Post.create({
      author: req.userId,
      text: String(text).trim(),
      imageUrl: imageUrl || "",
      videoUrl: videoUrl || "",
      private: !!isPrivate,
    });
    const populated = await p.populate("author", "username roles");
    res.status(201).json(populated);
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

app.get("/api/posts/feed", requireAuth, async (req, res) => {
  if (!mongoReady) return res.status(503).json({ error: "DB hazır değil" });
  try {
    const limit = Math.min(parseInt(req.query.limit) || 50, 100);
    const userIsK = await isKuziler(req.userId);

    const posts = await Post.find()
      .sort({ createdAt: -1 })
      .limit(limit)
      .populate("author", "username roles");

    const filtered = posts.filter(
      (p) => !p.private || userIsK || String(p.author._id) === String(req.userId)
    );
    res.json(filtered);
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

app.post("/api/posts/:id/like", requireAuth, async (req, res) => {
  if (!mongoReady) return res.status(503).json({ error: "DB hazır değil" });
  try {
    const post = await Post.findById(req.params.id);
    if (!post) return res.status(404).json({ error: "Gönderi bulunamadı" });

    const idx = post.likes.findIndex((u) => String(u) === String(req.userId));
    if (idx === -1) post.likes.push(req.userId);
    else post.likes.splice(idx, 1);

    await post.save();
    res.json({ likes: post.likes.length, liked: idx === -1 });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

app.delete("/api/posts/:id", requireAuth, async (req, res) => {
  if (!mongoReady) return res.status(503).json({ error: "DB hazır değil" });
  try {
    const post = await Post.findById(req.params.id).populate("author", "_id");
    if (!post) return res.status(404).json({ error: "Gönderi bulunamadı" });

    const isAuthor = String(post.author._id) === String(req.userId);
    const admin = await isAdmin(req.userId);
    if (!isAuthor && !admin) return res.status(403).json({ error: "Yetki yok" });

    await Post.deleteOne({ _id: post._id });
    res.json({ ok: true });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

/* ---------------- TROLL (sadece kursatomer @ KUZILER) ---------------- */
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
        : `${target.username} trollendi (∞).`,
    });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

/* ---------------- Statik index.html ---------------- */
app.get("/", (req, res) => {
  res.sendFile(path.join(__dirname, "index.html"));
});

/* ---------------- START ---------------- */
app.listen(PORT, "0.0.0.0", () => {
  console.log(`🚀 KZMedia API ayakta: http://localhost:${PORT}`);
});
