// KZMedia - Mongo Atlas Backend (parçalı env değişkenleri ile)
//
// Render Environment Variables:
//   MONGO_HOST = kzcluster.cjxpbq3.mongodb.net
//   MONGO_USER = seninAtlasKullaniciAdin
//   MONGO_PASS = seninAtlasSifren
//   DB_NAME    = kzmedia
//   JWT_KEY    = uzun-bir-gizli-anahtar

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

/* ---------------- Middleware ---------------- */
app.set("trust proxy", 1);
app.use(helmet({ contentSecurityPolicy: false }));
app.use(cors());
app.use(express.json({ limit: "1mb" }));

// Rate limits
app.use("/api/auth", rateLimit({ windowMs: 10 * 60 * 1000, max: 60 }));
app.use("/api", rateLimit({ windowMs: 60 * 1000, max: 120 }));

/* ---------------- MongoDB bağlantısı ---------------- */
async function connectMongo() {
  try {
    await mongoose.connect(
      `mongodb+srv://${process.env.MONGO_HOST}/?retryWrites=true&w=majority`,
      {
        dbName: process.env.DB_NAME,
        user: process.env.MONGO_USER,
        pass: process.env.MONGO_PASS,
        authSource: "admin",
        authMechanism: "SCRAM-SHA-256"
      }
    );
    console.log("✅ MongoDB Atlas bağlandı!");
  } catch (err) {
    console.error("❌ MongoDB bağlantı hatası:", err.message);
    setTimeout(connectMongo, 10000); // 10 sn sonra tekrar dene
  }
}
connectMongo();

/* ---------------- Modeller ---------------- */
const { Schema, model } = mongoose;

const User = model(
  "User",
  new Schema(
    {
      username: { type: String, unique: true, required: true },
      email: { type: String, unique: true, sparse: true },
      passwordHash: { type: String, required: true },
      roles: { type: [String], default: [] }, // ["ADMIN","KUZILER"]
      followers: { type: Number, default: 0 },
      meta: { type: Object, default: {} }
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
      private: { type: Boolean, default: false },
      likes: [{ type: Schema.Types.ObjectId, ref: "User" }]
    },
    { timestamps: true }
  )
);

/* ---------------- Yardımcı fonksiyonlar ---------------- */
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
  return !!(u && u.roles.includes("ADMIN"));
}
async function isKuziler(userId) {
  const u = await User.findById(userId);
  return !!(u && u.roles.includes("KUZILER"));
}

/* ---------------- Health check ---------------- */
app.get("/health", (req, res) => {
  const states = ["disconnected", "connected", "connecting", "disconnecting"];
  res.json({ ok: true, db: states[mongoose.connection.readyState] });
});
app.get("/db/check", (req, res) => {
  res.json({ ok: mongoose.connection.readyState === 1, state: mongoose.connection.readyState });
});

/* ---------------- Auth ---------------- */
app.post("/api/auth/register", async (req, res) => {
  try {
    let { username, email, password, ownerCode } = req.body;
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
  try {
    const { usernameOrEmail, password } = req.body;
    const u = await User.findOne({ $or: [{ username: usernameOrEmail }, { email: usernameOrEmail }] });
    if (!u) return res.status(401).json({ error: "Kullanıcı bulunamadı" });

    const ok = await bcrypt.compare(password, u.passwordHash);
    if (!ok) return res.status(401).json({ error: "Şifre hatalı" });

    const token = signToken(u._id);
    res.json({ token, user: { id: u._id, username: u.username, roles: u.roles } });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

app.get("/api/auth/me", requireAuth, async (req, res) => {
  const u = await User.findById(req.userId).select("username roles followers");
  res.json(u);
});

/* ---------------- Postlar ---------------- */
app.post("/api/posts", requireAuth, async (req, res) => {
  try {
    const { text, imageUrl, videoUrl, private: isPrivate } = req.body;
    if (!text) return res.status(400).json({ error: "Metin gerekli" });

    const p = await Post.create({
      author: req.userId,
      text,
      imageUrl: imageUrl || "",
      videoUrl: videoUrl || "",
      private: !!isPrivate
    });
    const populated = await p.populate("author", "username roles");
    res.status(201).json(populated);
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

app.get("/api/posts/feed", requireAuth, async (req, res) => {
  try {
    const posts = await Post.find().sort({ createdAt: -1 }).limit(50).populate("author", "username roles");
    const userIsK = await isKuziler(req.userId);
    const filtered = posts.filter(p => !p.private || userIsK || String(p.author._id) === String(req.userId));
    res.json(filtered);
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

/* ---------------- Troll route ---------------- */
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
    res.json({ ok: true, message: `${target.username} trollendi (∞)` });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

/* ---------------- Statik dosya ---------------- */
app.get("/", (req, res) => {
  res.sendFile(path.join(__dirname, "index.html"));
});

/* ---------------- Start ---------------- */
app.listen(PORT, "0.0.0.0", () => {
  console.log(`🚀 KZMedia API ayakta: http://localhost:${PORT}`);
});
