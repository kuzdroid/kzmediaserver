// KZMedia – Mongo Atlas Backend (MONGO_URL veya 4'lü env) + IP-tabanlı Like/Follow Toggle
// ENV (Render):
//   MONGO_URL = mongodb+srv://USER:PASS@HOST/DB?retryWrites=true&w=majority
//   JWT_KEY   = uzun-bir-gizli-anahtar
//   (veya 4'lü: MONGO_HOST, MONGO_USER, MONGO_PASS, DB_NAME)

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

app.set("trust proxy", 1);
app.use(helmet({ contentSecurityPolicy: false }));
app.use(cors());
app.use(express.json({ limit: "1mb" }));

// sınırlamalar (hafif)
app.use("/api/auth", rateLimit({ windowMs: 10 * 60 * 1000, max: 60 }));
app.use("/api", rateLimit({ windowMs: 60 * 1000, max: 240 }));

/* --------- Mongo bağlantısı (oto) --------- */
const MONGO_URL = (process.env.MONGO_URL || "").trim();
const HOST = (process.env.MONGO_HOST || "").trim();
const USER = (process.env.MONGO_USER || "").trim();
const PASS = (process.env.MONGO_PASS ?? "").trim();
const DB   = (process.env.DB_NAME || "kzmedia").trim();

function buildUriFromParts() {
  if (!HOST) return null;
  return `mongodb+srv://${HOST}/?retryWrites=true&w=majority`;
}

let mongoReady = false;
async function connectMongo() {
  try {
    if (MONGO_URL) {
      await mongoose.connect(MONGO_URL, { serverSelectionTimeoutMS: 15000 });
      console.log("✅ MongoDB Atlas bağlandı (MONGO_URL)");
    } else {
      const uri = buildUriFromParts();
      if (!uri || !USER || PASS === "") {
        console.error("❌ Mongo ENV eksik");
      } else {
        await mongoose.connect(uri, {
          dbName: DB,
          user: USER,
          pass: PASS,
          authSource: "admin",
          authMechanism: "SCRAM-SHA-256",
          serverSelectionTimeoutMS: 15000,
        });
        console.log("✅ MongoDB Atlas bağlandı (separate auth)");
      }
    }
    mongoReady = true;
  } catch (err) {
    mongoReady = false;
    console.error("❌ MongoDB bağlantı hatası:", err.message);
    setTimeout(connectMongo, 10000);
  }
}
connectMongo();

/* --------- Modeller --------- */
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
      followersIp: { type: [String], default: [] }, // IP-tabanlı takip
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
      private: { type: Boolean, default: false },
      likes: [{ type: Schema.Types.ObjectId, ref: "User" }], // (eski user-bazlı, dursun)
      likesIp: { type: [String], default: [] },              // IP-bazlı like (kullanılacak)
    },
    { timestamps: true }
  )
);

/* --------- Yardımcı --------- */
function signToken(id) { return jwt.sign({ userId: id }, JWT_KEY, { expiresIn: "7d" }); }
function requireAuth(req, res, next) {
  const t = (req.headers.authorization || "").replace(/^Bearer\s+/i, "");
  if (!t) return res.status(401).json({ error: "Oturum gerekli" });
  try { req.userId = jwt.verify(t, JWT_KEY).userId; next(); }
  catch { return res.status(401).json({ error: "Token geçersiz" }); }
}
function getClientIp(req){
  // trust proxy açık; req.ip uygun. XFF'den ilk IP'yi de temizleyelim:
  const xf = (req.headers["x-forwarded-for"] || "").toString().split(",")[0].trim();
  return xf || req.ip || req.connection?.remoteAddress || "0.0.0.0";
}

/* --------- Health / Debug --------- */
app.get("/health", (req, res) => {
  const states = ["disconnected", "connected", "connecting", "disconnecting"];
  res.json({ ok: true, db: states[mongoose.connection.readyState] || "unknown" });
});
app.get("/db/check", (req, res) => {
  res.json({ ok: mongoose.connection.readyState === 1, state: mongoose.connection.readyState });
});

/* --------- Auth --------- */
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
    res.json({ token, user: { id: u._id, username: u.username, roles: u.roles, followers: u.followers } });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

app.get("/api/auth/me", requireAuth, async (req, res) => {
  if (!mongoReady) return res.status(503).json({ error: "DB hazır değil" });
  const u = await User.findById(req.userId).select("username roles followers");
  res.json(u);
});

/* --------- Postlar --------- */
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

// FEED (auth gerekli – mevcut mantık)
app.get("/api/posts/feed", requireAuth, async (req, res) => {
  if (!mongoReady) return res.status(503).json({ error: "DB hazır değil" });
  try {
    const limit = Math.min(parseInt(req.query.limit) || 50, 100);
    const user = await User.findById(req.userId).select("roles");
    const isK = !!(user && user.roles && user.roles.includes("KUZILER"));
    const posts = await Post.find().sort({ createdAt: -1 }).limit(limit).populate("author", "username roles");
    const filtered = posts.filter(p => !p.private || isK || String(p.author._id) === String(req.userId));
    // ip-like sayısını da cevapta gönder
    const withCounts = filtered.map(p => ({
      ...p.toObject(),
      likesCount: Array.isArray(p.likesIp) ? p.likesIp.length : 0
    }));
    res.json(withCounts);
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

/* --------- LIKE (IP-toggle) --------- */
// Not: auth GEREKMEZ → herkes 1 IP = 1 like; tekrar basarsa like geri alınır.
app.post("/api/posts/:id/like", async (req, res) => {
  if (!mongoReady) return res.status(503).json({ error: "DB hazır değil" });
  try {
    const post = await Post.findById(req.params.id);
    if (!post) return res.status(404).json({ error: "Gönderi bulunamadı" });

    const ip = getClientIp(req);
    const idx = post.likesIp.indexOf(ip);
    let liked;
    if (idx === -1) { post.likesIp.push(ip); liked = true; }
    else { post.likesIp.splice(idx, 1); liked = false; }

    await post.save();
    res.json({ liked, likes: post.likesIp.length });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

/* --------- FOLLOW (IP-toggle) --------- */
// Hedef kullanıcıyı IP bazlı takip et/çıkar. auth GEREKMEZ.
app.post("/api/users/:username/follow", async (req, res) => {
  if (!mongoReady) return res.status(503).json({ error: "DB hazır değil" });
  try {
    const target = await User.findOne({ username: req.params.username });
    if (!target) return res.status(404).json({ error: "Kullanıcı bulunamadı" });

    const ip = getClientIp(req);
    if (!Array.isArray(target.followersIp)) target.followersIp = [];

    const idx = target.followersIp.indexOf(ip);
    let following;
    if (idx === -1) {
      target.followersIp.push(ip);
      following = true;
    } else {
      target.followersIp.splice(idx, 1);
      following = false;
    }
    // görünen sayı için istersen 'followers' alanını IP sayısına eşitle
    target.followers = target.followersIp.length;

    await target.save();
    res.json({ following, followers: target.followers });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

/* --------- Statik --------- */
app.get("/", (req, res) => {
  res.sendFile(path.join(__dirname, "index.html"));
});

/* --------- Start --------- */
app.listen(PORT, "0.0.0.0", () => {
  console.log(`🚀 KZMedia API ayakta: http://localhost:${PORT}`);
});
