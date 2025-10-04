// KZMedia - Production Backend (tek MONGO_URL, fixMongoUrl ile güvenli)

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
const DB_NAME = process.env.DB_NAME || "kzmedia";

// -------- Güvenlik / Middleware --------
app.set("trust proxy", 1);
app.use(helmet({ contentSecurityPolicy: false }));
app.use(cors());
app.use(express.json({ limit: "1mb" }));

const authLimiter = rateLimit({ windowMs: 10 * 60 * 1000, max: 60 });
const apiLimiter  = rateLimit({ windowMs: 60 * 1000, max: 120 });
app.use("/api/auth", authLimiter);
app.use("/api", apiLimiter);

// -------- MONGO URL Fixer --------
function fixMongoUrl(raw) {
  if (!raw) return "";
  let s = String(raw).trim().replace(/^["']|["']$/g, ""); // baş/son tırnakları at

  const [base, q = ""] = s.split("?");
  const params = new URLSearchParams(q);

  // boş değerli parametreleri sil
  for (const [k, v] of params.entries()) {
    if (!v) params.delete(k);
  }

  // gereksizleri kaldır
  params.delete("appName");

  // zorunlu ayarları tek sefer ekle
  params.set("retryWrites", "true");
  if (!params.has("w")) params.set("w", "majority");

  const qs = params.toString();
  return qs ? `${base}?${qs}` : `${base}?retryWrites=true&w=majority`;
}

const RAW_URL = process.env.MONGO_URL || "";
const SAFE_URL = fixMongoUrl(RAW_URL);

mongoose.connect(SAFE_URL, { dbName: DB_NAME })
  .then(() => console.log("✅ MongoDB Atlas bağlandı"))
  .catch(err => {
    console.error("❌ MongoDB bağlantı hatası:", err.message);
    process.exit(1);
  });

// -------- Modeller --------
const { Schema, model } = mongoose;

const userSchema = new Schema({
  username: { type: String, unique: true, required: true },
  email: { type: String, unique: true, sparse: true },
  passwordHash: { type: String, required: true },
  roles: { type: [String], default: [] },
  followers: { type: Number, default: 0 },
  meta: { type: Object, default: {} }
});
const User = model("User", userSchema);

const postSchema = new Schema({
  author: { type: Schema.Types.ObjectId, ref: "User", required: true },
  text: { type: String, required: true },
  imageUrl: String,
  videoUrl: String,
  private: { type: Boolean, default: false },
  likes: [{ type: Schema.Types.ObjectId, ref: "User" }]
}, { timestamps: true });
const Post = model("Post", postSchema);

// -------- Helpers --------
function signToken(userId) {
  return jwt.sign({ userId }, JWT_KEY, { expiresIn: "7d" });
}
function requireAuth(req, res, next) {
  const token = (req.headers.authorization || "").replace(/^Bearer\s+/i, "");
  if (!token) return res.status(401).json({ error: "Token gerekli" });
  try {
    const payload = jwt.verify(token, JWT_KEY);
    req.userId = payload.userId;
    next();
  } catch {
    return res.status(401).json({ error: "Token geçersiz" });
  }
}

// -------- Routes --------
app.get("/health", (req, res) => res.json({ ok: true }));

app.post("/api/auth/register", async (req, res) => {
  try {
    const { username, email, password, ownerCode } = req.body;
    if (!username || !password) return res.status(400).json({ error: "Eksik alan" });

    const exists = await User.findOne({ $or: [{ username }, { email }] });
    if (exists) return res.status(409).json({ error: "Kullanıcı zaten var" });

    const passwordHash = await bcrypt.hash(password, 10);
    const roles = ownerCode === "0" ? ["ADMIN", "KUZILER"] : [];

    const user = await User.create({ username, email, passwordHash, roles });
    res.json({ username: user.username, roles: user.roles });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

app.post("/api/auth/login", async (req, res) => {
  try {
    const { usernameOrEmail, password } = req.body;
    const user = await User.findOne({ $or: [{ username: usernameOrEmail }, { email: usernameOrEmail }] });
    if (!user) return res.status(404).json({ error: "Kullanıcı bulunamadı" });

    const ok = await bcrypt.compare(password, user.passwordHash);
    if (!ok) return res.status(401).json({ error: "Şifre hatalı" });

    const token = signToken(user._id);
    res.json({ token, username: user.username, roles: user.roles });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

app.post("/api/posts", requireAuth, async (req, res) => {
  try {
    const { text, imageUrl, videoUrl, private: isPrivate } = req.body;
    if (!text) return res.status(400).json({ error: "Metin gerekli" });

    const post = await Post.create({
      author: req.userId, text, imageUrl, videoUrl, private: !!isPrivate
    });
    res.json(post);
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

app.get("/api/posts/feed", requireAuth, async (req, res) => {
  const posts = await Post.find().sort({ createdAt: -1 }).limit(50).populate("author", "username roles");
  res.json(posts);
});

// Statik HTML
app.get("/", (req, res) => {
  res.sendFile(path.join(__dirname, "index.html"));
});

// -------- Start --------
app.listen(PORT, "0.0.0.0", () => {
  console.log(`🚀 KZMedia API ayakta: http://localhost:${PORT}`);
});
