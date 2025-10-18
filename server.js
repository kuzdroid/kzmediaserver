import express from "express";
import mongoose from "mongoose";
import cors from "cors";
import dotenv from "dotenv";
import bcrypt from "bcryptjs";
import jwt from "jsonwebtoken";
import path from "path";
import { fileURLToPath } from "url";

dotenv.config();

const app = express();
const PORT = process.env.PORT || 3000;
const JWT_KEY = process.env.JWT_KEY || "dev-secret";
const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

// --- Güvenlik başlıkları (WebLLM için gerekli) ---
app.use((req, res, next) => {
  res.setHeader("Cross-Origin-Opener-Policy", "same-origin");
  res.setHeader("Cross-Origin-Embedder-Policy", "require-corp");
  next();
});

app.use(cors());
app.use(express.json());

// --- MongoDB ---
const MONGO_URI = process.env.MONGO_URI || "mongodb://127.0.0.1:27017/kzmedia";
mongoose.connect(MONGO_URI, { dbName: process.env.DB_NAME || "kzmedia" })
  .then(() => console.log("✅ MongoDB bağlandı"))
  .catch(err => console.error("❌ MongoDB bağlantı hatası:", err.message));

// --- Modeller ---
const userSchema = new mongoose.Schema({
  username: { type: String, unique: true, required: true, trim: true },
  passHash: { type: String, required: true },
  roles:   { type: [String], default: [] }
}, { timestamps: true });

const postSchema = new mongoose.Schema({
  author: { type: String, required: true }, // username string
  text:   { type: String, required: true },
  imageUrl: String,
  videoUrl: String,
  private: { type: Boolean, default: false },
  createdAt: { type: Date, default: Date.now },
  likesBy: { type: [String], default: [] } // ileride IP/JWT ile 1 kez like
});

const User = mongoose.model("User", userSchema);
const Post = mongoose.model("Post", postSchema);

// --- Auth middleware ---
function auth(req, res, next) {
  const h = req.headers.authorization || "";
  const token = h.startsWith("Bearer ") ? h.slice(7) : null;
  if (!token) return res.status(401).json({ error: "No token" });
  try {
    const payload = jwt.verify(token, JWT_KEY);
    req.user = payload; // { id, username }
    next();
  } catch (e) {
    return res.status(401).json({ error: "Invalid token" });
  }
}

// --- Auth Routes ---
app.post("/api/auth/register", async (req, res) => {
  try {
    const { username, password, ownerCode } = req.body;
    if (!username || !password) return res.status(400).json({ error: "username ve password zorunlu" });

    const exists = await User.findOne({ username });
    if (exists) return res.status(409).json({ error: "Kullanıcı adı zaten var" });

    const passHash = await bcrypt.hash(password, 10);
    const roles = [];
    if (ownerCode === "0") { roles.push("ADMIN", "KUZILER"); } // opsiyonel
    const u = await User.create({ username, passHash, roles });
    res.json({ ok: true, user: { id: u._id, username: u.username, roles: u.roles } });
  } catch (e) {
    res.status(400).json({ error: e.message });
  }
});

app.post("/api/auth/login", async (req, res) => {
  try {
    const { usernameOrEmail, username, password } = req.body;
    const uname = usernameOrEmail || username;
    if (!uname || !password) return res.status(400).json({ error: "username ve password zorunlu" });

    const u = await User.findOne({ username: uname });
    if (!u) return res.status(404).json({ error: "Kullanıcı bulunamadı" });

    const ok = await bcrypt.compare(password, u.passHash);
    if (!ok) return res.status(401).json({ error: "Şifre yanlış" });

    const token = jwt.sign({ id: String(u._id), username: u.username }, JWT_KEY, { expiresIn: "7d" });
    res.json({ ok: true, token, user: { id: u._id, username: u.username, roles: u.roles } });
  } catch (e) {
    res.status(400).json({ error: e.message });
  }
});

app.get("/api/auth/me", auth, async (req, res) => {
  const u = await User.findById(req.user.id).lean();
  if (!u) return res.status(404).json({ error: "Bulunamadı" });
  res.json({ id: u._id, username: u.username, roles: u.roles });
});

// --- Post Routes ---
app.post("/api/posts", auth, async (req, res) => {
  try {
    const { text, imageUrl, videoUrl, private: isPrivate } = req.body;
    if (!text) return res.status(400).json({ error: "text zorunlu" });
    const p = await Post.create({
      author: req.user.username,
      text, imageUrl, videoUrl,
      private: !!isPrivate
    });
    res.json(p);
  } catch (e) {
    res.status(400).json({ error: e.message });
  }
});

// filtre: q param, özel: sadece KUZILER üyelerine görünür
app.get("/api/posts/feed", auth, async (req, res) => {
  const q = (req.query.q || "").toString().toLowerCase();
  const me = await User.findById(req.user.id).lean();
  const isMember = me?.roles?.includes("KUZILER");

  const cond = isMember ? {} : { private: { $ne: true } };
  let posts = await Post.find(cond).sort({ createdAt: -1 }).limit(200).lean();
  if (q) posts = posts.filter(p =>
    (p.text || "").toLowerCase().includes(q) ||
    (p.author || "").toLowerCase().includes(q)
  );
  res.json(posts);
});

// Asistanın akışa düşmesi (opsiyonel auth’suz)
app.post("/api/assistant/post", async (req, res) => {
  try {
    const { text } = req.body || {};
    if (!text) return res.status(400).json({ error: "text zorunlu" });
    const p = await Post.create({ author: "KZAsistan", text, private: false });
    res.json({ ok: true, id: p._id });
  } catch (e) {
    res.status(400).json({ error: e.message });
  }
});

// --- Sağlık ---
app.get("/api/health", (req, res) => res.json({ ok: true, name: "KZMedia API", public: false, health: "/api/health" }));

// --- index.html servis (public yoksa kökten ver) ---
app.get("/", (req, res) => {
  res.sendFile(path.join(__dirname, "index.html"));
});

// --- Başlat ---
app.listen(PORT, () => {
  console.log(`🚀 KZMedia API ayakta: http://localhost:${PORT}`);
});
