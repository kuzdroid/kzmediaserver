// KZMedia + KZAsistan • Tek dosya backend (public klasörü YOK)
// ENV: MONGO_URL (Atlas SRV), JWT_KEY (uzun gizli anahtar)

const express = require("express");
const mongoose = require("mongoose");
const cors = require("cors");
const bodyParser = require("body-parser");
const jwt = require("jsonwebtoken");
const bcrypt = require("bcryptjs");
const path = require("path");

const app = express();
const PORT = process.env.PORT || 10000;
const JWT_KEY = process.env.JWT_KEY || "supersecret-kzmedia";
const MONGO_URL = process.env.MONGO_URL;

if (!MONGO_URL) {
  console.error("❌ MONGO_URL env eksik. Render -> Environment sekmesinden ekleyin.");
  process.exit(1);
}

// Güvenlik başlıkları (WebLLM için)
app.use((req, res, next) => {
  res.setHeader("Cross-Origin-Opener-Policy", "same-origin");
  res.setHeader("Cross-Origin-Embedder-Policy", "require-corp");
  next();
});

app.use(cors());
app.use(bodyParser.json());

// ====== Mongo Modelleri ======
const UserSchema = new mongoose.Schema(
  { username: { type: String, unique: true, required: true, trim: true },
    password: { type: String, required: true } },
  { timestamps: true }
);

const PostSchema = new mongoose.Schema(
  { author: { type: String, required: true },
    text: { type: String, required: true },
    imageUrl: { type: String, default: null },
    videoUrl: { type: String, default: null },
    private: { type: Boolean, default: false } },
  { timestamps: true }
);

const User = mongoose.model("User", UserSchema);
const Post = mongoose.model("Post", PostSchema);

// Varsayılan kullanıcılar (şifre: KUZİLER)
async function ensureDefaults() {
  const defaults = [
    { username: "kursatomer@KUZİLER", password: "KUZİLER" },
    { username: "elalye@KUZİLER",     password: "KUZİLER" },
    { username: "sena@KUZİLER",       password: "KUZİLER" },
    { username: "MR.Selim@KUZİLER",   password: "KUZİLER" }
  ];
  for (const d of defaults) {
    const ex = await User.findOne({ username: d.username }).lean();
    if (!ex) {
      const hash = await bcrypt.hash(d.password, 10);
      await User.create({ username: d.username, password: hash });
    }
  }
}

// Auth middleware
function auth(req, res, next) {
  const h = req.headers["authorization"];
  if (!h) return res.status(401).json({ error: "No token" });
  const token = h.split(" ")[1];
  try {
    const decoded = jwt.verify(token, JWT_KEY);
    req.user = decoded;
    next();
  } catch {
    return res.status(401).json({ error: "Invalid token" });
  }
}

// Basit temizlik (küfür filtresi + XSS koruması)
function sanitize(s = "") {
  const t = String(s).slice(0, 2000);
  if (/<script|onerror=|onload=|javascript:/i.test(t)) return "";
  const bad = ["salak","aptal","gerizekalı","orospu","piç","şerefsiz","lanet"];
  let out = t;
  for (const w of bad) out = out.replace(new RegExp(`\\b${w}\\b`, "ig"), "★");
  return out;
}

// ====== API ======
app.get("/api/health", async (req, res) => {
  const uc = await User.countDocuments();
  const pc = await Post.countDocuments();
  res.json({ ok: true, name: "KZMedia API", users: uc, posts: pc, public: false });
});

app.post("/api/auth/register", async (req, res) => {
  try {
    const { username, password } = req.body || {};
    if (!username || !password) return res.status(400).json({ error: "Eksik alan" });
    const ex = await User.findOne({ username }).lean();
    if (ex) return res.status(400).json({ error: "Kullanıcı var" });
    const hash = await bcrypt.hash(password, 10);
    await User.create({ username, password: hash });
    res.json({ ok: true });
  } catch {
    res.status(400).json({ error: "Kayıt başarısız" });
  }
});

app.post("/api/auth/login", async (req, res) => {
  const { username, password } = req.body || {};
  if (!username || !password) return res.status(400).json({ error: "Eksik alan" });
  const u = await User.findOne({ username });
  if (!u) return res.status(400).json({ error: "Kullanıcı yok" });
  const ok = await bcrypt.compare(password, u.password);
  if (!ok) return res.status(400).json({ error: "Şifre yanlış" });
  const token = jwt.sign({ id: u._id, username: u.username }, JWT_KEY, { expiresIn: "7d" });
  res.json({ ok: true, user: { username: u.username }, token });
});

app.post("/api/posts", auth, async (req, res) => {
  try {
    const { text, imageUrl, videoUrl, private: priv } = req.body || {};
    const safe = sanitize(text);
    if (!safe) return res.status(400).json({ error: "Metin reddedildi" });
    const doc = await Post.create({
      author: req.user.username,
      text: safe,
      imageUrl: (imageUrl || "").trim() || null,
      videoUrl: (videoUrl || "").trim() || null,
      private: !!priv
    });
    res.json({ ok: true, post: doc });
  } catch {
    res.status(500).json({ error: "Post hata" });
  }
});

app.get("/api/posts/feed", auth, async (req, res) => {
  try {
    const q = (req.query.q || "").toString().toLowerCase();
    const list = await Post.find({}, null, { sort: { createdAt: -1 }, limit: 200 }).lean();
    const filtered = list.filter(p => {
      if (!q) return true;
      return (p.text || "").toLowerCase().includes(q) || (p.author || "").toLowerCase().includes(q);
    });
    res.json(filtered);
  } catch {
    res.status(500).json({ error: "Feed hata" });
  }
});

// KZAsistan’ın akışa mesaj atması (AUTH gerekmez — “KZAsistan” adına yazar)
app.post("/api/assistant/post", async (req, res) => {
  try {
    const { text } = req.body || {};
    const safe = sanitize(text);
    if (!safe) return res.status(400).json({ error: "Boş/uygunsuz mesaj" });
    const doc = await Post.create({ author: "KZAsistan", text: safe, private: false });
    res.json({ ok: true, post: doc });
  } catch {
    res.status(500).json({ error: "assistant post hata" });
  }
});

// ====== index.html servis (kökte duruyor) ======
app.get("*", (req, res) => {
  res.sendFile(path.join(__dirname, "index.html"));
});

// ====== Başlat ======
mongoose
  .connect(MONGO_URL)
  .then(async () => {
    await ensureDefaults();
    app.listen(PORT, () => {
      console.log(`🚀 Sunucu ayakta: http://localhost:${PORT}`);
      console.log(`ℹ️ Health: /api/health`);
    });
  })
  .catch((err) => {
    console.error("❌ MongoDB bağlantı hatası:", err.message);
    process.exit(1);
  });
