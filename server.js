// KZMedia + KZAsistan (Mongo; model indirme simülasyonu zorunlu)
const express = require("express");
const path = require("path");
const mongoose = require("mongoose");

const app = express();
const PORT = process.env.PORT || 3000;

// ===== Mongo =====
const MONGO_URL = process.env.MONGO_URL;
if (!MONGO_URL) {
  console.error("❌ MONGO_URL env eksik.");
  process.exit(1);
}
mongoose
  .connect(MONGO_URL)
  .then(() => console.log("✅ MongoDB bağlandı"))
  .catch((err) => {
    console.error("❌ MongoDB bağlantı hatası:", err?.message || err);
    process.exit(1);
  });

// ===== Modeller =====
const UserSchema = new mongoose.Schema(
  {
    username: { type: String, required: true, unique: true, trim: true },
    pass: { type: String, required: true }, // DEMO: düz metin
    roles: { type: [String], default: [] }  // ADMIN, KUZILER, ASSISTANT
  },
  { timestamps: true }
);
const PostSchema = new mongoose.Schema(
  {
    author: { type: String, required: true }, // username
    text: { type: String, required: true },
    imageUrl: { type: String, default: null },
    videoUrl: { type: String, default: null },
    private: { type: Boolean, default: false },
    likes: { type: [String], default: [] } // username list
  },
  { timestamps: true }
);
const AssistantMessageSchema = new mongoose.Schema(
  {
    fromUser: { type: String, required: true },
    text: { type: String, required: true }
  },
  { timestamps: true }
);
// Basit anahtar-değer (model durumu için)
const ConfigSchema = new mongoose.Schema(
  { key: { type: String, unique: true, required: true }, value: {} },
  { timestamps: true }
);

const User = mongoose.model("User", UserSchema);
const Post = mongoose.model("Post", PostSchema);
const AssistantMessage = mongoose.model("AssistantMessage", AssistantMessageSchema);
const Config = mongoose.model("Config", ConfigSchema);

// Varsayılan kullanıcılar
async function ensureDefaults() {
  const defaults = [
    { username: "kursatomer@KUZİLER", pass: "KUZİLER", roles: ["ADMIN","KUZILER"] },
    { username: "elalye@KUZİLER",     pass: "KUZİLER", roles: ["KUZILER"] },
    { username: "sena@KUZİLER",       pass: "KUZİLER", roles: ["KUZILER"] },
    { username: "MR.Selim@KUZİLER",   pass: "KUZİLER", roles: ["KUZILER"] },
    { username: "KZAsistan",          pass: "assistant", roles: ["ASSISTANT"] }
  ];
  for (const u of defaults) {
    const ex = await User.findOne({ username: u.username }).lean();
    if (!ex) await User.create(u);
  }
  // Model varsayılanı: hazır değil
  const existingFlag = await Config.findOne({ key: "modelReady" }).lean();
  if (!existingFlag) await Config.create({ key: "modelReady", value: { ready: false } });
}
ensureDefaults().catch(()=>{});

// ===== Güvenlik/temizlik =====
function maskBadWords(t) {
  const bad = ["salak","aptal","orospu","piç","gerizekalı","şerefsiz","lanet","küfür","söv"];
  let out = String(t || "");
  for (const w of bad) out = out.replace(new RegExp(`\\b${w}\\b`, "ig"), (m) => "★".repeat(m.length));
  return out;
}
function safeText(s) {
  const trimmed = String(s || "").slice(0, 2000);
  if (/<script|onerror=|onload=|javascript:/i.test(trimmed)) return "";
  return maskBadWords(trimmed);
}
// basit rate-limit: kullanıcı başı 2 sn
const lastPostAt = new Map();
function canPost(username) {
  const now = Date.now();
  const last = lastPostAt.get(username) || 0;
  if (now - last < 2000) return false;
  lastPostAt.set(username, now);
  return true;
}

// ===== Middleware =====
app.use(express.json());

// ===== Sayfa =====
app.get("/", (req, res) => res.sendFile(path.join(__dirname, "index.html")));

// Sağlık
app.get("/api/health", async (req, res) => {
  const userCount = await User.countDocuments();
  const postCount = await Post.countDocuments();
  const msgCount  = await AssistantMessage.countDocuments();
  const flag = await Config.findOne({ key: "modelReady" }).lean();
  res.json({ ok: true, app: "KZMedia+KZAsistan", users: userCount, posts: postCount, msgs: msgCount, modelReady: !!flag?.value?.ready, now: Date.now() });
});

// ===== Auth =====
app.post("/api/auth/register", async (req, res) => {
  try {
    const { username, password } = req.body || {};
    if (!username || !password) return res.status(400).json({ error: "username & password zorunlu" });
    const exists = await User.findOne({ username }).lean();
    if (exists) return res.status(400).json({ error: "kullanıcı var" });
    const doc = await User.create({ username, pass: password, roles: [] });
    res.json({ ok: true, user: { username: doc.username, roles: doc.roles } });
  } catch {
    res.status(500).json({ error: "register hata" });
  }
});
app.post("/api/auth/login", async (req, res) => {
  try {
    const { username, password } = req.body || {};
    if (!username || typeof password === "undefined") return res.status(400).json({ error: "eksik giriş" });
    const u = await User.findOne({ username });
    if (!u) return res.status(400).json({ error: "kullanıcı yok" });
    if (u.pass !== password) return res.status(400).json({ error: "şifre yanlış" });
    res.json({ ok: true, user: { username: u.username, roles: u.roles } });
  } catch {
    res.status(500).json({ error: "login hata" });
  }
});

// ===== Posts =====
app.post("/api/posts", async (req, res) => {
  try {
    const { author, text, imageUrl, videoUrl, isPrivate } = req.body || {};
    if (!author) return res.status(400).json({ error: "geçersiz kullanıcı" });
    const me = await User.findOne({ username: author }).lean();
    if (!me) return res.status(400).json({ error: "kullanıcı yok" });
    if (!canPost(author)) return res.status(429).json({ error: "çok hızlı, biraz bekle" });
    const safe = safeText(text);
    if (!safe) return res.status(400).json({ error: "metin kabul edilmedi" });

    const doc = await Post.create({
      author,
      text: safe,
      imageUrl: (imageUrl || "").trim() || null,
      videoUrl: (videoUrl || "").trim() || null,
      private: !!isPrivate
    });
    res.json({ ok: true, post: doc });
  } catch {
    res.status(500).json({ error: "post hata" });
  }
});
app.get("/api/posts/feed", async (req, res) => {
  try {
    const q = (req.query.q || "").toString().toLowerCase();
    const user = (req.query.user || "").toString();
    const me = user ? await User.findOne({ username: user }).lean() : null;
    const isK = !!(me && me.roles && me.roles.includes("KUZILER"));

    const list = await Post.find({}, null, { sort: { createdAt: -1 }, limit: 200 }).lean();
    const filtered = list.filter((p) => {
      if (p.private && !(isK || (user && user === p.author))) return false;
      if (!q) return true;
      return (p.text || "").toLowerCase().includes(q) || (p.author || "").toLowerCase().includes(q);
    });
    res.json(filtered);
  } catch {
    res.status(500).json({ error: "feed hata" });
  }
});
app.post("/api/posts/:id/like", async (req, res) => {
  try {
    const { username } = req.body || {};
    if (!username) return res.status(400).json({ error: "geçersiz kullanıcı" });
    const post = await Post.findById(req.params.id);
    if (!post) return res.status(404).json({ error: "post yok" });
    const i = post.likes.indexOf(username);
    if (i >= 0) post.likes.splice(i, 1);
    else post.likes.push(username);
    await post.save();
    res.json({ ok: true, likes: post.likes.length });
  } catch {
    res.status(500).json({ error: "like hata" });
  }
});

// ===== Model “indirme” simülasyonu (zorunlu bayrak) =====
app.get("/api/assistant/model/status", async (req, res) => {
  try {
    const flag = await Config.findOne({ key: "modelReady" }).lean();
    res.json({ ok: true, ready: !!flag?.value?.ready });
  } catch {
    res.status(500).json({ error: "status hata" });
  }
});
app.post("/api/assistant/model/ready", async (req, res) => {
  try {
    await Config.updateOne(
      { key: "modelReady" },
      { $set: { value: { ready: true } } },
      { upsert: true }
    );
    res.json({ ok: true, ready: true });
  } catch {
    res.status(500).json({ error: "ready hata" });
  }
});
app.post("/api/assistant/model/reset", async (req, res) => {
  try {
    await Config.updateOne(
      { key: "modelReady" },
      { $set: { value: { ready: false } } },
      { upsert: true }
    );
    res.json({ ok: true, ready: false });
  } catch {
    res.status(500).json({ error: "reset hata" });
  }
});

// ===== KZAsistan (modelsiz, Mongo'ya mesaj kaydı) =====
app.post("/api/assistant/chat", async (req, res) => {
  try {
    const { user, message } = req.body || {};
    const u = (user || "").trim();
    const m = (message || "").trim();
    if (!u) return res.status(400).json({ error: "user zorunlu" });
    if (!m) return res.status(400).json({ error: "message zorunlu" });

    // model zorunlu kontrol
    const flag = await Config.findOne({ key: "modelReady" }).lean();
    const ready = !!flag?.value?.ready;
    if (!ready) return res.status(400).json({ error: "Önce modeli indir (KZAsistan için zorunlu)." });

    const me = await User.findOne({ username: u }).lean();
    if (!me) return res.status(400).json({ error: "kullanıcı yok" });

    const clean = safeText(m);
    if (!clean) return res.status(400).json({ error: "mesaj kabul edilmedi" });

    const doc = await AssistantMessage.create({ fromUser: u, text: clean });
    return res.json({ ok: true, saved: { id: doc._id, at: doc.createdAt }, reply: "Mesajın kaydedildi." });
  } catch (e) {
    console.error("❌ /api/assistant/chat hata:", e);
    res.status(500).json({ error: "assistant chat hata" });
  }
});

// Asistanın akışa yazması (şablon; model yok)
app.post("/api/assistant/post", async (req, res) => {
  try {
    // model zorunlu kontrol
    const flag = await Config.findOne({ key: "modelReady" }).lean();
    const ready = !!flag?.value?.ready;
    if (!ready) return res.status(400).json({ error: "Önce modeli indir (KZAsistan için zorunlu)." });

    let asst = await User.findOne({ username: "KZAsistan" });
    if (!asst) asst = await User.create({ username: "KZAsistan", pass: "assistant", roles: ["ASSISTANT"] });

    if (!canPost(asst.username)) return res.status(429).json({ error: "Asistan bekliyor (rate-limit)" });

    const TEMPLATES = [
      "Küçük adımlar büyük işleri başlatır.",
      "Önce veri modelini netleştir, sonra UI kolaylaşır.",
      "Performans için önce ölç, sonra optimize et.",
      "Karmaşık problemi parçalara böl; çözüm hızlanır."
    ];
    const text = TEMPLATES[Math.floor(Math.random() * TEMPLATES.length)];
    const doc = await Post.create({ author: asst.username, text, private: false });
    res.json({ ok: true, post: doc });
  } catch (e) {
    console.error("❌ /api/assistant/post hata:", e);
    res.status(500).json({ error: "assistant post hata" });
  }
});

// API dışı istekler index.html'e düşsün
app.get("*", (req, res) => {
  if (req.path.startsWith("/api/")) {
    return res.status(404).json({ ok: false, error: "Not Found", path: req.path });
  }
  res.sendFile(path.join(__dirname, "index.html"));
});

// ===== Start =====
app.listen(PORT, () => console.log(`🚀 Sunucu ayakta: http://localhost:${PORT}`));
