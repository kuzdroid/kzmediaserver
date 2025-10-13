// server.js — KZMedia + KZAsistan (uzun/anlamlı), MongoDB/Atlas, public klasör YOK
// index.html kökten (/) servis edilir. Şifreler istemcide gösterilmez (demo = düz metin).

const express = require("express");
const path = require("path");
const mongoose = require("mongoose");

const app = express();
const PORT = process.env.PORT || 3000;

// ====== MongoDB Bağlantısı ======
const MONGO_URL = process.env.MONGO_URL;
if (!MONGO_URL) {
  console.error("❌ MONGO_URL env yok (Atlas SRV bağlantısını Render ayarlarına ekleyin).");
  process.exit(1);
}
mongoose
  .connect(MONGO_URL)
  .then(() => console.log("✅ MongoDB bağlandı"))
  .catch((err) => {
    console.error("❌ MongoDB bağlantı hatası:", err?.message || err);
    process.exit(1);
  });

// ====== Modeller ======
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
    likes: { type: [String], default: [] } // username listesi (toggle)
  },
  { timestamps: true }
);

const User = mongoose.model("User", UserSchema);
const Post = mongoose.model("Post", PostSchema);

// Varsayılan kullanıcılar
async function ensureDefaults() {
  const defaults = [
    { username: "kursatomer@KUZİLER", pass: "KUZİLER", roles: ["ADMIN", "KUZILER"] },
    { username: "elalye@KUZİLER",     pass: "KUZİLER", roles: ["KUZILER"] },
    { username: "sena@KUZİLER",       pass: "KUZİLER", roles: ["KUZILER"] },
    { username: "MR.Selim@KUZİLER",   pass: "KUZİLER", roles: ["KUZILER"] },
    { username: "KZAsistan",          pass: "assistant", roles: ["ASSISTANT"] }
  ];
  for (const u of defaults) {
    const exists = await User.findOne({ username: u.username }).lean();
    if (!exists) await User.create(u);
  }
}
ensureDefaults().catch(() => {});

// ====== İçerik Güvenliği ======
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

// Basit rate-limit (kullanıcı başı 2 sn)
const lastPostAt = new Map();
function canPost(username) {
  const now = Date.now();
  const last = lastPostAt.get(username) || 0;
  if (now - last < 2000) return false;
  lastPostAt.set(username, now);
  return true;
}

// ====== Middleware ======
app.use(express.json());

// ====== Sayfa ======
app.get("/", (req, res) => {
  res.sendFile(path.join(__dirname, "index.html"));
});

// Sağlık
app.get("/api/health", async (req, res) => {
  const userCount = await User.countDocuments();
  const postCount = await Post.countDocuments();
  res.json({ ok: true, app: "KZMedia+KZAsistan", users: userCount, posts: postCount, now: Date.now() });
});

// ====== Auth ======
app.post("/api/auth/register", async (req, res) => {
  try {
    const { username, password } = req.body || {};
    if (!username || !password) return res.status(400).json({ error: "username & password zorunlu" });

    const exists = await User.findOne({ username }).lean();
    if (exists) return res.status(400).json({ error: "kullanıcı var" });

    const doc = await User.create({ username, pass: password, roles: [] });
    res.json({ ok: true, user: { username: doc.username, roles: doc.roles } });
  } catch (e) {
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
  } catch (e) {
    res.status(500).json({ error: "login hata" });
  }
});

// ====== Posts ======
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
  } catch (e) {
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
  } catch (e) {
    res.status(500).json({ error: "feed hata" });
  }
});

// Like (toggle) — endpoint dursun, UI tarafı istersen ekleyebilirsin
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
  } catch (e) {
    res.status(500).json({ error: "like hata" });
  }
});

// ====== KZAsistan yardımcı ======
async function getOrCreateAssistant() {
  let asst = await User.findOne({ username: "KZAsistan" });
  if (!asst) {
    asst = await User.create({ username: "KZAsistan", pass: "assistant", roles: ["ASSISTANT"] });
  } else if (!asst.pass) {
    asst.pass = "assistant";
    await asst.save();
  }
  return asst;
}

// ====== KZAsistan ======
const KB = [
  { re: /merhaba|selam/i, ans: "Merhaba! Ben KZAsistan 🚀" },
  { re: /2\+2|iki\+iki/i, ans: "2 + 2 = 4 ✅" },
  { re: /adın ne|ismin/i, ans: "Benim adım KZAsistan 🤖" },
  { re: /nasılsın/i, ans: "İyiyim, sen nasılsın? 🙂" },
  { re: /html|css|javascript|js/i, ans: "Örnek kod da yazabilirim; ne yapmak istiyorsun?" }
];
function kbAnswer(q) {
  for (const r of KB) if (r.re.test(q)) return r.ans;
  return "Anladım. Biraz daha detay verirsen örnekle yardımcı olayım.";
}

app.post("/api/assistant/chat", async (req, res) => {
  try {
    const { message } = req.body || {};
    res.json({ ok: true, reply: kbAnswer(String(message || "")) });
  } catch {
    res.status(500).json({ error: "assistant hata" });
  }
});

app.post("/api/assistant/post", async (req, res) => {
  try {
    // 1) Asistan hesabı garanti
    const asst = await getOrCreateAssistant();

    // 2) Basit rate-limit
    if (!canPost(asst.username)) {
      return res.status(429).json({ error: "Asistan biraz bekliyor (rate-limit)" });
    }

    // 3) Metin şablonları
    const TEMPLATES = [
      "Küçük adımlar büyük işleri başlatır.",
      "Önce veri modelini netleştir, sonra UI kolaylaşır.",
      "Performans için önce ölç, sonra optimize et.",
      "Karmaşık problemi parçalara böl; çözüm hızlanır."
    ];
    const text = TEMPLATES[Math.floor(Math.random() * TEMPLATES.length)];
    if (!text) return res.status(500).json({ error: "Şablon bulunamadı" });

    // 4) Post oluştur
    const doc = await Post.create({
      author: asst.username,
      text,
      private: false
    });

    return res.json({ ok: true, post: doc });
  } catch (e) {
    console.error("❌ /api/assistant/post hata:", e);
    return res.status(500).json({ error: e?.message || "assistant post hata" });
  }
});

// API dışındaki her şey index.html'e düşsün (404 yerine SPA davranışı)
app.get("*", (req, res) => {
  if (req.path.startsWith("/api/")) {
    return res.status(404).json({ ok: false, error: "Not Found", path: req.path });
  }
  res.sendFile(path.join(__dirname, "index.html"));
});

// ====== Start ======
app.listen(PORT, () => {
  console.log(`🚀 Sunucu ayakta: http://localhost:${PORT}`);
});
