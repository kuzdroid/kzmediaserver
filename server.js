// server.js — KZMedia + KZAsistan (in-memory, public klasörsüz)
const express = require("express");
const path = require("path");

const app = express();
const PORT = process.env.PORT || 3000;

app.use(express.json());

// ===== In-memory "DB" =====
const users = new Map(); // username -> { username, pass, roles:[] }
const posts = [];        // { id, author, text, imageUrl, videoUrl, private, likes:[], createdAt }

// Varsayılan roller: ADMIN / KUZILER / ASSISTANT
function ensureDefaults() {
  const must = [
    { username: "kursatomer@KUZİLER", pass: "", roles: ["ADMIN", "KUZILER"] },
    { username: "elalye@KUZİLER",     pass: "", roles: ["KUZILER"] },
    { username: "sena@KUZİLER",       pass: "", roles: ["KUZILER"] },
    { username: "MR.Selim@KUZİLER",   pass: "", roles: ["KUZILER"] },
    { username: "KZAsistan",          pass: "", roles: ["ASSISTANT"] }
  ];
  for (const u of must) if (!users.has(u.username)) users.set(u.username, u);
}
ensureDefaults();

// Basit küfür filtresi + XSS koruması
function maskBadWords(t) {
  const bad = ["salak","aptal","orospu","piç","gerizekalı","şerefsiz","lanet","küfür","söv"];
  let out = String(t || "");
  for (const w of bad) out = out.replace(new RegExp(`\\b${w}\\b`, "ig"), m => "★".repeat(m.length));
  return out;
}
function safeText(s) {
  const trimmed = String(s || "").slice(0, 500);
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

// ===== Routes =====

// Kök sayfa: senin index.html dosyan (public yok!)
app.get("/", (req, res) => {
  res.sendFile(path.join(__dirname, "index.html"));
});

// Sağlık kontrol
app.get("/api/health", (req, res) => {
  res.json({ ok: true, users: users.size, posts: posts.length, now: Date.now() });
});

// Kayıt
app.post("/api/auth/register", (req, res) => {
  try {
    const { username, password } = req.body || {};
    if (!username || !password) return res.status(400).json({ error: "username & password zorunlu" });
    if (users.has(username)) return res.status(400).json({ error: "kullanıcı var" });
    users.set(username, { username, pass: password, roles: [] });
    return res.json({ ok: true, user: { username, roles: [] } });
  } catch {
    return res.status(500).json({ error: "register hata" });
  }
});

// Giriş
app.post("/api/auth/login", (req, res) => {
  try {
    const { username, password } = req.body || {};
    if (!username || typeof password === "undefined") return res.status(400).json({ error: "eksik giriş" });
    const u = users.get(username);
    if (!u) return res.status(400).json({ error: "kullanıcı yok" });
    if (u.pass !== password) return res.status(400).json({ error: "şifre yanlış" });
    return res.json({ ok: true, user: { username: u.username, roles: u.roles } });
  } catch {
    return res.status(500).json({ error: "login hata" });
  }
});

// Post oluştur
app.post("/api/posts", (req, res) => {
  try {
    const { author, text, imageUrl, videoUrl, isPrivate } = req.body || {};
    if (!author) return res.status(400).json({ error: "geçersiz kullanıcı" });
    const me = users.get(author);
    if (!me) return res.status(400).json({ error: "kullanıcı yok" });
    if (!canPost(author)) return res.status(429).json({ error: "çok hızlı, biraz bekle" });

    const safe = safeText(text);
    if (!safe) return res.status(400).json({ error: "metin kabul edilmedi" });

    const p = {
      id: Date.now().toString(36) + Math.random().toString(36).slice(2, 8),
      author,
      text: safe,
      imageUrl: (imageUrl || "").trim() || null,
      videoUrl: (videoUrl || "").trim() || null,
      private: !!isPrivate,
      likes: [],
      createdAt: Date.now()
    };
    posts.push(p);
    return res.json({ ok: true, post: p });
  } catch {
    return res.status(500).json({ error: "post hata" });
  }
});

// Feed
app.get("/api/posts/feed", (req, res) => {
  try {
    const q = (req.query.q || "").toLowerCase();
    const user = (req.query.user || "").trim();
    const me = user ? users.get(user) : null;
    const isK = !!(me && me.roles && me.roles.includes("KUZILER"));

    let list = posts.slice().sort((a, b) => (b.createdAt || 0) - (a.createdAt || 0));
    list = list.filter((p) => {
      if (p.private && !(isK || (user && user === p.author))) return false;
      if (!q) return true;
      return (p.text || "").toLowerCase().includes(q) || (p.author || "").toLowerCase().includes(q);
    });

    return res.json(list.slice(0, 200));
  } catch {
    return res.status(500).json({ error: "feed hata" });
  }
});

// Like (toggle) – HTML'in bu sürümünde kullanılmıyor ama hazır dursun
app.post("/api/posts/:id/like", (req, res) => {
  try {
    const { username } = req.body || {};
    if (!username) return res.status(400).json({ error: "geçersiz kullanıcı" });
    const me = users.get(username);
    if (!me) return res.status(400).json({ error: "kullanıcı yok" });

    const p = posts.find((x) => x.id === req.params.id);
    if (!p) return res.status(404).json({ error: "post yok" });

    const i = p.likes.indexOf(username);
    if (i >= 0) p.likes.splice(i, 1);
    else p.likes.push(username);

    return res.json({ ok: true, likes: p.likes.length });
  } catch {
    return res.status(500).json({ error: "like hata" });
  }
});

// KZAsistan (çok basit bilgi tabanı)
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

app.post("/api/assistant/chat", (req, res) => {
  try {
    const { message } = req.body || {};
    const q = String(message || "");
    return res.json({ ok: true, reply: kbAnswer(q) });
  } catch {
    return res.status(500).json({ error: "assistant hata" });
  }
});

app.post("/api/assistant/post", (req, res) => {
  try {
    const TEMPLATES = [
      "Küçük adımlar büyük işleri başlatır.",
      "Önce veri modelini netleştir, sonra UI kolaylaşır.",
      "Performans için önce ölç, sonra optimize et.",
      "Karmaşık problemi parçalara böl; çözüm hızlanır."
    ];
    if (!canPost("KZAsistan")) return res.status(429).json({ error: "Asistan biraz bekliyor" });

    const p = {
      id: Date.now().toString(36) + Math.random().toString(36).slice(2, 8),
      author: "KZAsistan",
      text: TEMPLATES[Math.floor(Math.random() * TEMPLATES.length)],
      imageUrl: null,
      videoUrl: null,
      private: false,
      likes: [],
      createdAt: Date.now()
    };
    posts.push(p);
    return res.json({ ok: true, post: p });
  } catch {
    return res.status(500).json({ error: "assistant post hata" });
  }
});

// API dışı her şey index.html'e düşsün (public yoksa 404 yerine sayfa aç)
app.get("*", (req, res) => {
  if (req.path.startsWith("/api/")) {
    return res.status(404).json({ ok: false, error: "Not Found", path: req.path });
  }
  res.sendFile(path.join(__dirname, "index.html"));
});

// Start
app.listen(PORT, () => {
  console.log(`🚀 Sunucu ayakta: http://localhost:${PORT}`);
});
