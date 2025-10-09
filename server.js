// KZMedia – HİBRİT: Kullanıcılar RAM'de, POSTLAR MongoDB Atlas'ta
// ENV (Render → Environment):
//   JWT_KEY      = uzun-bir-gizli-anahtar
//   MONGO_URL    = mongodb+srv://USER:PASS@HOST/kzmedia?retryWrites=true&w=majority
//   ADMIN_MASTER = kursatomer@KUZİLER    (varsayılan)
// Not: "0 yazınca admin" yok.

const express = require("express");
const helmet = require("helmet");
const cors = require("cors");
const rateLimit = require("express-rate-limit");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const mongoose = require("mongoose");
const path = require("path");

const app = express();
const PORT = process.env.PORT || 8080;
const JWT_KEY = (process.env.JWT_KEY || "kzmedia-secret-change").trim();
const ADMIN_MASTER = (process.env.ADMIN_MASTER || "kursatomer@KUZİLER").trim();
const MONGO_URL = (process.env.MONGO_URL || "").trim();

app.set("trust proxy", 1);
app.use(helmet({ contentSecurityPolicy: false }));
app.use(cors());
app.use(express.json({ limit: "1mb" }));

app.use("/api/auth", rateLimit({ windowMs: 10 * 60 * 1000, max: 120 }));
app.use("/api", rateLimit({ windowMs: 60 * 1000, max: 300 }));

/* ------------- Mongo: SADECE POSTLAR ------------- */
let mongoReady = false;

const PostSchema = new mongoose.Schema(
  {
    authorUsername: { type: String, required: true },
    authorRoles:    { type: [String], default: [] },
    text:     { type: String, required: true, maxlength: 500 },
    imageUrl: { type: String, default: "" },
    videoUrl: { type: String, default: "" },
    private:  { type: Boolean, default: false },
    likesIp:  { type: [String], default: [] }
  },
  { timestamps: true }
);
let Post;

async function connectMongo() {
  if (!MONGO_URL) {
    console.error("❌ MONGO_URL yok. Postlar kaydedilemez.");
    return;
  }
  try {
    await mongoose.connect(MONGO_URL, { serverSelectionTimeoutMS: 15000 });
    Post = mongoose.model("Post", PostSchema);
    mongoReady = true;
    console.log("✅ Mongo (postlar) bağlı");
  } catch (e) {
    mongoReady = false;
    console.error("❌ Mongo bağlantı hatası (postlar):", e.message);
    setTimeout(connectMongo, 10000);
  }
}
connectMongo();

/* ------------- Yardımcılar ------------- */
function getIp(req) {
  const xf = (req.headers["x-forwarded-for"] || "").toString().split(",")[0].trim();
  return xf || req.ip || req.connection?.remoteAddress || "0.0.0.0";
}
function signToken(username) {
  return jwt.sign({ username }, JWT_KEY, { expiresIn: "7d" });
}
function requireAuth(req, res, next) {
  const t = (req.headers.authorization || "").replace(/^Bearer\s+/i, "");
  if (!t) return res.status(401).json({ error: "Oturum gerekli" });
  try {
    const p = jwt.verify(t, JWT_KEY);
    req.username = p.username;
    if (!users.has(req.username)) return res.status(401).json({ error: "Kullanıcı yok" });
    next();
  } catch {
    return res.status(401).json({ error: "Token geçersiz" });
  }
}

/* ------------- Kullanıcılar (RAM) ------------- */
// user: { username, email, passwordHash, roles:[], followers:0, followersIp:[] }
const users = new Map();

// Hazır üyeler (şifre hepsinde "KUZİLER"); kursatomer admin
(async () => {
  const basePass = "KUZİLER";
  const ph = await bcrypt.hash(basePass, 10);
  const seed = [
    { u: "kursatomer@KUZİLER", roles: ["ADMIN","KUZILER"] },
    { u: "MR.Selim@KUZİLER",   roles: ["KUZILER"] },
    { u: "elalye@KUZİLER",     roles: ["KUZILER"] },
    { u: "sena@KUZİLER",       roles: ["KUZILER"] }
  ];
  for (const s of seed) {
    if (!users.has(s.u)) {
      users.set(s.u, {
        username: s.u,
        email: (s.u.replace(/\s/g,'') + "@kz.local"),
        passwordHash: ph,
        roles: s.roles.slice(),
        followers: 0,
        followersIp: []
      });
    }
  }
})();

/* ------------- Health ------------- */
app.get("/health", (req, res) => {
  const states = ["disconnected", "connected", "connecting", "disconnecting"];
  res.json({
    ok: true,
    mongo: MONGO_URL ? (states[mongoose.connection.readyState] || "unknown") : "disabled",
    users: users.size
  });
});

/* ------------- Auth ------------- */
// NOT: username ASCII kısıtı YOK. Türkçe/@/nokta kullanılabilir.
app.post("/api/auth/register", async (req, res) => {
  try {
    let { username, email, password } = req.body || {};
    if (!username || !password) return res.status(400).json({ error: "Eksik alanlar" });
    username = String(username).trim();
    if (users.has(username)) return res.status(409).json({ error: "Kullanıcı adı kullanımda" });

    const passwordHash = await bcrypt.hash(password, 10);
    users.set(username, {
      username,
      email: email || `${username.replace(/\s/g,'')}@kz.local`,
      passwordHash,
      roles: [],
      followers: 0,
      followersIp: []
    });

    res.status(201).json({ id: username, username, roles: [] });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.post("/api/auth/login", async (req, res) => {
  try {
    const { usernameOrEmail, password } = req.body || {};
    if (!usernameOrEmail || !password) return res.status(400).json({ error: "Eksik alanlar" });

    let user = users.get(usernameOrEmail);
    if (!user) {
      for (const u of users.values()) {
        if (u.email && u.email.toLowerCase() === String(usernameOrEmail).toLowerCase()) { user = u; break; }
      }
    }
    if (!user) return res.status(401).json({ error: "Kullanıcı bulunamadı" });

    const ok = await bcrypt.compare(password, user.passwordHash);
    if (!ok) return res.status(401).json({ error: "Şifre hatalı" });

    const token = signToken(user.username);
    res.json({ token, user: { id: user.username, username: user.username, roles: user.roles, followers: user.followers } });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.get("/api/auth/me", requireAuth, async (req, res) => {
  const u = users.get(req.username);
  res.json({ username: u.username, roles: u.roles, followers: u.followers });
});

/* ------------- Admin: sadece ADMIN_MASTER ------------- */
app.post("/api/admin/make-admin", requireAuth, async (req, res) => {
  try {
    if (req.username !== ADMIN_MASTER) return res.status(403).json({ error: "Yetki yok" });
    const { targetUsername } = req.body || {};
    if (!targetUsername) return res.status(400).json({ error: "Hedef kullanıcı gerekli" });
    const u = users.get(String(targetUsername));
    if (!u) return res.status(404).json({ error: "Kullanıcı yok" });
    if (!u.roles.includes("ADMIN")) u.roles.push("ADMIN");
    if (!u.roles.includes("KUZILER")) u.roles.push("KUZILER");
    res.json({ ok: true, target: u.username, roles: u.roles });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

/* ------------- Postlar (Mongo) ------------- */
app.post("/api/posts", requireAuth, async (req, res) => {
  if (!mongoReady) return res.status(503).json({ error: "DB hazır değil (postlar)" });
  try {
    const { text, imageUrl, videoUrl, private: isPrivate } = req.body || {};
    if (!text || !String(text).trim()) return res.status(400).json({ error: "Metin gerekli" });

    const u = users.get(req.username);
    const p = await Post.create({
      authorUsername: u.username,
      authorRoles: u.roles || [],
      text: String(text).trim(),
      imageUrl: imageUrl || "",
      videoUrl: videoUrl || "",
      private: !!isPrivate
    });

    res.status(201).json({ ...p.toObject(), author: { username: u.username, roles: u.roles }, _id: p._id });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.get("/api/posts/feed", requireAuth, async (req, res) => {
  if (!mongoReady) return res.status(503).json({ error: "DB hazır değil (postlar)" });
  try {
    const limit = Math.min(parseInt(req.query.limit) || 50, 100);
    const me = users.get(req.username);
    const isK = Array.isArray(me?.roles) && me.roles.includes("KUZILER");

    const list = await Post.find().sort({ createdAt: -1 }).limit(limit);
    const shaped = list
      .filter(p => !p.private || isK || p.authorUsername === me.username)
      .map(p => ({
        _id: p._id,
        author: { username: p.authorUsername, roles: p.authorRoles || [] },
        text: p.text, imageUrl: p.imageUrl, videoUrl: p.videoUrl,
        private: p.private, likesCount: (p.likesIp || []).length,
        createdAt: p.createdAt
      }));
    res.json(shaped);
  } catch (e) { res.status(500).json({ error: e.message }); }
});

/* ------------- Like (IP toggle) ------------- */
app.post("/api/posts/:id/like", async (req, res) => {
  if (!mongoReady) return res.status(503).json({ error: "DB hazır değil (postlar)" });
  try {
    const p = await Post.findById(req.params.id);
    if (!p) return res.status(404).json({ error: "Gönderi yok" });
    const ip = getIp(req);
    const i = p.likesIp.indexOf(ip);
    const liked = i === -1;
    if (liked) p.likesIp.push(ip);
    else p.likesIp.splice(i, 1);
    await p.save();
    res.json({ liked, likes: p.likesIp.length });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

/* ------------- Follow (IP toggle, RAM) ------------- */
app.post("/api/users/:username/follow", async (req, res) => {
  try {
    const key = decodeURIComponent(req.params.username);
    const u = users.get(key);
    if (!u) return res.status(404).json({ error: "Kullanıcı yok" });

    const ip = getIp(req);
    const i = u.followersIp.indexOf(ip);
    const following = i === -1;
    if (following) u.followersIp.push(ip);
    else u.followersIp.splice(i, 1);
    u.followers = u.followersIp.length;

    res.json({ following, followers: u.followers });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

/* ------------- Statik ------------- */
app.get("/", (req, res) => res.sendFile(path.join(__dirname, "index.html")));

/* ------------- Start ------------- */
app.listen(PORT, "0.0.0.0", () => {
  console.log(`🚀 KZMedia API ayakta: http://localhost:${PORT}`);
});
