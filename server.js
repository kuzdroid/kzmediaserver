// KZMedia – Mongo'suz API (kullanıcılar RAM'de, SADECE POSTLAR diske yazılır)
// ENV (Render → Environment):
//   JWT_KEY = uzun-bir-gizli-anahtar  (yoksa default kullanılır)

const express = require("express");
const helmet = require("helmet");
const cors = require("cors");
const rateLimit = require("express-rate-limit");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const fs = require("fs");
const fsp = require("fs/promises");
const path = require("path");

const app = express();
const PORT = process.env.PORT || 8080;
const JWT_KEY = (process.env.JWT_KEY || "kzmedia-dev-secret-change-me").trim();

app.set("trust proxy", 1);
app.use(helmet({ contentSecurityPolicy: false }));
app.use(cors());
app.use(express.json({ limit: "1mb" }));

app.use("/api/auth", rateLimit({ windowMs: 10 * 60 * 1000, max: 100 }));
app.use("/api", rateLimit({ windowMs: 60 * 1000, max: 300 }));

/* ---------------- IP helper ---------------- */
function getIp(req) {
  const xf = (req.headers["x-forwarded-for"] || "").toString().split(",")[0].trim();
  return xf || req.ip || req.connection?.remoteAddress || "0.0.0.0";
}

/* ---------------- In-Memory Users ----------------
  sadece RAM'de. restart olursa sıfırlanır.
  user: { username, email, passwordHash, roles:[], followers:0, followersIp:[] }
---------------------------------------------------*/
const users = new Map(); // key: username (case-sensitive önerme); sadece ASCII kullan

// İstersen bir admin seed (şifre 0 = admin)
async function seedAdmin() {
  const u = "owner";
  if (!users.has(u)) {
    const passwordHash = await bcrypt.hash("0", 10);
    users.set(u, {
      username: u,
      email: "owner@kz.local",
      passwordHash,
      roles: ["ADMIN", "KUZILER"],
      followers: 0,
      followersIp: [],
    });
  }
}
seedAdmin();

/* ---------------- Posts storage (disk) ----------------
  SADECE postlar kalıcı. data/posts.json içinde.
-------------------------------------------------------*/
const DATA_DIR = path.join(__dirname, "data");
const POSTS_FILE = path.join(DATA_DIR, "posts.json");

let posts = []; // { id, author:{username,roles}, text,imageUrl,videoUrl,private,likesIp[],createdAt }

async function ensureDataFile() {
  try { await fsp.mkdir(DATA_DIR, { recursive: true }); } catch {}
  try {
    const buf = await fsp.readFile(POSTS_FILE);
    posts = JSON.parse(buf.toString() || "[]");
    if (!Array.isArray(posts)) posts = [];
  } catch {
    posts = [];
    await fsp.writeFile(POSTS_FILE, "[]");
  }
}
ensureDataFile();

let saveTimer = null;
function savePostsLater() {
  if (saveTimer) clearTimeout(saveTimer);
  saveTimer = setTimeout(async () => {
    try { await fsp.writeFile(POSTS_FILE, JSON.stringify(posts, null, 2)); }
    catch (e) { console.error("postları yazarken hata:", e.message); }
  }, 200); // basit debounce
}

/* ---------------- Auth helpers ---------------- */
function signToken(username) {
  return jwt.sign({ username }, JWT_KEY, { expiresIn: "7d" });
}
function requireAuth(req, res, next) {
  const t = (req.headers.authorization || "").replace(/^Bearer\s+/i, "");
  if (!t) return res.status(401).json({ error: "Oturum gerekli" });
  try {
    const payload = jwt.verify(t, JWT_KEY);
    req.username = payload.username;
    if (!users.has(req.username)) return res.status(401).json({ error: "Kullanıcı yok" });
    next();
  } catch {
    return res.status(401).json({ error: "Token geçersiz" });
  }
}

/* ---------------- Health ---------------- */
app.get("/health", (req, res) => {
  res.json({ ok: true, db: "na", posts: posts.length, users: users.size });
});

/* ---------------- Auth ---------------- */
app.post("/api/auth/register", async (req, res) => {
  try {
    let { username, email, password, ownerCode } = req.body || {};
    if (!username || !password) return res.status(400).json({ error: "Eksik alanlar" });
    username = String(username).trim();

    // Basit ASCII kontrolü (Render logunda uyarı alıyordun)
    if (!/^[A-Za-z0-9._-]{3,32}$/.test(username)) {
      return res.status(400).json({ error: "Kullanıcı adı ASCII olmalı (3-32): A-Z a-z 0-9 . _ -" });
    }
    if (users.has(username)) return res.status(409).json({ error: "Kullanıcı adı kullanımda" });

    const passwordHash = await bcrypt.hash(password, 10);
    const roles = ownerCode === "0" ? ["ADMIN", "KUZILER"] : [];
    users.set(username, {
      username,
      email: email || `${username}@kz.local`,
      passwordHash,
      roles,
      followers: 0,
      followersIp: [],
    });

    res.status(201).json({ id: username, username, roles });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

app.post("/api/auth/login", async (req, res) => {
  try {
    const { usernameOrEmail, password } = req.body || {};
    if (!usernameOrEmail || !password) return res.status(400).json({ error: "Eksik alanlar" });

    // username öncelik; yoksa email ile ara
    let user = users.get(usernameOrEmail);
    if (!user) {
      for (const u of users.values()) {
        if (u.email && u.email.toLowerCase() === String(usernameOrEmail).toLowerCase()) {
          user = u; break;
        }
      }
    }
    if (!user) return res.status(401).json({ error: "Kullanıcı bulunamadı" });

    const ok = await bcrypt.compare(password, user.passwordHash);
    if (!ok) return res.status(401).json({ error: "Şifre hatalı" });

    const token = signToken(user.username);
    res.json({
      token,
      user: { id: user.username, username: user.username, roles: user.roles, followers: user.followers },
    });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

app.get("/api/auth/me", requireAuth, async (req, res) => {
  const u = users.get(req.username);
  res.json({ username: u.username, roles: u.roles, followers: u.followers });
});

/* ---------------- Posts ---------------- */
app.post("/api/posts", requireAuth, async (req, res) => {
  try {
    const { text, imageUrl, videoUrl, private: isPrivate } = req.body || {};
    if (!text || !String(text).trim()) return res.status(400).json({ error: "Metin gerekli" });

    const u = users.get(req.username);
    const post = {
      id: Date.now().toString(36) + Math.random().toString(36).slice(2, 8),
      author: { username: u.username, roles: u.roles },
      text: String(text).trim(),
      imageUrl: imageUrl || "",
      videoUrl: videoUrl || "",
      private: !!isPrivate,
      likesIp: [],
      createdAt: Date.now(),
    };
    posts.unshift(post);
    savePostsLater();

    res.status(201).json(post);
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

app.get("/api/posts/feed", requireAuth, async (req, res) => {
  try {
    const limit = Math.min(parseInt(req.query.limit) || 50, 100);
    const me = users.get(req.username);
    const isK = Array.isArray(me?.roles) && me.roles.includes("KUZILER");

    const filtered = posts.filter(
      (p) => !p.private || isK || p.author.username === me.username
    );
    const sliced = filtered.slice(0, limit);
    res.json(sliced.map((p) => ({ ...p, likesCount: p.likesIp.length, _id: p.id })));
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

/* ---------------- Like (IP toggle, auth gerekmez) ---------------- */
app.post("/api/posts/:id/like", async (req, res) => {
  try {
    const p = posts.find((x) => x.id === req.params.id);
    if (!p) return res.status(404).json({ error: "Gönderi yok" });
    const ip = getIp(req);
    const i = p.likesIp.indexOf(ip);
    const liked = i === -1;
    if (liked) p.likesIp.push(ip);
    else p.likesIp.splice(i, 1);
    savePostsLater();
    res.json({ liked, likes: p.likesIp.length });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

/* ---------------- Follow (IP toggle, auth gerekmez) ---------------- */
app.post("/api/users/:username/follow", async (req, res) => {
  try {
    const u = users.get(req.params.username);
    if (!u) return res.status(404).json({ error: "Kullanıcı yok" });

    const ip = getIp(req);
    const i = u.followersIp.indexOf(ip);
    const following = i === -1;
    if (following) u.followersIp.push(ip);
    else u.followersIp.splice(i, 1);
    u.followers = u.followersIp.length; // RAM'de

    res.json({ following, followers: u.followers });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

/* ---------------- Statik ---------------- */
app.get("/", (req, res) => res.sendFile(path.join(__dirname, "index.html")));

/* ---------------- Start ---------------- */
app.listen(PORT, "0.0.0.0", () => {
  console.log(`🚀 KZMedia API ayakta: http://localhost:${PORT}`);
});
