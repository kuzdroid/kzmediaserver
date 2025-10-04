// 🌐 KZMedia - Sunucu + MongoDB Atlas
const express = require("express");
const mongoose = require("mongoose");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const cors = require("cors");
const helmet = require("helmet");

const app = express();
const PORT = process.env.PORT || 8080;

// Middleware
app.use(express.json());
app.use(cors());
app.use(helmet());

// ENV değişkenleri
const MONGO_USER = process.env.MONGO_USER;
const MONGO_PASS = process.env.MONGO_PASS;
const MONGO_HOST = process.env.MONGO_HOST;
const DB_NAME    = process.env.DB_NAME || "kzmedia";
const JWT_KEY    = process.env.JWT_KEY || "super-secret-key";

// Mongo bağlantısı
const MONGO_URL = `mongodb+srv://${MONGO_USER}:${MONGO_PASS}@${MONGO_HOST}/${DB_NAME}?retryWrites=true&w=majority`;

mongoose.connect(MONGO_URL, { dbName: DB_NAME })
  .then(() => console.log("✅ MongoDB Atlas bağlandı"))
  .catch(err => {
    console.error("❌ MongoDB bağlantı hatası:", err.message);
    process.exit(1);
  });

// --- MODELLER ---
const userSchema = new mongoose.Schema({
  username: { type: String, unique: true },
  email: String,
  password: String,
  roles: [String],
  followers: { type: Number, default: 0 }
});
const User = mongoose.model("User", userSchema);

const postSchema = new mongoose.Schema({
  author: String,
  text: String,
  imageUrl: String,
  videoUrl: String,
  private: Boolean,
  likes: { type: Number, default: 0 },
  createdAt: { type: Date, default: Date.now }
});
const Post = mongoose.model("Post", postSchema);

// --- Auth middleware ---
function auth(req, res, next) {
  const token = req.headers["authorization"]?.split(" ")[1];
  if (!token) return res.status(401).json({ error: "Token gerekli" });
  try {
    req.user = jwt.verify(token, JWT_KEY);
    next();
  } catch (e) {
    return res.status(401).json({ error: "Geçersiz token" });
  }
}

// --- ROUTES ---

// Health check
app.get("/health", (req, res) => res.json({ ok: true }));

// Kayıt
app.post("/api/auth/register", async (req, res) => {
  try {
    const { username, email, password, ownerCode } = req.body;
    if (!username || !password) return res.status(400).json({ error: "Eksik bilgi" });

    const hashed = await bcrypt.hash(password, 10);
    const roles = [];

    if (ownerCode === "0") {
      roles.push("ADMIN", "KUZILER");
    }

    const user = await User.create({ username, email, password: hashed, roles });
    res.json({ username: user.username, roles: user.roles });
  } catch (err) {
    res.status(500).json({ error: "Kayıt hatası: " + err.message });
  }
});

// Giriş
app.post("/api/auth/login", async (req, res) => {
  try {
    const { usernameOrEmail, password } = req.body;
    const user = await User.findOne({
      $or: [{ username: usernameOrEmail }, { email: usernameOrEmail }]
    });
    if (!user) return res.status(400).json({ error: "Kullanıcı yok" });

    const ok = await bcrypt.compare(password, user.password);
    if (!ok) return res.status(400).json({ error: "Yanlış şifre" });

    const token = jwt.sign({ id: user._id, username: user.username, roles: user.roles }, JWT_KEY, { expiresIn: "7d" });
    res.json({ token, username: user.username, roles: user.roles });
  } catch (err) {
    res.status(500).json({ error: "Login hatası: " + err.message });
  }
});

// Post oluştur
app.post("/api/posts", auth, async (req, res) => {
  try {
    const { text, imageUrl, videoUrl, private } = req.body;
    if (!text) return res.status(400).json({ error: "Metin gerekli" });

    const post = await Post.create({
      author: req.user.username,
      text,
      imageUrl,
      videoUrl,
      private: !!private
    });

    res.json(post);
  } catch (err) {
    res.status(500).json({ error: "Post hatası: " + err.message });
  }
});

// Feed
app.get("/api/posts/feed", auth, async (req, res) => {
  try {
    const posts = await Post.find().sort({ createdAt: -1 }).limit(50);
    res.json(posts);
  } catch (err) {
    res.status(500).json({ error: "Feed hatası: " + err.message });
  }
});

// Static: index.html
const path = require("path");
app.get("/", (req, res) => {
  res.sendFile(path.join(__dirname, "index.html"));
});

app.listen(PORT, "0.0.0.0", () => {
  console.log(`🚀 KZMedia API ayakta: http://localhost:${PORT}`);
});
