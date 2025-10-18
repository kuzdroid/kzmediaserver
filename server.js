import express from "express";
import mongoose from "mongoose";
import cors from "cors";
import dotenv from "dotenv";
import path from "path";
import { fileURLToPath } from "url";

dotenv.config();

const app = express();
const PORT = process.env.PORT || 3000;

// --- Güvenlik başlıkları (WebLLM için şart: HTTPS + COOP/COEP) ---
app.use((req, res, next) => {
  res.setHeader("Cross-Origin-Opener-Policy", "same-origin");
  res.setHeader("Cross-Origin-Embedder-Policy", "require-corp");
  next();
});

app.use(cors());
app.use(express.json());

// --- MongoDB (SADECE POSTLAR) ---
const MONGO_URI = process.env.MONGO_URI || "mongodb://127.0.0.1:27017/kzmedia";
const DB_NAME = process.env.DB_NAME || "kzmedia";

mongoose.connect(MONGO_URI, { dbName: DB_NAME })
  .then(() => console.log("✅ MongoDB bağlandı"))
  .catch(err => console.error("❌ MongoDB bağlantı hatası:", err.message));

// Post şeması (users yok!)
const postSchema = new mongoose.Schema({
  author: { type: String, default: "Anonim" },
  text:   { type: String, required: true },
  imageUrl: String,
  videoUrl: String,
  private: { type: Boolean, default: false },
  createdAt: { type: Date, default: Date.now },
  likes: { type: Number, default: 0 }
});
const Post = mongoose.model("Post", postSchema);

// --- API ---
app.get("/api/health", (req, res) => res.json({ ok: true, name: "KZMedia API", postsDB: DB_NAME }));

// Gönderi oluştur (auth YOK — sadece metin zorunlu)
app.post("/api/posts", async (req, res) => {
  try {
    const { author, text, imageUrl, videoUrl, private: isPrivate } = req.body || {};
    if (!text || !String(text).trim()) return res.status(400).json({ error: "text zorunlu" });
    const p = await Post.create({
      author: (author && String(author).trim()) || "Anonim",
      text: String(text),
      imageUrl: imageUrl || undefined,
      videoUrl: videoUrl || undefined,
      private: !!isPrivate
    });
    res.json(p);
  } catch (e) {
    res.status(400).json({ error: e.message });
  }
});

// Akış (en yeni 200)
app.get("/api/posts", async (req, res) => {
  const q = (req.query.q || "").toString().toLowerCase();
  let posts = await Post.find({}).sort({ createdAt: -1 }).limit(200).lean();
  if (q) {
    posts = posts.filter(p =>
      (p.text || "").toLowerCase().includes(q) ||
      (p.author || "").toLowerCase().includes(q)
    );
  }
  res.json(posts);
});

// KZAsistan mesajını akışa yaz (opsiyonel)
app.post("/api/assistant/post", async (req, res) => {
  try {
    const { text } = req.body || {};
    if (!text || !String(text).trim()) return res.status(400).json({ error: "text zorunlu" });
    const p = await Post.create({ author: "KZAsistan", text: String(text) });
    res.json({ ok: true, id: p._id });
  } catch (e) {
    res.status(400).json({ error: e.message });
  }
});

// --- index.html servis (kökte, public klasörü yok) ---
const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
app.get("/", (req, res) => {
  res.sendFile(path.join(__dirname, "index.html"));
});

// --- Başlat ---
app.listen(PORT, () => {
  console.log(`🚀 KZMedia ayakta: http://localhost:${PORT}`);
});
