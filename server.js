import express from "express";
import mongoose from "mongoose";
import path from "path";
import { fileURLToPath } from "url";
import cors from "cors";
import dotenv from "dotenv";

dotenv.config();
const app = express();
const PORT = process.env.PORT || 3000;

// MongoDB bağlantısı
mongoose.connect(process.env.MONGO_URI, {
  useNewUrlParser: true,
  useUnifiedTopology: true
}).then(() => console.log("✅ MongoDB bağlandı"))
  .catch(err => console.error("❌ MongoDB bağlantı hatası:", err));

// Gönderi şeması
const postSchema = new mongoose.Schema({
  author: String,
  text: String,
  createdAt: { type: Date, default: Date.now },
  likes: { type: Number, default: 0 }
});
const Post = mongoose.model("Post", postSchema);

app.use(cors());
app.use(express.json());

// Güvenlik başlıkları (WebLLM için şart)
app.use((req, res, next) => {
  res.setHeader("Cross-Origin-Opener-Policy", "same-origin");
  res.setHeader("Cross-Origin-Embedder-Policy", "require-corp");
  next();
});

// Public klasörü
const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
app.use(express.static(path.join(__dirname, "public")));

// Sağlık kontrolü
app.get("/api/health", (req, res) => res.json({ ok: true, name: "KZMedia+KZAsistan" }));

// Gönderiler
app.post("/api/posts", async (req, res) => {
  try {
    const post = new Post(req.body);
    await post.save();
    res.json(post);
  } catch (err) {
    res.status(400).json({ error: err.message });
  }
});

app.get("/api/posts", async (req, res) => {
  const posts = await Post.find().sort({ createdAt: -1 });
  res.json(posts);
});

app.listen(PORT, () => console.log(`🚀 Sunucu http://localhost:${PORT}`));
