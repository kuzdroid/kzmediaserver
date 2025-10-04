const express = require("express");
const path = require("path");
const mongoose = require("mongoose");
const cors = require("cors");

const app = express();
const PORT = process.env.PORT || 8080;
const MONGO_URL = process.env.MONGO_URL; // Render > Environment > MONGO_URL

// Orijin: herkes GET yapsın diye basit cors (gerekirse kısıtlayabilirsin)
app.use(cors());
app.use(express.json({ limit: "1mb" }));

// --- Mongo bağlan ---
if (!MONGO_URL) {
  console.warn("UYARI: MONGO_URL tanımlı değil. /api/state çağrıları çalışmaz.");
} else {
  mongoose
    .connect(MONGO_URL, { dbName: "kzmedia" })
    .then(() => console.log("MongoDB bağlı ✅"))
    .catch((e) => console.error("MongoDB bağlantı hatası:", e));
}

// Tek bir belgeye tüm state'i koyacağız (users, posts, ad)
const stateSchema = new mongoose.Schema(
  {
    key: { type: String, unique: true },
    data: { type: Object, default: { users: {}, posts: [], ad: "" } }
  },
  { timestamps: true }
);
const State = mongoose.models.State || mongoose.model("State", stateSchema);

// Sağlık kontrolü
app.get("/health", (req, res) => res.json({ ok: true }));

// Buluttaki state'i getir (yoksa default döner)
app.get("/api/state", async (req, res) => {
  try {
    if (!MONGO_URL) return res.status(503).json({ error: "DB yok" });
    let doc = await State.findOne({ key: "global" });
    if (!doc) {
      doc = await State.create({ key: "global", data: { users: {}, posts: [], ad: "" } });
    }
    res.json(doc.data);
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: "Sunucu hatası" });
  }
});

// Bulut state'ini tamamen kaydet (frontend tüm DATA'yı gönderir)
app.post("/api/state", async (req, res) => {
  try {
    if (!MONGO_URL) return res.status(503).json({ error: "DB yok" });
    const incoming = req.body; // { users, posts, ad }
    if (!incoming || typeof incoming !== "object") {
      return res.status(400).json({ error: "Geçersiz gövde" });
    }
    const doc = await State.findOneAndUpdate(
      { key: "global" },
      { $set: { data: incoming } },
      { upsert: true, new: true }
    );
    res.json({ ok: true, updatedAt: doc.updatedAt });
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: "Sunucu hatası" });
  }
});

// index.html'i kökten servis et
app.get("/", (req, res) => {
  res.sendFile(path.join(__dirname, "index.html"));
});

// SPA tarzı: diğer GET isteklerini de index.html'e yönlendir (opsiyonel)
app.get("*", (req, res) => {
  res.sendFile(path.join(__dirname, "index.html"));
});

app.listen(PORT, "0.0.0.0", () => {
  console.log(`KZMedia backend ayakta: http://localhost:${PORT}`);
});
