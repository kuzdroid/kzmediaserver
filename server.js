// KZMedia - Basit Sunucu (Mongo YOK)
// Tek amacı: index.html dosyanı Render üzerinde herkese açmak.

const express = require("express");
const path = require("path");

const app = express();
const PORT = process.env.PORT || 8080;

// Health kontrolü (Render test için)
app.get("/health", (req, res) => {
  res.json({ ok: true });
});

// Kök dizindeki index.html’i herkese gönder
app.get("/", (req, res) => {
  res.sendFile(path.join(__dirname, "index.html"));
});

// Public static dosyaları (örn. css, js) da servis et
app.use(express.static(__dirname));

app.listen(PORT, "0.0.0.0", () => {
  console.log(`🚀 KZMedia Mongo'suz sunucu ayakta: http://localhost:${PORT}`);
});

