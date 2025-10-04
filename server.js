const express = require("express");
const path = require("path");

const app = express();
const PORT = process.env.PORT || 8080;

// Kök dizindeki index.html dosyasını gönder
app.get("/", (req, res) => {
  res.sendFile(path.join(__dirname, "index.html"));
});

// Sağlık kontrolü (isteğe bağlı)
app.get("/health", (req, res) => {
  res.status(200).json({ ok: true });
});

// Diğer tüm yolları index.html'e yönlendir (SPA gibi çalışsın)
app.get("*", (req, res) => {
  res.sendFile(path.join(__dirname, "index.html"));
});

// Sunucuyu başlat
app.listen(PORT, "0.0.0.0", () => {
  console.log(`KZMedia sunucusu çalışıyor: http://localhost:${PORT}`);
});
