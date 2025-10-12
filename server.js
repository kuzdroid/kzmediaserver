// server.js
const express = require("express");
const path = require("path");

const app = express();
const PORT = process.env.PORT || 3000;

// JSON verisi işlemek için
app.use(express.json());

// Ana sayfa (index.html) direkt kökten servis edilir
app.get("/", (req, res) => {
  res.sendFile(path.join(__dirname, "index.html"));
});

// Basit bir API örneği (KZAsistan için cevap dönsün)
app.post("/api/ask", (req, res) => {
  const { question } = req.body;

  // Basit cevap sistemi (API'siz, yapay zekasız)
  let answer = "Bunu bilmiyorum ama araştırabilirsin 🙂";

  if (question.toLowerCase().includes("merhaba")) {
    answer = "Merhaba! Ben KZAsistan 🚀";
  }
  if (question.toLowerCase().includes("2+2")) {
    answer = "2 + 2 = 4 ✅";
  }

  res.json({ reply: answer });
});

// Server başlat
app.listen(PORT, () => {
  console.log(`🚀 Sunucu http://localhost:${PORT} adresinde çalışıyor`);
});
