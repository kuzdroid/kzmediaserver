// server.js — KZMedia + KZAsistan (statik servis) v1.0.2
const express = require("express");
const path = require("path");
const app = express();

const PORT = process.env.PORT || 3000;

app.use(express.static(path.join(__dirname, "public")));

app.get("/api/health", (req, res) => {
  res.json({ ok: true, app: "KZMedia+KZAsistan", version: "1.0.2" });
});

app.get("/", (req, res) => {
  res.sendFile(path.join(__dirname, "public", "index.html"));
});

// SPA fallback (api dışındaki tüm yollar index.html’e düşsün)
app.get("*", (req, res, next) => {
  if (req.path.startsWith("/api/")) return next();
  res.sendFile(path.join(__dirname, "public", "index.html"));
});

app.listen(PORT, () => {
  console.log(`🚀 KZMedia+KZAsistan çalışıyor: http://localhost:${PORT}`);
});
