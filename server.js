const express = require("express");
const path = require("path");

const app = express();
const PORT = process.env.PORT || 8080;

// Senin verdiğin HTML dosyasını string olarak değil, ayrı bir dosya olarak sunacağız.
// Bu yüzden index.html diye kaydedeceğiz.
app.get("/", (req, res) => {
  res.sendFile(path.join(__dirname, "index.html"));
});

app.listen(PORT, () => {
  console.log(`KZMedia çalışıyor: http://localhost:${PORT}`);
});
