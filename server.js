// KZMedia - PROD Backend (MongoDB Atlas, separate auth + retry)
// Gerekli ENV (Render → Settings → Environment):
// MONGO_HOST=kzcluster.cjxpbq3.mongodb.net
// MONGO_USER=KZMedia                // Atlas Database Access'teki DB User (CASE-SENSITIVE)
// MONGO_PASS=ParolanHarfRakam       // Atlas'ta Reset Password ile verdiğin şifre
// DB_NAME=kzmedia
// JWT_KEY=kzmedia-ProdSecret-2025!! // uzun gizli anahtar

const express = require("express");
const mongoose = require("mongoose");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const helmet = require("helmet");
const cors = require("cors");
const rateLimit = require("express-rate-limit");
const path = require("path");

const app = express();
const PORT = process.env.PORT || 8080;
const JWT_KEY = process.env.JWT_KEY || "dummy-secret-key";

// Güvenlik / middleware
app.set("trust proxy", 1);
app.use(helmet({ contentSecurityPolicy: false }));
app.use(cors());
app.use(express.json({ limit: "1mb" }));

// Rate limit
app.use("/api/auth", rateLimit({ windowMs: 10 * 60 * 1000, max: 60 }));
app.use("/api", rateLimit({ windowMs: 60 * 1000, max: 120 }));

/* ---------------- MONGO (retry) ---------------- */
const HOST = (process.env.MONGO_HOST || "").trim();
const USER = (process.env.MONGO_USER || "").trim();
const PASS = process.env.MONGO_PASS ?? "";
const DB   = (process.env.DB_NAME || "kzmedia").trim();

const baseUri = HOST ? `mongodb+srv://${HOST}/?retryWrites=true&w=majority` : null;
let mongoReady = false;

async function connectMongo() {
  if (!baseUri) return;
  try {
    await mongoose.connect(baseUri, {
      dbName: DB,
      user: USER,
      pass: PASS,
      authSource: "admin",
      authMechanism: "SCRAM-SHA-256",
      serverSelectionTimeoutMS: 15000
    });
    mongoReady = true;
    console.log("✅ MongoDB Atlas bağlandı");
  } catch (err) {
    mongoReady = false;
    console.error("❌ MongoDB bağlantı hatası:", err.message);
  }
}
connectMongo();
setInterval(() => { if (!mongoReady) connectMongo(); }, 10000);

/* ---------------- MODELLER ---------------- */
const { Schema, model } = mongoose;
const User = model("User", new Schema({
  username: { type: String, unique: true, required: true },
  email: { type: String, unique: true, sparse: true },
  passwordHash: { type: String, required: true },
  roles: { type: [String], default: [] },
  followers: { type: Number, default: 0 },
  meta: { type: Object, default: {} }
}, { timestamps: true }));

const Post = model("Post", new Schema({
  author: { type: Schema.Types.ObjectId, ref: "User", required: true },
  text: { type: String, required: true, maxlength: 500 },
  imageUrl: { type: String, default: "" },
  videoUrl: { type: String, default: "" },
  private: { type: Boolean, default: false },
  likes: [{ type: Schema.Types.ObjectId, ref: "User" }]
}, { timestamps: true }));

/* ---------------- YARDIMCI ---------------- */
function signToken(id){ return jwt.sign({ userId:id }, JWT_KEY, { expiresIn:"7d" }); }
function requireAuth(req,res,next){
  const t=(req.headers.authorization||"").replace(/^Bearer\s+/i,"");
  if(!t) return res.status(401).json({error:"Oturum gerekli"});
  try{ req.userId=jwt.verify(t,JWT_KEY).userId; next(); }
  catch{ return res.status(401).json({error:"Token geçersiz"}); }
}

/* ---------------- HEALTH ---------------- */
app.get("/health",(req,res)=>{
  const states=["disconnected","connected","connecting","disconnecting"];
  res.json({ ok:true, db:states[mongoose.connection.readyState]||"unknown" });
});
app.get("/db/check",(req,res)=>{
  res.json({ ok: mongoose.connection.readyState===1, state: mongoose.connection.readyState });
});

/* ---------------- AUTH ---------------- */
app.post("/api/auth/register", async (req,res)=>{
  try{
    const { username, email, password, ownerCode }=req.body||{};
    if(!username||!password) return res.status(400).json({error:"Eksik alan"});
    const exists=await User.findOne({$or:[{username},{email}]});
    if(exists) return res.status(409).json({error:"Kullanıcı var"});
    const hash=await bcrypt.hash(password,10);
    const roles= ownerCode==="0" ? ["ADMIN","KUZILER"] : [];
    const u=await User.create({username,email,passwordHash:hash,roles});
    res.status(201).json({id:u._id,username:u.username,roles:u.roles});
  }catch(e){res.status(500).json({error:e.message});}
});

app.post("/api/auth/login", async (req,res)=>{
  try{
    const { usernameOrEmail, password }=req.body||{};
    const u=await User.findOne({$or:[{username:usernameOrEmail},{email:usernameOrEmail}]});
    if(!u) return res.status(401).json({error:"Kullanıcı yok"});
    const ok=await bcrypt.compare(password,u.passwordHash);
    if(!ok) return res.status(401).json({error:"Şifre hatalı"});
    const token=signToken(u._id);
    res.json({token,user:{id:u._id,username:u.username,roles:u.roles,followers:u.followers}});
  }catch(e){res.status(500).json({error:e.message});}
});

/* ---------------- POSTS ---------------- */
app.post("/api/posts", requireAuth, async (req,res)=>{
  try{
    const {text,imageUrl,videoUrl,private:isPrivate}=req.body||{};
    if(!text) return res.status(400).json({error:"Metin gerekli"});
    const p=await Post.create({author:req.userId,text,imageUrl,videoUrl,private:!!isPrivate});
    const populated=await p.populate("author","username roles");
    res.status(201).json(populated);
  }catch(e){res.status(500).json({error:e.message});}
});

app.get("/api/posts/feed", requireAuth, async (req,res)=>{
  try{
    const posts=await Post.find().sort({createdAt:-1}).limit(50).populate("author","username roles");
    res.json(posts);
  }catch(e){res.status(500).json({error:e.message});}
});

/* ---------------- Statik index.html ---------------- */
app.get("/",(req,res)=>{ res.sendFile(path.join(__dirname,"index.html")); });

/* ---------------- START ---------------- */
app.listen(PORT,"0.0.0.0",()=>console.log(`🚀 KZMedia API: http://localhost:${PORT}`));
