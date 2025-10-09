// KZMedia – Prod API (Mongo Atlas) + IP-bazlı Like/Follow Toggle
// ENV (Render → Environment):
//   JWT_KEY   = bir-uzun-gizli-anahtar
//   MONGO_URL = mongodb+srv://USER:PASS@HOST/DBNAME?retryWrites=true&w=majority
// (veya 4'lü: MONGO_HOST, MONGO_USER, MONGO_PASS, DB_NAME)

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
const JWT_KEY = (process.env.JWT_KEY || "dummy-secret-kzmedia").trim();

app.set("trust proxy", 1);
app.use(helmet({ contentSecurityPolicy: false }));
app.use(cors());
app.use(express.json({ limit: "1mb" }));

app.use("/api/auth", rateLimit({ windowMs: 10 * 60 * 1000, max: 80 }));
app.use("/api", rateLimit({ windowMs: 60 * 1000, max: 240 }));

/* ---------- Mongo ---------- */
const MONGO_URL = (process.env.MONGO_URL || "").trim();
const HOST = (process.env.MONGO_HOST || "").trim();
const USER = (process.env.MONGO_USER || "").trim();
const PASS = (process.env.MONGO_PASS ?? "").trim();
const DB   = (process.env.DB_NAME || "kzmedia").trim();

function partsUri() { return HOST ? `mongodb+srv://${HOST}/?retryWrites=true&w=majority` : null; }

let mongoReady = false;
async function connectMongo(){
  try{
    if(MONGO_URL){
      await mongoose.connect(MONGO_URL, { serverSelectionTimeoutMS: 15000 });
      console.log("✅ Mongo bağlandı (MONGO_URL)");
    }else{
      const uri = partsUri();
      if(!uri || !USER || PASS==="") throw new Error("Mongo ENV eksik");
      await mongoose.connect(uri, {
        dbName: DB, user: USER, pass: PASS,
        authSource: "admin", authMechanism: "SCRAM-SHA-256",
        serverSelectionTimeoutMS: 15000
      });
      console.log("✅ Mongo bağlandı (separate creds)");
    }
    mongoReady = true;
  }catch(e){
    mongoReady = false;
    console.error("❌ MongoDB bağlantı hatası:", e.message);
    setTimeout(connectMongo, 10000);
  }
}
connectMongo();

/* ---------- Modeller ---------- */
const { Schema, model } = mongoose;

const User = model("User", new Schema({
  username: { type: String, unique: true, required: true, minlength: 3, maxlength: 32 },
  email: { type: String, unique: true, sparse: true },
  passwordHash: { type: String, required: true },
  roles: { type: [String], default: [] },      // ["ADMIN","KUZILER"]
  followers: { type: Number, default: 0 },     // görünen sayı
  followersIp: { type: [String], default: [] } // IP-bazlı takip
},{timestamps:true}));

const Post = model("Post", new Schema({
  author: { type: Schema.Types.ObjectId, ref: "User", required: true },
  text:   { type: String, required: true, maxlength: 500 },
  imageUrl: { type: String, default: "" },
  videoUrl: { type: String, default: "" },
  private:  { type: Boolean, default: false }, // @KUZILER
  likesIp:  { type: [String], default: [] }    // IP-bazlı like
},{timestamps:true}));

/* ---------- Yardımcı ---------- */
function signToken(id){ return jwt.sign({ userId:id }, JWT_KEY, { expiresIn:"7d" }); }
function requireAuth(req,res,next){
  const t=(req.headers.authorization||"").replace(/^Bearer\s+/i,"");
  if(!t) return res.status(401).json({error:"Oturum gerekli"});
  try{ req.userId=jwt.verify(t,JWT_KEY).userId; next(); }
  catch{ return res.status(401).json({error:"Token geçersiz"}); }
}
function getIp(req){
  const xf=(req.headers["x-forwarded-for"]||"").toString().split(",")[0].trim();
  return xf || req.ip || req.connection?.remoteAddress || "0.0.0.0";
}

/* ---------- Health ---------- */
app.get("/health",(req,res)=>{
  const states=["disconnected","connected","connecting","disconnecting"];
  res.json({ ok:true, db: states[mongoose.connection.readyState]||"unknown" });
});

/* ---------- Auth ---------- */
app.post("/api/auth/register", async (req,res)=>{
  if(!mongoReady) return res.status(503).json({error:"DB hazır değil"});
  try{
    let { username, email, password, ownerCode } = req.body||{};
    if(!username || !password) return res.status(400).json({error:"Eksik alanlar"});
    username=String(username).trim();
    const dupe=await User.findOne({ $or:[{username},{email}] });
    if(dupe) return res.status(409).json({error:"Kullanıcı adı/eposta kullanımda"});
    const passwordHash = await bcrypt.hash(password,10);
    const roles = ownerCode==="0" ? ["ADMIN","KUZILER"] : [];
    const u = await User.create({ username, email, passwordHash, roles });
    res.status(201).json({ id:u._id, username:u.username, roles:u.roles });
  }catch(e){ res.status(500).json({error:e.message}); }
});

app.post("/api/auth/login", async (req,res)=>{
  if(!mongoReady) return res.status(503).json({error:"DB hazır değil"});
  try{
    const { usernameOrEmail, password } = req.body||{};
    if(!usernameOrEmail || !password) return res.status(400).json({error:"Eksik alanlar"});
    const u = await User.findOne({ $or:[{username:usernameOrEmail},{email:usernameOrEmail}] });
    if(!u) return res.status(401).json({error:"Kullanıcı bulunamadı"});
    const ok = await bcrypt.compare(password,u.passwordHash);
    if(!ok) return res.status(401).json({error:"Şifre hatalı"});
    const token=signToken(u._id);
    res.json({ token, user:{ id:u._id, username:u.username, roles:u.roles, followers:u.followers } });
  }catch(e){ res.status(500).json({error:e.message}); }
});

app.get("/api/auth/me", requireAuth, async (req,res)=>{
  if(!mongoReady) return res.status(503).json({error:"DB hazır değil"});
  const u=await User.findById(req.userId).select("username roles followers");
  res.json(u);
});

/* ---------- Postlar ---------- */
app.post("/api/posts", requireAuth, async (req,res)=>{
  if(!mongoReady) return res.status(503).json({error:"DB hazır değil"});
  try{
    const { text, imageUrl, videoUrl, private:isPrivate } = req.body||{};
    if(!text || !String(text).trim()) return res.status(400).json({error:"Metin gerekli"});
    const p = await Post.create({
      author:req.userId, text:String(text).trim(),
      imageUrl:imageUrl||"", videoUrl:videoUrl||"", private:!!isPrivate
    });
    const populated = await p.populate("author","username roles");
    res.status(201).json(populated);
  }catch(e){ res.status(500).json({error:e.message}); }
});

app.get("/api/posts/feed", requireAuth, async (req,res)=>{
  if(!mongoReady) return res.status(503).json({error:"DB hazır değil"});
  try{
    const limit=Math.min(parseInt(req.query.limit)||50,100);
    const me = await User.findById(req.userId).select("roles");
    const isK = !!(me && me.roles && me.roles.includes("KUZILER"));
    const posts = await Post.find().sort({createdAt:-1}).limit(limit).populate("author","username roles");
    const filtered = posts.filter(p=>!p.private || isK || String(p.author._id)===String(req.userId));
    res.json(filtered.map(p=>({ ...p.toObject(), likesCount: p.likesIp.length })));
  }catch(e){ res.status(500).json({error:e.message}); }
});

/* ---------- Like (IP toggle, auth gerekmez) ---------- */
app.post("/api/posts/:id/like", async (req,res)=>{
  if(!mongoReady) return res.status(503).json({error:"DB hazır değil"});
  try{
    const post=await Post.findById(req.params.id);
    if(!post) return res.status(404).json({error:"Gönderi yok"});
    const ip=getIp(req);
    const i=post.likesIp.indexOf(ip);
    const liked = i===-1;
    if(liked) post.likesIp.push(ip); else post.likesIp.splice(i,1);
    await post.save();
    res.json({ liked, likes: post.likesIp.length });
  }catch(e){ res.status(500).json({error:e.message}); }
});

/* ---------- Follow (IP toggle, auth gerekmez) ---------- */
app.post("/api/users/:username/follow", async (req,res)=>{
  if(!mongoReady) return res.status(503).json({error:"DB hazır değil"});
  try{
    const u=await User.findOne({ username:req.params.username });
    if(!u) return res.status(404).json({error:"Kullanıcı yok"});
    const ip=getIp(req);
    const i=u.followersIp.indexOf(ip);
    const following = i===-1;
    if(following) u.followersIp.push(ip); else u.followersIp.splice(i,1);
    u.followers=u.followersIp.length;
    await u.save();
    res.json({ following, followers:u.followers });
  }catch(e){ res.status(500).json({error:e.message}); }
});

/* ---------- Statik ---------- */
app.get("/", (req,res)=> res.sendFile(path.join(__dirname,"index.html")));

/* ---------- Start ---------- */
app.listen(PORT,"0.0.0.0",()=>console.log(`🚀 KZMedia API ayakta: http://localhost:${PORT}`));
