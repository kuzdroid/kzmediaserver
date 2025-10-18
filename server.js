const express = require("express");
const mongoose = require("mongoose");
const cors = require("cors");
const bodyParser = require("body-parser");
const jwt = require("jsonwebtoken");
const bcrypt = require("bcryptjs");
const path = require("path");

const app = express();
const PORT = process.env.PORT || 10000;
const JWT_KEY = process.env.JWT_KEY || "supersecret";
const MONGO_URL = process.env.MONGO_URL || "mongodb://127.0.0.1:27017/kzmedia";

app.use(cors());
app.use(bodyParser.json());

// === Mongo Modelleri ===
const UserSchema = new mongoose.Schema({
  username: { type: String, unique: true },
  password: String
});
const PostSchema = new mongoose.Schema({
  author: String,
  text: String,
  imageUrl: String,
  videoUrl: String,
  private: Boolean,
  createdAt: { type: Date, default: Date.now }
});
const User = mongoose.model("User", UserSchema);
const Post = mongoose.model("Post", PostSchema);

// === Auth Middleware ===
function auth(req, res, next){
  const authHeader = req.headers["authorization"];
  if(!authHeader) return res.status(401).json({error:"No token"});
  const token = authHeader.split(" ")[1];
  try{
    const decoded = jwt.verify(token, JWT_KEY);
    req.user = decoded;
    next();
  }catch(err){
    return res.status(401).json({error:"Invalid token"});
  }
}

// === API ===
app.get("/api/health",(req,res)=>res.json({ok:true,name:"KZMedia API"}));

app.post("/api/auth/register", async (req,res)=>{
  try{
    const { username, password } = req.body;
    if(!username||!password) return res.status(400).json({error:"Eksik alan"});
    const hash = await bcrypt.hash(password,10);
    const user = new User({username,password:hash});
    await user.save();
    res.json({ok:true});
  }catch(err){
    res.status(400).json({error:"Kayıt başarısız: "+err.message});
  }
});

app.post("/api/auth/login", async (req,res)=>{
  const { username, password } = req.body;
  const user = await User.findOne({username});
  if(!user) return res.status(400).json({error:"Kullanıcı yok"});
  const ok = await bcrypt.compare(password,user.password);
  if(!ok) return res.status(400).json({error:"Şifre yanlış"});
  const token = jwt.sign({id:user._id,username:user.username},JWT_KEY);
  res.json({ok:true,user,token});
});

app.post("/api/posts", auth, async (req,res)=>{
  const { text,imageUrl,videoUrl,private } = req.body;
  const post = new Post({author:req.user.username,text,imageUrl,videoUrl,private});
  await post.save();
  res.json(post);
});

app.get("/api/posts/feed", auth, async (req,res)=>{
  const posts = await Post.find().sort({createdAt:-1}).limit(50);
  res.json(posts);
});

// === index.html doğrudan gönder ===
app.get("/", (req,res)=>{
  res.sendFile(path.join(__dirname,"index.html"));
});

// === MongoDB Connect ===
mongoose.connect(MONGO_URL)
.then(()=>{ app.listen(PORT,()=>console.log(`🚀 Sunucu http://localhost:${PORT}`)); })
.catch(err=>console.error("❌ MongoDB bağlantı hatası:",err));
