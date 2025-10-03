// Node.js'in yerleşik http modülünü CommonJS (require) ile dahil et
const http = require('http'); 

// Render'dan gelen PORT ortam değişkenini kullan, yoksa 8080 varsay
const PORT = process.env.PORT || 8080;

// *** DİKKAT ***
// HTML içeriğiniz burada bir JavaScript template string'i olarak tanımlanır.
// Bu kısım HİÇ DEĞİŞTİRİLMEMİŞTİR.
const html = `<!doctype html>
<html lang="tr">
<head>
<meta charset="utf-8"/>
<meta name="viewport" content="width=device-width,initial-scale=1"/>
<title>KZMedia • Tek Dosya (Yerel Demo)</title>
<style>
:root{--bg:#0b0c10;--card:#11131a;--text:#e8eaed;--muted:#a3a7b0;--primary:#4f8cff;--accent:#64d2ff;--danger:#ff5c74;--border:#212532}
*{box-sizing:border-box}
body{margin:0;font-family:system-ui,Segoe UI,Roboto,Arial;background:var(--bg);color:var(--text)}
.header{display:flex;justify-content:space-between;align-items:center;padding:12px 16px;background:var(--card);border-bottom:1px solid var(--border)}
.container{max-width:1100px;margin:18px auto;padding:0 16px;display:grid;grid-template-columns:1fr;gap:12px}
@media(min-width:900px){.container{grid-template-columns:1fr 320px}}
.card{background:var(--card);border:1px solid var(--border);border-radius:12px;padding:12px}
input,textarea,select{width:100%;padding:8px;border-radius:8px;border:1px solid var(--border);background:#0e1016;color:var(--text);outline:none}
button{padding:8px 10px;border-radius:8px;border:none;cursor:pointer}
.btn-primary{background:var(--primary);color:#fff}
.btn-danger{background:var(--danger);color:#fff}
.small{font-size:13px;color:var(--muted)}
.feed .post{margin-top:12px;padding:12px;border-radius:10px;border:1px solid var(--border);background:linear-gradient(180deg,rgba(255,255,255,0.01),transparent)}
.post .meta{display:flex;justify-content:space-between;align-items:center}
.post img,.post video{max-width:100%;border-radius:8px;margin-top:8px}
.tag{background:var(--primary);color:#fff;padding:3px 8px;border-radius:999px;font-size:12px;margin-left:8px}
.controls{display:flex;gap:8px;flex-wrap:wrap;margin-top:8px}
.notice{padding:8px;border-radius:8px;background:#122;color:#9fdf;margin-top:8px}
.admin-badge{background:#222;border-radius:6px;padding:4px 8px;font-size:12px;color:var(--accent)}
.row{display:flex;gap:8px;align-items:center;margin-top:4px}
.field-inline{flex:1}
.footer{font-size:12px;color:var(--muted);text-align:center;margin-top:12px}
.small-muted{font-size:12px;color:var(--muted)}
.user-row button{padding:4px 8px;font-size:12px;}
</style>
</head>
<body>
<div class="header">
  <div style="font-weight:800">KZMedia</div>
  <div class="small-muted">Tam demo (yerel). Veriler localStorage'da.</div>
</div>
<main class="container">
    <section class="card">
    <div id="topArea">
      <div id="authBox">
        <h3>Giriş / Kayıt</h3>
        <div class="row">
          <input id="txtUser" placeholder="Kullanıcı adı (boş olamaz)" class="field-inline">
          <input id="txtPass" placeholder="Şifre" class="field-inline" type="password">
        </div>
        <div class="row" style="margin-top:8px">
          <button id="btnRegister" class="btn-primary">Kayıt Ol</button>
          <button id="btnLogin">Giriş</button>
        </div>
        <div class="small-muted" style="margin-top:8px">
          Sahip kodu (owner key) yerel olarak <code>OWNER_CODE</code> ile kontrol edilir. Varsayılan: "0".
        </div>
      </div>
      <div id="composeBox" style="display:none;margin-top:12px">
        <h3>Paylaş</h3>
        <textarea id="postText" rows="3" placeholder="Ne paylaşmak istersin?"></textarea>
        <input id="postImage" placeholder="Resim URL (opsiyonel)">
        <input id="postVideo" placeholder="Video URL (opsiyonel)">
        <label style="display:block;margin-top:6px">
          <input id="postPrivate" type="checkbox"> 
          <span class="small">@kuzilerözel (yalnızca @KUZILER üyeleri görebilir)</span>
        </label>
        <div class="controls">
          <button id="btnPost" class="btn-primary">Paylaş</button>
          <button id="btnRefresh">Yenile</button>
        </div>
      </div>
    </div>
    <hr>
    <h3>Akış</h3>
    <div id="feed" class="feed"></div>
    <div id="empty" class="notice" style="display:none">Henüz gönderi yok.</div>
    <div class="footer">KZMedia • Yerel demo</div>
  </section>

    <aside class="card">
    <div>
      <div class="small">Şu anki kullanıcı: <strong id="meName">—</strong> <span id="meBadge"></span></div>
      <div class="small-muted" style="margin-top:6px">Takipçi: <strong id="meFollowers">0</strong></div>
      <div style="margin-top:8px" id="authButtons"></div>
    </div>
    <hr>
    <div id="adminPanel" style="display:none">
      <h4>Admin Paneli</h4>
      <div class="small-muted">Burada adminler duyuru (ilan), kullanıcı rolleri ve takipçi sayısını düzenleyebilir. Ayrıca kullanıcıları admin yapabilirsiniz.</div>
      <div style="margin-top:8px">
        <label>Duyuru / İlan (tek tane)</label>
        <textarea id="adminAd" rows="3" placeholder="Kısa ilan/duyuru"></textarea>
        <div style="margin-top:8px" class="row">
          <button id="btnSaveAd" class="btn-primary">Duyuruyu Kaydet</button>
          <button id="btnClearAd">Temizle</button>
        </div>
      </div>
      <hr>
      <div>
        <h4>Kullanıcıları Yönet</h4>
        <div id="userList"></div>
      </div>
      <hr>
      <div>
        <label>Kullanıcı takipçi sayısını değiştir</label>
        <div class="row" style="margin-top:6px">
          <input id="adminUserFollowers" placeholder="kullaniciadi" class="field-inline">
          <input id="adminFollowerCount" placeholder="yeni sayı" style="width:90px">
        </div>
        <div style="margin-top:8px">
          <button id="btnSetFollowers" class="btn-primary">Uygula</button>
        </div>
      </div>
    </div>
    <div id="adBox" style="margin-top:12px"></div>
  </aside>
</main>

<script>
const OWNER_CODE = "0"; // owner kodu
let DATA = loadData();
const $ = id=>document.getElementById(id);

function loadData(){
  const raw = localStorage.getItem('KZMedia.data');
  if(!raw) return { users:{}, posts:[], ad:"" };
  try{ return JSON.parse(raw);}catch(e){return { users:{}, posts:[], ad:"" };}
}

function saveData(){ localStorage.setItem('KZMedia.data',JSON.stringify(DATA)); }
function setMe(name){
  if(!name){
    window._ME=null;
    $('meName').textContent='—';
    $('meBadge').textContent='';
    $('meFollowers').textContent='0';
  }else{
    window._ME={name};
    const u = DATA.users[name];
    const isAdmin = u.roles && u.roles.indexOf('ADMIN')>=0;
    const isK = u.roles && u.roles.indexOf('KUZILER')>=0;
    $('meName').textContent=name;
    $('meBadge').textContent= isAdmin ? ' <span class="admin-badge">ADMIN</span>' : (isK ? ' <span class="small-muted">@KUZILER</span>' : '');
    $('meFollowers').textContent=u.followers||0;
  }
  renderAuthUI();
  loadFeed();
  renderAd();
  addAuthButtons();
  renderUsers();
}

function renderAuthUI(){
  if(window._ME){ $('composeBox').style.display='block'; $('authBox').style.display='none'; }
  else { $('composeBox').style.display='none'; $('authBox').style.display='block'; }

  const meName = window._ME?.name;
  if(meName && DATA.users[meName] && DATA.users[meName].roles && DATA.users[meName].roles.indexOf('ADMIN')>=0){
    $('adminPanel').style.display='block';
  }else{
    $('adminPanel').style.display='none';
  }
}

// --- Register / Login
$('btnRegister').addEventListener('click',()=>{
  const name = $('txtUser').value.trim();
  const pass = $('txtPass').value;
  if(!name){ alert('Kullanıcı adı girin'); return;}
  if(DATA.users[name]){ alert('Bu kullanıcı adı zaten var'); return;}
  DATA.users[name]={ pass:pass||'', roles:[], followers:0 };
  if(pass===OWNER_CODE){ DATA.users[name].roles.push('ADMIN'); DATA.users[name].roles.push('KUZILER'); }
  saveData();
  alert('Kayıt tamam. Giriş yapabilirsiniz.');
});

$('btnLogin').addEventListener('click',()=>{
  const name = $('txtUser').value.trim();
  const pass = $('txtPass').value;
  if(!name){ alert('Kullanıcı adı girin'); return;}
  const u = DATA.users[name];
  if(!u){ alert('Kullanıcı bulunamadı. Kayıt olun.'); return;}
  if(u.pass!==pass){ alert('Şifre yanlış'); return;}
  setMe(name);
});

// logout / profil
function addAuthButtons(){
  const box=$('authButtons'); box.innerHTML='';
  if(window._ME){
    const btnLogout=document.createElement('button'); btnLogout.textContent='Çıkış';
    btnLogout.onclick=()=>setMe(null);
    const btnProfile=document.createElement('button'); btnProfile.textContent='Profilim';
    btnProfile.onclick=()=>alert('Profil: '+window._ME.name);
    box.appendChild(btnProfile); box.appendChild(btnLogout);
  }
}

// --- Posts
$('btnPost').addEventListener('click',()=>{
  if(!window._ME){ alert('Önce giriş yapın'); return;}
  const text = $('postText').value.trim();
  if(!text){ alert('Metin boş olamaz'); return;}
  const p={ id:Date.now().toString(36)+Math.random().toString(36).slice(2,8),
            author:window._ME.name,
            text,
            imageUrl:$('postImage').value.trim()||null,
            videoUrl:$('postVideo').value.trim()||null,
            private:!!$('postPrivate').checked,
            likes:0,
            createdAt:Date.now() };
  DATA.posts.push(p);
  saveData();
  $('postText').value=''; $('postImage').value=''; $('postVideo').value=''; $('postPrivate').checked=false;
  loadFeed();
});

function loadFeed(){
  const feed = $('feed'); feed.innerHTML='';
  const q = $('q')?.value.trim().toLowerCase()||'';
  const list = (DATA.posts||[]).slice().sort((a,b)=>(b.createdAt||0)-(a.createdAt||0));
  let shown=0;
  for(const p of list){
    if(p.private){
      const me=window._ME?DATA.users[window._ME.name]:null;
      const isMember = me && me.roles && me.roles.indexOf('KUZILER')>=0;
      if(!isMember && !(window._ME && window._ME.name===p.author)) continue;
    }
    if(q && !((p.text||'').toLowerCase().includes(q) || (p.author||'').toLowerCase().includes(q))) continue;
    const div=document.createElement('div'); div.className='post';
    const isAdmin = window._ME && DATA.users[window._ME.name] && DATA.users[window._ME.name].roles && DATA.users[window._ME.name].roles.indexOf('ADMIN')>=0;
    const canEdit = window._ME && (window._ME.name===p.author || isAdmin);
    const tag = (DATA.users[p.author] && DATA.users[p.author].roles && DATA.users[p.author].roles.indexOf('KUZILER')>=0) ? '<span class="tag">@KUZILER</span>':'';
    div.innerHTML = `<div class="meta"><div class="who">${escapeHtml(p.author)} ${tag}</div><div class="small">${new Date(p.createdAt).toLocaleString()}</div></div>
                     <div>${escapeHtml(p.text)}</div>
                     ${p.imageUrl?`<div><img src="${escapeHtml(p.imageUrl)}" alt=""></div>`:''}
                     ${p.videoUrl?`<div><video controls src="${escapeHtml(p.videoUrl)}"></video></div>`:''}
                     <div style="margin-top:8px" class="row">
                       <button class="btn-like">❤ ${p.likes||0}</button>
                       ${canEdit?'<button class="btn-edit">Düzenle</button>':''}
                       ${canEdit?'<button class="btn-del">Sil</button>':''}
                     </div>`;
    feed.appendChild(div);
    shown++;
    div.querySelector('.btn-like')?.addEventListener('click',()=>{ p.likes=(p.likes||0)+1; saveData(); loadFeed(); });
    if(canEdit){
      div.querySelector('.btn-edit')?.addEventListener('click',()=>{ const newText=prompt('Yeni metin:',p.text); if(newText!==null){ p.text=newText; saveData(); loadFeed(); }});
      div.querySelector('.btn-del')?.addEventListener('click',()=>{ if(confirm('Gönderiyi silmek istiyor musunuz?')){ DATA.posts=DATA.posts.filter(x=>x.id!==p.id); saveData(); loadFeed(); }});
    }
  }
  $('empty').style.display=shown?'none':'block';
}

function escapeHtml(s=''){return String(s).replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;','\'':'&#39;'})[c]);}

// --- Admin Actions
$('btnSaveAd')?.addEventListener('click',()=>{ if(!checkAdmin()) return; DATA.ad=$('adminAd').value.trim(); saveData(); renderAd(); alert('Duyuru kaydedildi'); });
$('btnClearAd')?.addEventListener('click',()=>{ if(!checkAdmin()) return; DATA.ad=''; saveData(); renderAd(); });

// --- Set followers
$('btnSetFollowers')?.addEventListener('click',()=>{
  if(!checkAdmin()) return;
  const name=$('adminUserFollowers').value.trim(); const cnt=parseInt($('adminFollowerCount').value);
  if(!name || !DATA.users[name]) return alert('Kullanıcı bulunamadı');
  if(Number.isNaN(cnt)) return alert('Geçerli sayı girin');
  DATA.users[name].followers=cnt; saveData(); alert('Ayar kaydedildi');
  if(window._ME && window._ME.name===name) setMe(name);
});

// --- Render ad
function renderAd(){
  const box=$('adBox'); box.innerHTML='';
  if(DATA.ad && DATA.ad.trim()){ const d=document.createElement('div'); d.className='notice'; d.textContent=DATA.ad; box.appendChild(d); }
}

// --- Check admin
function checkAdmin(){ const me=window._ME && DATA.users[window._ME.name]; if(!me || !me.roles || me.roles.indexOf('ADMIN')<0){ alert('Sadece adminler yapabilir'); return false;} return true;}

// --- Render users for admin panel
function renderUsers(){
  const list=$('userList'); if(!list) return;
  list.innerHTML='';
  for(const name in DATA.users){
    const u=DATA.users[name];
    const div=document.createElement('div'); div.className='row user-row';
    const isAdmin = u.roles && u.roles.indexOf('ADMIN')>=0;
    const displayName = isAdmin?name+'@ADMIN':name;
    div.innerHTML=`<span>${displayName}</span> <button class="btn-primary btn-make-admin">Admin Yap</button>`;
    div.querySelector('.btn-make-admin').addEventListener('click',()=>{
      if(!checkAdmin()) return;
      if(!u.roles) u.roles=[];
      if(u.roles.indexOf('ADMIN')<0) u.roles.push('ADMIN');
      saveData(); renderUsers(); alert(displayName+' artık admin!');
    });
    list.appendChild(div);
  }
}

// startup
(function startup(){
  if(!DATA.users['owner']) DATA.users['owner']={pass:OWNER_CODE,roles:['ADMIN','KUZILER'],followers:0};
  saveData();
  setMe(null);
})();
</script>
</body>
</html>`;

const server = http.createServer((req, res) => {
  // Sadece tek sayfa: her istekte aynı HTML'i döndürüyoruz
  res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' });
  res.end(html);
});

// Port dinleme başlar ve olası hataları yakalar (Exited with status 1'i çözer)
server.listen(PORT, (err) => {
  if (err) {
    console.error(`❌ KRİTİK HATA: Port ${PORT} Dinlenemedi!`, err.message);
    // Sunucuyu kapat, hata kodunu loga yazdır
    process.exit(1); 
    return;
  }
  console.log(`KZMedia sunucusu ayakta: http://localhost:${PORT} ✅`);
});

// Port dinleme dışında kalan genel hataları yakalar
server.on('error', (e) => {
  console.error(`❌ SUNUCU GENEL HATASI:`, e.message);
  process.exit(1);
});
