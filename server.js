'use strict';
const express = require('express');
const bcrypt = require('bcryptjs');
const Database = require('better-sqlite3');
const crypto = require('crypto');
const path = require('path');
const app = express();
const db = new Database(path.join(__dirname, 'nomera.sqlite'));
db.pragma('journal_mode = WAL');
db.pragma('foreign_keys = ON');
db.exec(`
CREATE TABLE IF NOT EXISTS users (
 id INTEGER PRIMARY KEY AUTOINCREMENT,
 login TEXT NOT NULL UNIQUE COLLATE NOCASE,
 password_hash TEXT NOT NULL,
 rubles INTEGER NOT NULL DEFAULT 0,
 dollars INTEGER NOT NULL DEFAULT 0,
 created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
 last_seen INTEGER NOT NULL DEFAULT 0
);
CREATE TABLE IF NOT EXISTS plates (
 id TEXT PRIMARY KEY,
 owner_id INTEGER NOT NULL REFERENCES users(id),
 country TEXT NOT NULL,
 plate_text TEXT NOT NULL,
 region TEXT NOT NULL DEFAULT '',
 letters TEXT NOT NULL DEFAULT '',
 digits TEXT NOT NULL DEFAULT '',
 plate_type TEXT NOT NULL DEFAULT 'civ',
 rarity INTEGER NOT NULL DEFAULT 0,
 value INTEGER NOT NULL DEFAULT 0,
 details_json TEXT NOT NULL DEFAULT '[]',
 created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
 UNIQUE(country, plate_text)
);
CREATE INDEX IF NOT EXISTS plates_owner_idx ON plates(owner_id);
CREATE TABLE IF NOT EXISTS auctions (
 id INTEGER PRIMARY KEY AUTOINCREMENT,
 plate_id TEXT NOT NULL UNIQUE REFERENCES plates(id),
 seller_id INTEGER NOT NULL REFERENCES users(id),
 price INTEGER NOT NULL CHECK(price > 0),
 status TEXT NOT NULL DEFAULT 'active',
 created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE INDEX IF NOT EXISTS auctions_status_idx ON auctions(status, created_at);
CREATE TABLE IF NOT EXISTS trade_offers (
 id INTEGER PRIMARY KEY AUTOINCREMENT,
 from_user INTEGER NOT NULL REFERENCES users(id),
 to_user INTEGER NOT NULL REFERENCES users(id),
 from_plate TEXT NOT NULL REFERENCES plates(id),
 to_plate TEXT NOT NULL REFERENCES plates(id),
 cash INTEGER NOT NULL DEFAULT 0 CHECK(cash >= 0),
 dollars INTEGER NOT NULL DEFAULT 0 CHECK(dollars >= 0),
 status TEXT NOT NULL DEFAULT 'pending',
 created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
`);
for (const col of ['luck INTEGER NOT NULL DEFAULT 0','rolls INTEGER NOT NULL DEFAULT 0']) { try { db.exec('ALTER TABLE users ADD COLUMN '+col); } catch(e) {} }
db.exec(`
CREATE TABLE IF NOT EXISTS sessions (
 token TEXT PRIMARY KEY,
 user_id INTEGER NOT NULL REFERENCES users(id),
 created_at INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS grants (
 id INTEGER PRIMARY KEY AUTOINCREMENT,
 user_id INTEGER NOT NULL REFERENCES users(id),
 kind TEXT NOT NULL,
 payload_json TEXT NOT NULL DEFAULT '{}',
 applied INTEGER NOT NULL DEFAULT 0,
 created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE INDEX IF NOT EXISTS grants_user_idx ON grants(user_id, applied);
`);
db.exec(`
CREATE TABLE IF NOT EXISTS daily_tasks (
 id INTEGER PRIMARY KEY AUTOINCREMENT,
 title TEXT NOT NULL,
 kind TEXT NOT NULL,
 target INTEGER NOT NULL CHECK(target>0),
 min_rarity INTEGER NOT NULL DEFAULT 0,
 country TEXT NOT NULL DEFAULT '',
 reward_rub INTEGER NOT NULL DEFAULT 0,
 reward_usd INTEGER NOT NULL DEFAULT 0,
 active INTEGER NOT NULL DEFAULT 1,
 created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE IF NOT EXISTS task_progress (
 user_id INTEGER NOT NULL REFERENCES users(id),
 task_id INTEGER NOT NULL REFERENCES daily_tasks(id) ON DELETE CASCADE,
 day TEXT NOT NULL,
 progress INTEGER NOT NULL DEFAULT 0,
 claimed INTEGER NOT NULL DEFAULT 0,
 PRIMARY KEY(user_id,task_id,day)
);
`);
// Игровой день заданий — по Москве (UTC+3)
const taskDay=(shiftDays=0)=>new Date(Date.now()+3*3600e3-shiftDays*864e5).toISOString().slice(0,10);
function trackTasks(userId,{rarity,country}){
 const tasks=db.prepare('SELECT id,kind,target,min_rarity,country FROM daily_tasks WHERE active=1').all();
 if(!tasks.length) return;
 const day=taskDay();
 const up=db.prepare('INSERT INTO task_progress(user_id,task_id,day,progress) VALUES(?,?,?,1) ON CONFLICT(user_id,task_id,day) DO UPDATE SET progress=MIN(?,progress+1) WHERE claimed=0');
 for(const t of tasks){
  const hit=t.kind==='rolls'||(t.kind==='rarity'&&rarity>=t.min_rarity)||(t.kind==='country'&&country===t.country);
  if(hit) up.run(userId,t.id,day,t.target);
 }
}
app.use((req,res,next)=>{res.setHeader('Access-Control-Allow-Origin','*');res.setHeader('Access-Control-Allow-Headers','Content-Type, Authorization');res.setHeader('Access-Control-Allow-Methods','GET, POST, OPTIONS');if(req.method==='OPTIONS')return res.sendStatus(204);next()});
app.use(express.json({limit:'256kb'}));
// Раздаём только страницу игры: раньше express.static(__dirname) отдавал наружу nomera.sqlite и server.js
app.get(['/','/index.html'],(req,res)=>res.sendFile(path.join(__dirname,'index.html')));
function fail(res, status, error) { return res.status(status).json({error}); }
function auth(req,res,next) {
 const token = (req.headers.authorization || '').replace(/^Bearer\s+/i,'');
 const row = token ? db.prepare('SELECT user_id FROM sessions WHERE token=?').get(token) : null;
 const userId = row && row.user_id;
 if (!userId) return fail(res,401,'Войди в аккаунт на сервере');
 const user = db.prepare('SELECT id, login, rubles, dollars FROM users WHERE id=?').get(userId);
 if (!user) return fail(res,401,'Аккаунт не найден');
 db.prepare('UPDATE users SET last_seen=? WHERE id=?').run(Date.now(), user.id);
 req.user = user; next();
}
function issue(user) { const token=crypto.randomBytes(32).toString('hex'); db.prepare('INSERT INTO sessions(token,user_id,created_at) VALUES(?,?,?)').run(token,user.id,Date.now()); return token; }
function validLogin(login) { return typeof login==='string' && /^[a-z0-9_а-яё]{3,16}$/i.test(login); }
app.post('/api/register', async (req,res)=>{
 const login=String(req.body.login||'').trim().toLowerCase(), password=String(req.body.password||'');
 if(!validLogin(login)||password.length<4||password.length>200) return fail(res,400,'Логин: 3–16 символов; пароль: от 4 символов');
 try { const hash=await bcrypt.hash(password,12); const info=db.prepare('INSERT INTO users(login,password_hash,rubles) VALUES(?,?,5000)').run(login,hash); const user=db.prepare('SELECT id,login,rubles,dollars FROM users WHERE id=?').get(info.lastInsertRowid); res.json({token:issue(user),user}); }
 catch(e) { if(String(e).includes('UNIQUE')) return fail(res,409,'Такой логин уже занят'); console.error(e); return fail(res,500,'Не удалось создать аккаунт'); }
});
app.post('/api/login', async (req,res)=>{
 const login=String(req.body.login||'').trim().toLowerCase(), password=String(req.body.password||'');
 const user=db.prepare('SELECT * FROM users WHERE login=? COLLATE NOCASE').get(login);
 if(!user || !(await bcrypt.compare(password,user.password_hash))) return fail(res,401,'Неверный логин или пароль');
 db.prepare('UPDATE users SET last_seen=? WHERE id=?').run(Date.now(),user.id);
 res.json({token:issue(user),user:{id:user.id,login:user.login,rubles:user.rubles,dollars:user.dollars}});
});
app.get('/api/me',auth,(req,res)=>res.json({user:req.user}));
function adminOnly(req,res,next){
 const adminLogin=String(process.env.ADMIN_LOGIN||'admin').toLowerCase();
 if(req.user.login.toLowerCase()!==adminLogin) return fail(res,403,'Нет прав администратора. Используй админ-аккаунт.');
 next();
}
app.get('/api/admin/users',auth,adminOnly,(req,res)=>{
 const rows=db.prepare(`SELECT u.id,u.login,u.created_at,u.last_seen,u.rubles,u.dollars,u.luck,u.rolls,
  (SELECT COUNT(*) FROM plates p WHERE p.owner_id=u.id) AS plates,
  (SELECT COUNT(*) FROM plates p WHERE p.owner_id=u.id AND p.rarity>=3) AS rare,
  (SELECT COALESCE(MAX(p.value),0) FROM plates p WHERE p.owner_id=u.id) AS best,
  (SELECT COALESCE(SUM(p.value),0) FROM plates p WHERE p.owner_id=u.id) AS total_value
  FROM users u ORDER BY u.last_seen DESC, u.created_at DESC`).all();
 const users=rows.map(u=>({...u,online:Date.now()-u.last_seen<90000}));
 res.json({users});
});
app.get('/api/admin/stats',auth,adminOnly,(req,res)=>{
 const one=(q)=>db.prepare(q).get();
 const now=Date.now();
 const rarity=db.prepare('SELECT rarity,COUNT(*) AS n FROM plates GROUP BY rarity ORDER BY rarity').all();
 res.json({
  players:one('SELECT COUNT(*) AS n FROM users').n,
  online:one('SELECT COUNT(*) AS n FROM users WHERE last_seen>'+(now-90000)).n,
  active24h:one('SELECT COUNT(*) AS n FROM users WHERE last_seen>'+(now-86400000)).n,
  plates:one('SELECT COUNT(*) AS n FROM plates').n,
  rarity,
  auctionsActive:one("SELECT COUNT(*) AS n FROM auctions WHERE status='active'").n,
  auctionsSold:one("SELECT COUNT(*) AS n FROM auctions WHERE status='sold'").n,
  tradesPending:one("SELECT COUNT(*) AS n FROM trade_offers WHERE status='pending'").n,
  tradesDone:one("SELECT COUNT(*) AS n FROM trade_offers WHERE status='accepted'").n,
  best:db.prepare('SELECT p.plate_text AS text,p.value,u.login AS owner FROM plates p JOIN users u ON u.id=p.owner_id ORDER BY p.value DESC LIMIT 5').all()
 });
});
app.post('/api/admin/grant',auth,adminOnly,(req,res)=>{
 const target=db.prepare('SELECT id,login FROM users WHERE login=? COLLATE NOCASE').get(String(req.body.login||'').trim());
 if(!target) return fail(res,404,'Игрок не найден');
 const kind=String(req.body.kind||'');
 const addGrant=(payload)=>db.prepare('INSERT INTO grants(user_id,kind,payload_json) VALUES(?,?,?)').run(target.id,kind,JSON.stringify(payload));
 if(kind==='luck'){
  const level=Number(req.body.level);
  if(!Number.isSafeInteger(level)||level<1||level>1e9) return fail(res,400,'Уровень удачи: целое от 1 до 1 000 000 000');
  db.prepare('UPDATE users SET luck=? WHERE id=?').run(level-1,target.id);
  addGrant({level}); return res.json({ok:true});
 }
 if(kind==='money'){
  const rubles=Math.round(Number(req.body.rubles)||0), dollars=Math.round(Number(req.body.dollars)||0);
  if(!Number.isSafeInteger(rubles)||!Number.isSafeInteger(dollars)||(!rubles&&!dollars)) return fail(res,400,'Укажи сумму');
  db.prepare('UPDATE users SET rubles=MAX(0,rubles+?), dollars=MAX(0,dollars+?) WHERE id=?').run(rubles,dollars,target.id);
  addGrant({rubles,dollars}); return res.json({ok:true});
 }
 if(kind==='plate'){
  const p=req.body.plate||{}; const text=String(p.text||'').trim().toUpperCase(), country=String(p.country||'ru').trim().toLowerCase();
  if(!text||text.length>40) return fail(res,400,'Некорректный номер');
  if(!/^[a-z0-9_]{2,8}$/.test(country)) return fail(res,400,'Некорректный код страны (2–8 латинских букв или цифр)');
  const id=crypto.randomUUID();
  const fields={id,country,countryName:String(p.countryName||'').trim().slice(0,40),text,region:String(p.region||''),letters:String(p.letters||''),digits:String(p.digits||''),type:String(p.type||'civ'),rarity:Math.max(0,Math.min(4,Number(p.rarity)||0)),value:Math.max(0,Math.min(2000000000,Math.round(Number(p.value)||0)))};
  try{
   db.prepare('INSERT INTO plates(id,owner_id,country,plate_text,region,letters,digits,plate_type,rarity,value,details_json) VALUES(?,?,?,?,?,?,?,?,?,?,?)')
    .run(id,target.id,country,text,fields.region,fields.letters,fields.digits,fields.type,fields.rarity,fields.value,JSON.stringify(Array.isArray(p.details)?p.details.slice(0,20):[]));
  }catch(e){ if(String(e).includes('UNIQUE')) return fail(res,409,'Такой номер уже существует в общей базе'); console.error(e); return fail(res,500,'Не удалось выдать номер'); }
  addGrant(fields); return res.json({ok:true,id,text});
 }
 return fail(res,400,'Неизвестный тип выдачи');
});
// ---------- Ежедневные задания ----------
const TASK_KINDS=['rolls','rarity','country'];
app.get('/api/admin/tasks',auth,adminOnly,(req,res)=>{
 const day=taskDay();
 const tasks=db.prepare(`SELECT t.*,
  (SELECT COUNT(*) FROM task_progress p WHERE p.task_id=t.id AND p.day=? AND p.progress>=t.target) AS done_today,
  (SELECT COUNT(*) FROM task_progress p WHERE p.task_id=t.id AND p.day=? AND p.claimed=1) AS claimed_today
  FROM daily_tasks t ORDER BY t.id DESC`).all(day,day).map(t=>({...t,active:!!t.active}));
 res.json({tasks});
});
app.post('/api/admin/tasks',auth,adminOnly,(req,res)=>{
 const b=req.body||{};
 const kind=String(b.kind||''), title=String(b.title||'').trim().slice(0,100);
 const target=Number(b.target), minRarity=Number(b.minRarity||0), rewardRub=Number(b.rewardRub||0), rewardUsd=Number(b.rewardUsd||0);
 const country=String(b.country||'').trim().toLowerCase();
 if(!TASK_KINDS.includes(kind)) return fail(res,400,'Неизвестный тип задания');
 if(!title) return fail(res,400,'Нужно название задания');
 if(!Number.isSafeInteger(target)||target<1||target>1000000) return fail(res,400,'Цель: целое число от 1 до 1 000 000');
 if(!Number.isSafeInteger(minRarity)||minRarity<0||minRarity>4) return fail(res,400,'Редкость: от 0 до 4');
 if(!Number.isSafeInteger(rewardRub)||rewardRub<0||rewardRub>2e9||!Number.isSafeInteger(rewardUsd)||rewardUsd<0||rewardUsd>1e9) return fail(res,400,'Награда должна быть целым неотрицательным числом');
 if(!rewardRub&&!rewardUsd) return fail(res,400,'Укажи награду в ₽ или в $');
 if(kind==='country'&&!/^[a-z0-9_]{2,8}$/.test(country)) return fail(res,400,'Выбери страну');
 const info=db.prepare('INSERT INTO daily_tasks(title,kind,target,min_rarity,country,reward_rub,reward_usd) VALUES(?,?,?,?,?,?,?)')
  .run(title,kind,target,kind==='rarity'?minRarity:0,kind==='country'?country:'',rewardRub,rewardUsd);
 res.json({ok:true,id:info.lastInsertRowid});
});
app.post('/api/admin/tasks/:id/toggle',auth,adminOnly,(req,res)=>{
 const r=db.prepare('UPDATE daily_tasks SET active=1-active WHERE id=?').run(Number(req.params.id));
 if(!r.changes) return fail(res,404,'Задание не найдено'); res.json({ok:true});
});
app.post('/api/admin/tasks/:id/delete',auth,adminOnly,(req,res)=>{
 const r=db.prepare('DELETE FROM daily_tasks WHERE id=?').run(Number(req.params.id));
 if(!r.changes) return fail(res,404,'Задание не найдено'); res.json({ok:true});
});
app.get('/api/tasks',auth,(req,res)=>{
 const day=taskDay();
 db.prepare('DELETE FROM task_progress WHERE day<?').run(taskDay(7));
 const tasks=db.prepare(`SELECT t.id,t.title,t.kind,t.target,t.min_rarity,t.country,t.reward_rub,t.reward_usd,
  COALESCE(p.progress,0) AS progress, COALESCE(p.claimed,0) AS claimed
  FROM daily_tasks t LEFT JOIN task_progress p ON p.task_id=t.id AND p.user_id=? AND p.day=?
  WHERE t.active=1 ORDER BY t.id`).all(req.user.id,day).map(t=>({...t,progress:Math.min(t.progress,t.target),claimed:!!t.claimed}));
 res.json({day,tasks});
});
app.post('/api/tasks/:id/claim',auth,(req,res)=>{
 try{
  const out=db.transaction(()=>{
   const t=db.prepare('SELECT * FROM daily_tasks WHERE id=? AND active=1').get(Number(req.params.id));
   if(!t) throw Error('Задание недоступно');
   const day=taskDay();
   const p=db.prepare('SELECT progress,claimed FROM task_progress WHERE user_id=? AND task_id=? AND day=?').get(req.user.id,t.id,day);
   if(!p||p.progress<t.target) throw Error('Задание ещё не выполнено');
   if(p.claimed) throw Error('Награда уже получена');
   db.prepare('UPDATE task_progress SET claimed=1 WHERE user_id=? AND task_id=? AND day=?').run(req.user.id,t.id,day);
   db.prepare('UPDATE users SET rubles=rubles+?, dollars=dollars+? WHERE id=?').run(t.reward_rub,t.reward_usd,req.user.id);
   return {rubles:t.reward_rub,dollars:t.reward_usd};
  })();
  res.json({ok:true,...out});
 }catch(e){ return fail(res,400,e.message||'Не удалось забрать награду'); }
});

app.get('/api/grants',auth,(req,res)=>{
 const grants=db.prepare('SELECT id,kind,payload_json FROM grants WHERE user_id=? AND applied=0 ORDER BY id').all(req.user.id).map(g=>({id:g.id,kind:g.kind,payload:JSON.parse(g.payload_json)}));
 res.json({grants});
});
app.post('/api/grants/ack',auth,(req,res)=>{
 const ids=(Array.isArray(req.body.ids)?req.body.ids:[]).map(Number).filter(Number.isSafeInteger).slice(0,200);
 const st=db.prepare('UPDATE grants SET applied=1 WHERE id=? AND user_id=?');
 for(const id of ids) st.run(id,req.user.id);
 res.json({ok:true});
});
app.get('/api/players',auth,(req,res)=>{
 const players=db.prepare('SELECT login,last_seen FROM users ORDER BY login COLLATE NOCASE').all().map(p=>({login:p.login,online:Date.now()-p.last_seen<90000}));
 res.json({players});
});
app.get('/api/plates',auth,(req,res)=>{
 const plates=db.prepare('SELECT id,country,plate_text AS text,region,letters,digits,plate_type AS type,rarity,value,details_json FROM plates WHERE owner_id=? ORDER BY created_at DESC').all(req.user.id).map(p=>({...p,details:JSON.parse(p.details_json)}));
 res.json({plates});
});
app.get('/api/players/:login/plates',auth,(req,res)=>{
 const target=db.prepare('SELECT id,login FROM users WHERE login=? COLLATE NOCASE').get(String(req.params.login||''));
 if(!target) return fail(res,404,'Игрок не найден');
 const plates=db.prepare('SELECT id,plate_text AS text,country,rarity,value FROM plates WHERE owner_id=? ORDER BY created_at DESC LIMIT 100').all(target.id);
 res.json({login:target.login,plates});
});
app.post('/api/claim',auth,(req,res)=>{
 const p=req.body.plate||{}; const text=String(p.text||'').trim().toUpperCase(), country=String(p.country||'ru');
 if(!text || text.length>40 || !['ru','ua','ae','am','ge','kz','az','uz','kg','tj','tr','us','ng','af','pt','ady'].includes(country)) return fail(res,400,'Некорректный номер или страна');
 const id=crypto.randomUUID();
 try {
  db.prepare(`INSERT INTO plates(id,owner_id,country,plate_text,region,letters,digits,plate_type,rarity,value,details_json) VALUES(?,?,?,?,?,?,?,?,?,?,?)`)
   .run(id,req.user.id,country,text,String(p.region||''),String(p.letters||''),String(p.digits||''),String(p.type||'civ'),Math.max(0,Math.min(4,Number(p.rarity)||0)),Math.max(0,Math.min(2000000000,Math.round(Number(p.value)||0))),JSON.stringify(Array.isArray(p.details)?p.details.slice(0,20):[]));
  db.prepare('UPDATE users SET rolls=rolls+1, luck=? WHERE id=?').run(Math.max(0,Math.min(1e9,Math.floor(Number(req.body.luck)||0))),req.user.id);
  try{ trackTasks(req.user.id,{rarity:Math.max(0,Math.min(4,Number(p.rarity)||0)),country}); }catch(e){ console.error('tasks',e); }
  res.json({ok:true,id,text});
 } catch(e) { if(String(e).includes('UNIQUE')) return fail(res,409,'Такой номер уже существует в общей базе и больше не выпадет'); console.error(e); return fail(res,500,'Не удалось сохранить номер'); }
});
app.post('/api/transfer',auth,(req,res)=>{
 const toLogin=String(req.body.to||'').trim(), plateId=String(req.body.plateId||'');
 const to=db.prepare('SELECT id FROM users WHERE login=? COLLATE NOCASE').get(toLogin);
 if(!to) return fail(res,404,'Получатель не найден'); if(to.id===req.user.id) return fail(res,400,'Нельзя передать номер самому себе');
 const owned=db.prepare('SELECT id FROM plates WHERE owner_id=? AND (id=? OR plate_text=? COLLATE NOCASE) ORDER BY CASE WHEN id=? THEN 0 ELSE 1 END LIMIT 1').get(req.user.id,plateId,plateId,plateId);
 const result=owned?db.prepare('UPDATE plates SET owner_id=? WHERE id=? AND owner_id=?').run(to.id,owned.id,req.user.id):{changes:0};
 if(!result.changes) return fail(res,404,'Номер не найден в твоей коллекции'); res.json({ok:true});
});
app.post('/api/trades',auth,(req,res)=>{
 const toLogin=String(req.body.to||'').trim(), myId=String(req.body.myPlateId||''), theirId=String(req.body.theirPlateId||'');
 const cash=Number(req.body.cash||0), dollars=Number(req.body.usd||0);
 if(!Number.isSafeInteger(cash)||!Number.isSafeInteger(dollars)||cash<0||dollars<0) return fail(res,400,'Доплата должна быть целым неотрицательным числом');
 const to=db.prepare('SELECT id FROM users WHERE login=? COLLATE NOCASE').get(toLogin);
 if(!to) return fail(res,404,'Игрок не найден'); if(to.id===req.user.id) return fail(res,400,'Нельзя торговать с собой');
 const a=db.prepare('SELECT id FROM plates WHERE owner_id=? AND (id=? OR plate_text=? COLLATE NOCASE) ORDER BY CASE WHEN id=? THEN 0 ELSE 1 END LIMIT 1').get(req.user.id,myId,myId,myId), b=db.prepare('SELECT id FROM plates WHERE owner_id=? AND (id=? OR plate_text=? COLLATE NOCASE) ORDER BY CASE WHEN id=? THEN 0 ELSE 1 END LIMIT 1').get(to.id,theirId,theirId,theirId);
 if(!a||!b) return fail(res,400,'Проверь ID номеров и их владельцев');
 if(req.user.rubles<cash||req.user.dollars<dollars) return fail(res,400,'На серверном балансе не хватает средств');
 const info=db.prepare('INSERT INTO trade_offers(from_user,to_user,from_plate,to_plate,cash,dollars) VALUES(?,?,?,?,?,?)').run(req.user.id,to.id,myId,theirId,cash,dollars);
 res.json({ok:true,offerId:info.lastInsertRowid});
});
app.get('/api/trades',auth,(req,res)=>{
 const offers=db.prepare(`SELECT t.id,t.cash,t.dollars,t.status,t.created_at, u.login AS from_login, v.login AS to_login, p.plate_text AS from_plate, q.plate_text AS to_plate FROM trade_offers t JOIN users u ON u.id=t.from_user JOIN users v ON v.id=t.to_user JOIN plates p ON p.id=t.from_plate JOIN plates q ON q.id=t.to_plate WHERE t.to_user=? AND t.status='pending' ORDER BY t.id DESC`).all(req.user.id);
 res.json({offers});
});
app.post('/api/trades/:id/accept',auth,(req,res)=>{
 const tx=db.transaction(()=>{
  const t=db.prepare("SELECT * FROM trade_offers WHERE id=? AND to_user=? AND status='pending'").get(Number(req.params.id),req.user.id);
  if(!t) throw Error('Предложение не найдено или уже обработано');
  const from=db.prepare('SELECT * FROM users WHERE id=?').get(t.from_user), to=db.prepare('SELECT * FROM users WHERE id=?').get(t.to_user);
  const p=db.prepare('SELECT * FROM plates WHERE id=?').get(t.from_plate), q=db.prepare('SELECT * FROM plates WHERE id=?').get(t.to_plate);
  if(!p||!q||p.owner_id!==from.id||q.owner_id!==to.id) throw Error('Владение номерами изменилось');
  if(from.rubles<t.cash||from.dollars<t.dollars) throw Error('У отправителя больше недостаточно средств');
  db.prepare('UPDATE users SET rubles=rubles-?, dollars=dollars-? WHERE id=?').run(t.cash,t.dollars,from.id);
  db.prepare('UPDATE users SET rubles=rubles+?, dollars=dollars+? WHERE id=?').run(t.cash,t.dollars,to.id);
  db.prepare('UPDATE plates SET owner_id=? WHERE id=?').run(to.id,p.id);
  db.prepare('UPDATE plates SET owner_id=? WHERE id=?').run(from.id,q.id);
  db.prepare("UPDATE trade_offers SET status='accepted' WHERE id=?").run(t.id);
 });
 try{tx();res.json({ok:true})}catch(e){res.status(400).json({error:e.message})}
});

app.get('/api/auctions',auth,(req,res)=>{
 const auctions=db.prepare(`SELECT a.id,a.price,a.created_at,p.plate_text AS text,p.country,p.rarity,p.value,p.id AS plate_id,u.login AS seller,a.seller_id=? AS mine FROM auctions a JOIN plates p ON p.id=a.plate_id JOIN users u ON u.id=a.seller_id WHERE a.status='active' ORDER BY a.created_at DESC LIMIT 100`).all(req.user.id).map(x=>({...x,mine:!!x.mine}));
 res.json({auctions});
});
app.post('/api/auctions',auth,(req,res)=>{
 const plate=String(req.body.plate||'').trim(),price=Number(req.body.price);
 if(!plate||!Number.isSafeInteger(price)||price<1||price>2000000000)return fail(res,400,'Цена должна быть целым числом от 1 до 2 000 000 000 ₽');
 const p=db.prepare('SELECT id,owner_id FROM plates WHERE owner_id=? AND (id=? OR plate_text=? COLLATE NOCASE) LIMIT 1').get(req.user.id,plate,plate);
 if(!p)return fail(res,404,'Этот номер не найден в твоей серверной коллекции');
 db.prepare("DELETE FROM auctions WHERE plate_id=? AND status!='active'").run(p.id);
 try{db.prepare("INSERT INTO auctions(plate_id,seller_id,price) VALUES(?,?,?)").run(p.id,req.user.id,price);res.json({ok:true})}catch(e){if(String(e).includes('UNIQUE'))return fail(res,409,'Этот номер уже выставлен на аукцион');console.error(e);return fail(res,500,'Не удалось выставить номер')}
});
app.post('/api/auctions/:id/cancel',auth,(req,res)=>{
 const r=db.prepare("DELETE FROM auctions WHERE id=? AND seller_id=? AND status='active'").run(Number(req.params.id),req.user.id);
 if(!r.changes)return fail(res,404,'Лот не найден, уже продан или он не твой');
 res.json({ok:true});
});
app.post('/api/auctions/:id/buy',auth,(req,res)=>{
 try{const result=db.transaction(()=>{
  const a=db.prepare("SELECT * FROM auctions WHERE id=? AND status='active'").get(Number(req.params.id));
  if(!a)throw Error('Лот уже продан или снят');if(a.seller_id===req.user.id)throw Error('Нельзя купить собственный номер');
  const buyer=db.prepare('SELECT rubles FROM users WHERE id=?').get(req.user.id);if(!buyer||buyer.rubles<a.price)throw Error('Не хватает серверных рублей');
  const plate=db.prepare('SELECT id,owner_id,plate_text,country,region,letters,digits,plate_type,rarity,value FROM plates WHERE id=?').get(a.plate_id);if(!plate||plate.owner_id!==a.seller_id)throw Error('Владелец номера изменился');
  db.prepare('UPDATE users SET rubles=rubles-? WHERE id=?').run(a.price,req.user.id);
  db.prepare('UPDATE users SET rubles=rubles+? WHERE id=?').run(a.price,a.seller_id);
  db.prepare('UPDATE plates SET owner_id=? WHERE id=?').run(req.user.id,plate.id);
  db.prepare("UPDATE auctions SET status='sold' WHERE id=?").run(a.id);return {text:plate.plate_text,price:a.price,plate:{id:plate.id,country:plate.country,region:plate.region,letters:plate.letters,digits:plate.digits,type:plate.plate_type,rarity:plate.rarity,value:plate.value}};
 })();res.json({ok:true,...result})}catch(e){return fail(res,400,e.message||'Покупка не удалась')}
});

db.exec(`
CREATE TABLE IF NOT EXISTS shop_items (
 id INTEGER PRIMARY KEY AUTOINCREMENT,
 plate_text TEXT NOT NULL,
 country TEXT NOT NULL,
 region TEXT NOT NULL DEFAULT '',
 value INTEGER NOT NULL DEFAULT 0,
 rarity INTEGER NOT NULL DEFAULT 0,
 price_usd REAL NOT NULL CHECK(price_usd > 0),
 image TEXT NOT NULL DEFAULT '',
 status TEXT NOT NULL DEFAULT 'active',
 buyer_id INTEGER,
 created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE INDEX IF NOT EXISTS shop_status_idx ON shop_items(status);
`);
const SHOP_COUNTRIES=['ru','ua','ae','am','ge','kz','az','uz','kg','tj','tr','us','ng','af','pt','ady'];
const isAdminUser=u=>u.login.toLowerCase()===String(process.env.ADMIN_LOGIN||'admin').toLowerCase();
const shopRarity=v=>[0,5e3,3e4,3e5,2.5e6].reduce((r,t,i)=>v>=t?i:r,0);
app.get('/api/shop',auth,(req,res)=>{
 const items=db.prepare("SELECT id,plate_text AS text,country,region,value,rarity,price_usd AS price,image FROM shop_items WHERE status='active' ORDER BY id DESC LIMIT 200").all();
 res.json({items,admin:isAdminUser(req.user)});
});
app.post('/api/admin/shop',auth,adminOnly,(req,res)=>{
 const b=req.body||{},text=String(b.text||'').trim().toUpperCase(),country=String(b.country||'ru'),region=String(b.region||'').trim().slice(0,8);
 const price=Math.round(Number(b.price)*1000)/1000,value=Math.max(0,Math.min(2000000000,Math.round(Number(b.value)||0))),image=String(b.image||'');
 if(!text||text.length>40)return fail(res,400,'Укажи номер (до 40 символов)');
 if(!SHOP_COUNTRIES.includes(country))return fail(res,400,'Неизвестная страна');
 if(!(price>0)||price>1e9)return fail(res,400,'Цена в $ должна быть больше нуля');
 if(image&&(image.length>150000||!/^data:image\/(jpeg|png|webp);base64,[A-Za-z0-9+\/=]+$/.test(image)))return fail(res,400,'Картинка некорректная или слишком большая');
 if(db.prepare('SELECT 1 FROM plates WHERE country=? AND plate_text=?').get(country,text)||db.prepare("SELECT 1 FROM shop_items WHERE country=? AND plate_text=? AND status='active'").get(country,text))return fail(res,409,'Такой номер уже существует или уже лежит в магазине');
 db.prepare('INSERT INTO shop_items(plate_text,country,region,value,rarity,price_usd,image) VALUES(?,?,?,?,?,?,?)').run(text,country,region,value,shopRarity(value),price,image);
 res.json({ok:true});
});
app.post('/api/admin/shop/:id/delete',auth,adminOnly,(req,res)=>{
 const r=db.prepare("DELETE FROM shop_items WHERE id=? AND status='active'").run(Number(req.params.id));
 if(!r.changes)return fail(res,404,'Товар не найден или уже продан');
 res.json({ok:true});
});
app.post('/api/shop/:id/buy',auth,(req,res)=>{
 try{const out=db.transaction(()=>{
  const it=db.prepare("SELECT * FROM shop_items WHERE id=? AND status='active'").get(Number(req.params.id));
  if(!it)throw Error('Товар уже продан или удалён');
  const pid=crypto.randomUUID();
  try{db.prepare('INSERT INTO plates(id,owner_id,country,plate_text,region,letters,digits,plate_type,rarity,value,details_json) VALUES(?,?,?,?,?,?,?,?,?,?,?)').run(pid,req.user.id,it.country,it.plate_text,it.region,'','','civ',it.rarity,it.value,'[]')}
  catch(e){if(String(e).includes('UNIQUE'))throw Error('Такой номер уже существует');throw e}
  db.prepare("UPDATE shop_items SET status='sold',buyer_id=? WHERE id=?").run(req.user.id,it.id);
  return {text:it.plate_text,price:it.price_usd,plate:{id:pid,country:it.country,region:it.region,value:it.value,rarity:it.rarity,image:it.image}};
 })();res.json({ok:true,...out})}catch(e){return fail(res,400,e.message||'Покупка не удалась')}
});
app.get('/api/health',(req,res)=>res.json({ok:true,service:'nomera-online'}));
const port=Number(process.env.PORT||3000);
app.listen(port,'0.0.0.0',()=>console.log(`Генератор номеров запущен: http://localhost:${port}`));
