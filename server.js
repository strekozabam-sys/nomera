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
app.use((req,res,next)=>{res.setHeader('Access-Control-Allow-Origin','*');res.setHeader('Access-Control-Allow-Headers','Content-Type, Authorization');res.setHeader('Access-Control-Allow-Methods','GET, POST, OPTIONS');if(req.method==='OPTIONS')return res.sendStatus(204);next()});
app.use(express.json({limit:'32kb'}));
app.use(express.static(__dirname));
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
  const p=req.body.plate||{}; const text=String(p.text||'').trim().toUpperCase(), country=String(p.country||'ru');
  if(!text||text.length>40) return fail(res,400,'Некорректный номер');
  const id=crypto.randomUUID();
  const fields={id,country,text,region:String(p.region||''),letters:String(p.letters||''),digits:String(p.digits||''),type:String(p.type||'civ'),rarity:Math.max(0,Math.min(4,Number(p.rarity)||0)),value:Math.max(0,Math.min(2000000000,Math.round(Number(p.value)||0)))};
  try{
   db.prepare('INSERT INTO plates(id,owner_id,country,plate_text,region,letters,digits,plate_type,rarity,value,details_json) VALUES(?,?,?,?,?,?,?,?,?,?,?)')
    .run(id,target.id,country,text,fields.region,fields.letters,fields.digits,fields.type,fields.rarity,fields.value,JSON.stringify(Array.isArray(p.details)?p.details.slice(0,20):[]));
  }catch(e){ if(String(e).includes('UNIQUE')) return fail(res,409,'Такой номер уже существует в общей базе'); console.error(e); return fail(res,500,'Не удалось выдать номер'); }
  addGrant(fields); return res.json({ok:true,id,text});
 }
 return fail(res,400,'Неизвестный тип выдачи');
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
 try{db.prepare("INSERT INTO auctions(plate_id,seller_id,price) VALUES(?,?,?)").run(p.id,req.user.id,price);res.json({ok:true})}catch(e){if(String(e).includes('UNIQUE'))return fail(res,409,'Этот номер уже выставлен на аукцион');console.error(e);return fail(res,500,'Не удалось выставить номер')}
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

app.get('/api/health',(req,res)=>res.json({ok:true,service:'nomera-online'}));
const port=Number(process.env.PORT||3000);
app.listen(port,'0.0.0.0',()=>console.log(`Генератор номеров запущен: http://localhost:${port}`));
