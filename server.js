import express from 'express';
import helmet from 'helmet';
import morgan from 'morgan';
import Database from 'better-sqlite3';
import crypto from 'node:crypto';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const app = express();
const PORT = Number(process.env.PORT || 3000);
const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD || '';
const SESSION_SECRET = process.env.SESSION_SECRET || crypto.randomBytes(32).toString('hex');
if (process.env.NODE_ENV === 'production' && (!ADMIN_PASSWORD || !process.env.SESSION_SECRET)) { throw new Error('Defina ADMIN_PASSWORD e SESSION_SECRET no ambiente de produção.'); }
const db = new Database(path.join(__dirname,'data','andre-aereas.db'));

db.pragma('journal_mode = WAL');
db.exec(`CREATE TABLE IF NOT EXISTS locations (
 id INTEGER PRIMARY KEY AUTOINCREMENT,
 city TEXT NOT NULL,
 region TEXT DEFAULT '', country TEXT DEFAULT '', airport TEXT NOT NULL,
 code TEXT NOT NULL UNIQUE, latitude REAL, longitude REAL, active INTEGER NOT NULL DEFAULT 1,
 created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE IF NOT EXISTS users (
 id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT NOT NULL, email TEXT NOT NULL UNIQUE,
 password_hash TEXT NOT NULL, role TEXT NOT NULL DEFAULT 'customer', active INTEGER NOT NULL DEFAULT 1,
 created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE IF NOT EXISTS user_sessions (
 token_hash TEXT PRIMARY KEY, user_id INTEGER NOT NULL, expires_at INTEGER NOT NULL,
 created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP, FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
);
CREATE TABLE IF NOT EXISTS password_resets (
 token_hash TEXT PRIMARY KEY, user_id INTEGER NOT NULL, expires_at INTEGER NOT NULL, used INTEGER NOT NULL DEFAULT 0
);
CREATE TABLE IF NOT EXISTS quotes (
 id INTEGER PRIMARY KEY AUTOINCREMENT, user_id INTEGER, origin TEXT NOT NULL, destination TEXT NOT NULL,
 departure_date TEXT NOT NULL, return_date TEXT, passengers INTEGER NOT NULL, selected_flight_id INTEGER,
 flight_snapshot TEXT, quoted_price REAL, status TEXT NOT NULL DEFAULT 'pending', whatsapp_opened_at TEXT,
 created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP, updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
 FOREIGN KEY(user_id) REFERENCES users(id), FOREIGN KEY(selected_flight_id) REFERENCES flights(id)
);
CREATE TABLE IF NOT EXISTS purchases (
 id INTEGER PRIMARY KEY AUTOINCREMENT, quote_id INTEGER NOT NULL UNIQUE, user_id INTEGER,
 amount REAL NOT NULL, status TEXT NOT NULL DEFAULT 'confirmed', confirmed_by TEXT NOT NULL,
 confirmed_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP, notes TEXT DEFAULT '',
 FOREIGN KEY(quote_id) REFERENCES quotes(id), FOREIGN KEY(user_id) REFERENCES users(id)
);
CREATE TABLE IF NOT EXISTS loyalty_settings (
 id INTEGER PRIMARY KEY CHECK(id=1), enabled INTEGER NOT NULL DEFAULT 0, miles_per_purchase INTEGER NOT NULL DEFAULT 100,
 benefit_per_mile REAL NOT NULL DEFAULT 0.01, min_redeem_miles INTEGER NOT NULL DEFAULT 1000,
 max_discount_percent REAL NOT NULL DEFAULT 10, expiry_days INTEGER, approved INTEGER NOT NULL DEFAULT 0,
 updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
INSERT OR IGNORE INTO loyalty_settings(id) VALUES(1);
CREATE TABLE IF NOT EXISTS mile_ledger (
 id INTEGER PRIMARY KEY AUTOINCREMENT, user_id INTEGER NOT NULL, delta INTEGER NOT NULL,
 kind TEXT NOT NULL, purchase_id INTEGER, reason TEXT NOT NULL, admin_id TEXT NOT NULL,
 rule_snapshot TEXT NOT NULL, created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
 UNIQUE(purchase_id,kind), FOREIGN KEY(user_id) REFERENCES users(id), FOREIGN KEY(purchase_id) REFERENCES purchases(id)
);
CREATE TABLE IF NOT EXISTS admin_audit (
 id INTEGER PRIMARY KEY AUTOINCREMENT, admin_id TEXT NOT NULL, action TEXT NOT NULL,
 target_type TEXT NOT NULL, target_id TEXT, details TEXT NOT NULL DEFAULT '{}',
 created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE IF NOT EXISTS flights (
 id INTEGER PRIMARY KEY AUTOINCREMENT,
 origin_id INTEGER NOT NULL, destination_id INTEGER NOT NULL,
 flight_code TEXT NOT NULL, airline_name TEXT NOT NULL DEFAULT 'André Aéreas',
 departure_date TEXT NOT NULL, return_date TEXT, departure_time TEXT NOT NULL, arrival_time TEXT NOT NULL,
 duration_minutes INTEGER DEFAULT 0, stops INTEGER NOT NULL DEFAULT 0,
 cabin TEXT NOT NULL DEFAULT 'Econômica', price REAL NOT NULL DEFAULT 0,
 seats INTEGER NOT NULL DEFAULT 0, trip_type TEXT NOT NULL DEFAULT 'round', active INTEGER NOT NULL DEFAULT 1,
 created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
 FOREIGN KEY(origin_id) REFERENCES locations(id), FOREIGN KEY(destination_id) REFERENCES locations(id)
);`);

function sign(value){return crypto.createHmac('sha256',SESSION_SECRET).update(value).digest('hex');}
function cookieToken(){const payload=Buffer.from(JSON.stringify({role:'admin',exp:Date.now()+1000*60*60*8})).toString('base64url');return `${payload}.${sign(payload)}`;}
function isAdmin(req){const raw=(req.headers.cookie||'').split(';').map(x=>x.trim()).find(x=>x.startsWith('aa_admin='))?.split('=')[1];if(!raw)return false;const [payload,sig]=raw.split('.');if(!payload||!sig)return false;const a=Buffer.from(sig),b=Buffer.from(sign(payload));if(a.length!==b.length||!crypto.timingSafeEqual(a,b))return false;try{return JSON.parse(Buffer.from(payload,'base64url').toString()).exp>Date.now();}catch{return false;}}
function requireAdmin(req,res,next){if(!isAdmin(req))return res.status(401).json({error:'Não autorizado'});next();}
function cleanLocation(row){return {...row,active:Boolean(row.active)};}
function cleanFlight(row){return {...row,active:Boolean(row.active)};}


const hashPassword = (password, salt=crypto.randomBytes(16).toString('hex')) => ({salt, hash:crypto.scryptSync(password,salt,64).toString('hex')});
const verifyPassword = (password, stored) => { try { const [salt,hash]=String(stored).split(':'); const actual=crypto.scryptSync(password,salt,64); const expected=Buffer.from(hash,'hex'); return actual.length===expected.length && crypto.timingSafeEqual(actual,expected); } catch { return false; } };
const digest = token => crypto.createHash('sha256').update(token).digest('hex');
function currentUser(req){ const token=(req.headers.cookie||'').split(';').map(v=>v.trim()).find(v=>v.startsWith('aa_session='))?.slice(11); if(!token)return null; const row=db.prepare('SELECT u.id,u.name,u.email,u.role,u.active,s.expires_at FROM user_sessions s JOIN users u ON u.id=s.user_id WHERE s.token_hash=?').get(digest(decodeURIComponent(token))); if(!row||!row.active||row.expires_at<Date.now())return null; return row; }
function requireUser(req,res,next){const u=currentUser(req);if(!u)return res.status(401).json({error:'Faça login para continuar.'});req.user=u;next();}
function requireStaff(req,res,next){const u=currentUser(req);if(!u||!['admin','staff'].includes(u.role))return res.status(403).json({error:'Acesso administrativo necessário.'});req.user=u;next();}
function audit(admin,action,targetType,targetId,details={}){db.prepare('INSERT INTO admin_audit(admin_id,action,target_type,target_id,details) VALUES(?,?,?,?,?)').run(String(admin),action,targetType,String(targetId??''),JSON.stringify(details));}
const validEmail=e=>/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(String(e||'')) && String(e).length<=254;

app.use(helmet({contentSecurityPolicy:false}));
app.use(express.json());
app.use(morgan('tiny'));
app.use(express.static(path.join(__dirname,'public')));

app.post('/api/admin/login',(req,res)=>{if(!ADMIN_PASSWORD || String(req.body.password||'')!==ADMIN_PASSWORD)return res.status(401).json({error:'Senha inválida. Configure ADMIN_PASSWORD no ambiente.'});res.setHeader('Set-Cookie',`aa_admin=${cookieToken()}; HttpOnly; SameSite=Lax; Path=/; Max-Age=28800`);res.json({ok:true});});
app.post('/api/admin/logout',(req,res)=>{res.setHeader('Set-Cookie','aa_admin=; HttpOnly; SameSite=Lax; Path=/; Max-Age=0');res.json({ok:true});});
app.get('/api/admin/me',(req,res)=>res.json({authenticated:isAdmin(req)}));

app.get('/api/locations',(req,res)=>{const q=String(req.query.q||'').trim().toLowerCase();let rows=db.prepare('SELECT * FROM locations WHERE active=1 ORDER BY city, airport').all();if(q)rows=rows.filter(x=>`${x.city} ${x.airport} ${x.code} ${x.region} ${x.country}`.toLowerCase().includes(q));res.json(rows.map(cleanLocation));});
app.get('/api/admin/locations',requireAdmin,(req,res)=>res.json(db.prepare('SELECT * FROM locations ORDER BY active DESC, city, airport').all().map(cleanLocation)));
app.post('/api/admin/locations',requireAdmin,(req,res)=>{const b=req.body;try{const info=db.prepare(`INSERT INTO locations(city,region,country,airport,code,latitude,longitude,active) VALUES(?,?,?,?,?,?,?,?)`).run(String(b.city||'').trim(),String(b.region||'').trim(),String(b.country||'').trim(),String(b.airport||'').trim(),String(b.code||'').trim().toUpperCase(),b.latitude===''?null:Number(b.latitude),b.longitude===''?null:Number(b.longitude),b.active===false?0:1);res.status(201).json(cleanLocation(db.prepare('SELECT * FROM locations WHERE id=?').get(info.lastInsertRowid)));}catch(e){res.status(400).json({error:e.message.includes('UNIQUE')?'Código IATA já cadastrado':e.message});}});
app.put('/api/admin/locations/:id',requireAdmin,(req,res)=>{const b=req.body;try{db.prepare(`UPDATE locations SET city=?,region=?,country=?,airport=?,code=?,latitude=?,longitude=?,active=? WHERE id=?`).run(String(b.city||'').trim(),String(b.region||'').trim(),String(b.country||'').trim(),String(b.airport||'').trim(),String(b.code||'').trim().toUpperCase(),b.latitude===''?null:Number(b.latitude),b.longitude===''?null:Number(b.longitude),b.active===false?0:1,Number(req.params.id));const row=db.prepare('SELECT * FROM locations WHERE id=?').get(req.params.id);res.json(cleanLocation(row));}catch(e){res.status(400).json({error:e.message.includes('UNIQUE')?'Código IATA já cadastrado':e.message});}});
app.delete('/api/admin/locations/:id',requireAdmin,(req,res)=>{const used=db.prepare('SELECT COUNT(*) c FROM flights WHERE origin_id=? OR destination_id=?').get(req.params.id,req.params.id).c;if(used)return res.status(409).json({error:'Este local já está ligado a voos. Desative-o em vez de apagar.'});db.prepare('DELETE FROM locations WHERE id=?').run(req.params.id);res.json({ok:true});});

app.get('/api/flights',(req,res)=>{const {origin,destination,date,tripType='round'}=req.query;let sql=`SELECT f.*,o.city origin_city,o.airport origin_airport,o.code origin_code,d.city destination_city,d.airport destination_airport,d.code destination_code FROM flights f JOIN locations o ON o.id=f.origin_id JOIN locations d ON d.id=f.destination_id WHERE f.active=1 AND f.seats>0 AND o.active=1 AND d.active=1`;const args=[];if(origin){sql+=' AND o.code=?';args.push(String(origin).toUpperCase());}if(destination){sql+=' AND d.code=?';args.push(String(destination).toUpperCase());}if(date){sql+=' AND f.departure_date=?';args.push(date);}if(tripType==='oneway')sql+=" AND f.trip_type='oneway'";sql+=' ORDER BY f.price ASC, f.departure_time ASC';res.json(db.prepare(sql).all(...args).map(cleanFlight));});
app.get('/api/admin/flights',requireAdmin,(req,res)=>{res.json(db.prepare(`SELECT f.*,o.city origin_city,o.code origin_code,d.city destination_city,d.code destination_code FROM flights f JOIN locations o ON o.id=f.origin_id JOIN locations d ON d.id=f.destination_id ORDER BY f.departure_date DESC,f.departure_time`).all().map(cleanFlight));});
app.post('/api/admin/flights',requireAdmin,(req,res)=>{const b=req.body;try{const info=db.prepare(`INSERT INTO flights(origin_id,destination_id,flight_code,airline_name,departure_date,return_date,departure_time,arrival_time,duration_minutes,stops,cabin,price,seats,trip_type,active) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`).run(Number(b.origin_id),Number(b.destination_id),String(b.flight_code||'').trim(),String(b.airline_name||'André Aéreas').trim(),b.departure_date,b.return_date||null,b.departure_time,b.arrival_time,Number(b.duration_minutes||0),Number(b.stops||0),String(b.cabin||'Econômica'),Number(b.price||0),Number(b.seats||0),String(b.trip_type||'round'),b.active===false?0:1);res.status(201).json({id:info.lastInsertRowid});}catch(e){res.status(400).json({error:e.message});}});
app.put('/api/admin/flights/:id',requireAdmin,(req,res)=>{const b=req.body;try{db.prepare(`UPDATE flights SET origin_id=?,destination_id=?,flight_code=?,airline_name=?,departure_date=?,return_date=?,departure_time=?,arrival_time=?,duration_minutes=?,stops=?,cabin=?,price=?,seats=?,trip_type=?,active=? WHERE id=?`).run(Number(b.origin_id),Number(b.destination_id),String(b.flight_code||'').trim(),String(b.airline_name||'André Aéreas').trim(),b.departure_date,b.return_date||null,b.departure_time,b.arrival_time,Number(b.duration_minutes||0),Number(b.stops||0),String(b.cabin||'Econômica'),Number(b.price||0),Number(b.seats||0),String(b.trip_type||'round'),b.active===false?0:1,Number(req.params.id));res.json({ok:true});}catch(e){res.status(400).json({error:e.message});}});
app.delete('/api/admin/flights/:id',requireAdmin,(req,res)=>{db.prepare('DELETE FROM flights WHERE id=?').run(req.params.id);res.json({ok:true});});


// Customer accounts: passwords are scrypt-hashed; session tokens are stored only as SHA-256 digests.
const loginAttempts=new Map();
app.post('/api/auth/register',(req,res)=>{const name=String(req.body.name||'').trim(),email=String(req.body.email||'').trim().toLowerCase(),password=String(req.body.password||'');if(name.length<2||name.length>100||!validEmail(email)||password.length<10||password.length>200)return res.status(400).json({error:'Informe nome, e-mail válido e senha com pelo menos 10 caracteres.'});const h=hashPassword(password);try{const info=db.prepare('INSERT INTO users(name,email,password_hash) VALUES(?,?,?)').run(name,email,`${h.salt}:${h.hash}`);res.status(201).json({ok:true,user:{id:info.lastInsertRowid,name,email}});}catch(e){res.status(409).json({error:'Este e-mail já está cadastrado.'});}});
app.post('/api/auth/login',(req,res)=>{const ip=req.ip||'unknown',now=Date.now(),a=loginAttempts.get(ip)||{n:0,until:0};if(a.until>now&&a.n>=8)return res.status(429).json({error:'Muitas tentativas. Aguarde alguns minutos.'});const email=String(req.body.email||'').trim().toLowerCase(),password=String(req.body.password||'');const u=db.prepare('SELECT * FROM users WHERE email=? AND active=1').get(email);if(!u||!verifyPassword(password,u.password_hash)){a.n++;if(a.n>=8)a.until=now+15*60*1000;loginAttempts.set(ip,a);return res.status(401).json({error:'E-mail ou senha inválidos.'});}loginAttempts.delete(ip);const token=crypto.randomBytes(32).toString('base64url');db.prepare('INSERT INTO user_sessions(token_hash,user_id,expires_at) VALUES(?,?,?)').run(digest(token),u.id,now+7*86400000);res.setHeader('Set-Cookie',`aa_session=${encodeURIComponent(token)}; HttpOnly; SameSite=Lax; Path=/; Max-Age=604800${process.env.NODE_ENV==='production'?'; Secure':''}`);res.json({ok:true,user:{id:u.id,name:u.name,email:u.email,role:u.role}});});
app.post('/api/auth/logout',(req,res)=>{const token=(req.headers.cookie||'').split(';').map(v=>v.trim()).find(v=>v.startsWith('aa_session='))?.slice(11);if(token)db.prepare('DELETE FROM user_sessions WHERE token_hash=?').run(digest(decodeURIComponent(token)));res.setHeader('Set-Cookie','aa_session=; HttpOnly; SameSite=Lax; Path=/; Max-Age=0');res.json({ok:true});});
app.get('/api/auth/me',(req,res)=>{const u=currentUser(req);res.json({authenticated:!!u,user:u?{id:u.id,name:u.name,email:u.email,role:u.role}:null});});
app.post('/api/auth/forgot-password',(req,res)=>{const email=String(req.body.email||'').trim().toLowerCase(),u=db.prepare('SELECT id FROM users WHERE email=? AND active=1').get(email);const generic={ok:true,message:'Se a conta existir, serão enviados passos de recuperação.'};if(!u)return res.json(generic);const token=crypto.randomBytes(32).toString('base64url');db.prepare('INSERT INTO password_resets(token_hash,user_id,expires_at) VALUES(?,?,?)').run(digest(token),u.id,Date.now()+30*60*1000);if(process.env.NODE_ENV!=='production'&&process.env.EXPOSE_DEV_RESET_TOKEN==='true')return res.json({...generic,devToken:token});return res.json({...generic,note:'Envio de e-mail ainda depende de configurar um provedor SMTP/transacional.'});});
app.post('/api/auth/reset-password',(req,res)=>{const token=String(req.body.token||''),password=String(req.body.password||'');if(password.length<10)return res.status(400).json({error:'A nova senha deve ter pelo menos 10 caracteres.'});const r=db.prepare('SELECT * FROM password_resets WHERE token_hash=? AND used=0 AND expires_at>?').get(digest(token),Date.now());if(!r)return res.status(400).json({error:'Token inválido ou expirado.'});const h=hashPassword(password);const tx=db.transaction(()=>{db.prepare('UPDATE users SET password_hash=? WHERE id=?').run(`${h.salt}:${h.hash}`,r.user_id);db.prepare('UPDATE password_resets SET used=1 WHERE token_hash=?').run(digest(token));db.prepare('DELETE FROM user_sessions WHERE user_id=?').run(r.user_id);});tx();res.json({ok:true});});
app.post('/api/quotes', (req,res)=>{const u=currentUser(req),b=req.body;const origin=String(b.origin||'').trim().slice(0,120),destination=String(b.destination||'').trim().slice(0,120),date=String(b.departure_date||''),ret=String(b.return_date||'')||null,passengers=Number(b.passengers);if(!origin||!destination||origin===destination||!/^[0-9]{4}-[0-9]{2}-[0-9]{2}$/.test(date)||!Number.isInteger(passengers)||passengers<1||passengers>9)return res.status(400).json({error:'Confira origem, destino, data e quantidade de passageiros.'});let flight=null;if(b.flight_id){flight=db.prepare(`SELECT f.*,o.city origin_city,o.code origin_code,d.city destination_city,d.code destination_code FROM flights f JOIN locations o ON o.id=f.origin_id JOIN locations d ON d.id=f.destination_id WHERE f.id=? AND f.active=1 AND f.seats>=? AND f.departure_date=? AND o.active=1 AND d.active=1`).get(Number(b.flight_id),passengers,date);if(!flight)return res.status(400).json({error:'O voo selecionado não está mais disponível. Solicite uma cotação sem selecionar voo.'});}const info=db.prepare('INSERT INTO quotes(user_id,origin,destination,departure_date,return_date,passengers,selected_flight_id,flight_snapshot,quoted_price) VALUES(?,?,?,?,?,?,?,?,?)').run(u?.id||null,origin,destination,date,ret,passengers,flight?.id||null,flight?JSON.stringify({flight_code:flight.flight_code,airline_name:flight.airline_name,departure_time:flight.departure_time,arrival_time:flight.arrival_time,origin_code:flight.origin_code,destination_code:flight.destination_code,cabin:flight.cabin,price:flight.price}):null,flight?.price??null);const msg=`Olá! Quero cotar uma passagem pela André Aéreas.\nOrigem: ${origin}\nDestino: ${destination}\nIda: ${date}\nVolta: ${ret||'Não informada'}\nPassageiros: ${passengers}${flight?`\nVoo: ${flight.flight_code} — ${flight.airline_name}\nHorário: ${flight.departure_time}–${flight.arrival_time}\nPreço informado: R$ ${Number(flight.price).toFixed(2).replace('.',',')} (sujeito a confirmação)`:'\nNão selecionei um voo; preciso de opções e valores atualizados.'}\nSolicitação nº ${info.lastInsertRowid}`;res.status(201).json({id:info.lastInsertRowid,status:'pending',whatsapp_url:'https://wa.me/553591793515?text='+encodeURIComponent(msg)});});
app.get('/api/me/quotes',requireUser,(req,res)=>res.json(db.prepare('SELECT id,origin,destination,departure_date,return_date,passengers,quoted_price,status,created_at,updated_at FROM quotes WHERE user_id=? ORDER BY id DESC').all(req.user.id)));
app.get('/api/me/purchases',requireUser,(req,res)=>res.json(db.prepare('SELECT p.id,p.amount,p.status,p.confirmed_at,q.origin,q.destination,q.departure_date FROM purchases p JOIN quotes q ON q.id=p.quote_id WHERE p.user_id=? ORDER BY p.id DESC').all(req.user.id)));
app.get('/api/me/miles',requireUser,(req,res)=>{const balance=db.prepare('SELECT COALESCE(SUM(delta),0) n FROM mile_ledger WHERE user_id=?').get(req.user.id).n;res.json({balance,ledger:db.prepare('SELECT id,delta,kind,reason,created_at FROM mile_ledger WHERE user_id=? ORDER BY id DESC').all(req.user.id)});});
app.get('/api/admin/overview',requireAdmin,(req,res)=>res.json({customers:db.prepare("SELECT COUNT(*) n FROM users WHERE role='customer'").get().n,quotes:db.prepare('SELECT COUNT(*) n FROM quotes').get().n,purchases:db.prepare("SELECT COUNT(*) n FROM purchases WHERE status='confirmed'").get().n,miles:db.prepare('SELECT COALESCE(SUM(delta),0) n FROM mile_ledger').get().n}));
app.get('/api/admin/quotes',requireAdmin,(req,res)=>res.json(db.prepare('SELECT q.*,u.name customer_name,u.email customer_email FROM quotes q LEFT JOIN users u ON u.id=q.user_id ORDER BY q.id DESC').all()));
app.patch('/api/admin/quotes/:id/status',requireAdmin,(req,res)=>{const allowed=['pending','in_progress','quote_sent','purchase_confirmed','cancelled'],status=String(req.body.status||'');if(!allowed.includes(status))return res.status(400).json({error:'Status inválido.'});const info=db.prepare('UPDATE quotes SET status=?,updated_at=CURRENT_TIMESTAMP WHERE id=?').run(status,Number(req.params.id));if(!info.changes)return res.status(404).json({error:'Cotação não encontrada.'});audit('admin','quote_status','quote',req.params.id,{status});res.json({ok:true});});
app.get('/api/admin/loyalty-settings',requireAdmin,(req,res)=>res.json(db.prepare('SELECT * FROM loyalty_settings WHERE id=1').get()));
app.put('/api/admin/loyalty-settings',requireAdmin,(req,res)=>{const b=req.body;if(!Number.isInteger(Number(b.miles_per_purchase))||Number(b.miles_per_purchase)<0||!Number.isInteger(Number(b.min_redeem_miles))||Number(b.min_redeem_miles)<0||Number(b.benefit_per_mile)<0||Number(b.max_discount_percent)<0||Number(b.max_discount_percent)>100)return res.status(400).json({error:'Configurações inválidas.'});db.prepare('UPDATE loyalty_settings SET enabled=?,miles_per_purchase=?,benefit_per_mile=?,min_redeem_miles=?,max_discount_percent=?,expiry_days=?,approved=?,updated_at=CURRENT_TIMESTAMP WHERE id=1').run(b.enabled?1:0,Number(b.miles_per_purchase),Number(b.benefit_per_mile),Number(b.min_redeem_miles),Number(b.max_discount_percent),b.expiry_days?Number(b.expiry_days):null,b.approved?1:0);audit('admin','loyalty_settings','settings','1',b);res.json({ok:true});});
app.post('/api/admin/purchases',(req,res)=>{if(!isAdmin(req))return res.status(401).json({error:'Não autorizado'});const b=req.body,quote=db.prepare('SELECT * FROM quotes WHERE id=?').get(Number(b.quote_id));if(!quote)return res.status(404).json({error:'Cotação não encontrada.'});if(!quote.user_id)return res.status(400).json({error:'Para conceder milhas, a compra precisa estar vinculada a uma conta de cliente.'});const amount=Number(b.amount);if(!Number.isFinite(amount)||amount<0)return res.status(400).json({error:'Valor da compra inválido.'});const settings=db.prepare('SELECT * FROM loyalty_settings WHERE id=1').get();const tx=db.transaction(()=>{const info=db.prepare('INSERT INTO purchases(quote_id,user_id,amount,confirmed_by,notes) VALUES(?,?,?,?,?)').run(quote.id,quote.user_id,amount,'admin',String(b.notes||'').slice(0,1000));db.prepare("UPDATE quotes SET status='purchase_confirmed',updated_at=CURRENT_TIMESTAMP WHERE id=?").run(quote.id);if(settings.enabled&&settings.approved&&settings.miles_per_purchase>0){db.prepare('INSERT INTO mile_ledger(user_id,delta,kind,purchase_id,reason,admin_id,rule_snapshot) VALUES(?,?,?,?,?,?,?)').run(quote.user_id,settings.miles_per_purchase,'purchase_credit',info.lastInsertRowid,'Compra confirmada', 'admin',JSON.stringify(settings));}audit('admin','purchase_confirmed','purchase',info.lastInsertRowid,{quote_id:quote.id,amount});return info.lastInsertRowid;});try{const id=tx();res.status(201).json({ok:true,id,miles_awarded:settings.enabled&&settings.approved?settings.miles_per_purchase:0});}catch(e){res.status(409).json({error:'Esta cotação já possui uma compra registrada ou ocorreu um conflito.'});}});
app.get('/api/admin/users',requireAdmin,(req,res)=>res.json(db.prepare("SELECT u.id,u.name,u.email,u.role,u.active,u.created_at,COALESCE((SELECT SUM(delta) FROM mile_ledger m WHERE m.user_id=u.id),0) miles FROM users u ORDER BY u.id DESC").all()));
app.post('/api/admin/miles/adjust',(req,res)=>{if(!isAdmin(req))return res.status(401).json({error:'Não autorizado'});const b=req.body,userId=Number(b.user_id),delta=Number(b.delta),reason=String(b.reason||'').trim();if(!Number.isInteger(delta)||delta===0||!reason||reason.length>500)return res.status(400).json({error:'Informe quantidade inteira diferente de zero e motivo.'});const balance=db.prepare('SELECT COALESCE(SUM(delta),0) n FROM mile_ledger WHERE user_id=?').get(userId)?.n;if(balance===undefined)return res.status(404).json({error:'Cliente não encontrado.'});if(balance+delta<0)return res.status(400).json({error:'O ajuste não pode deixar o saldo negativo.'});db.prepare('INSERT INTO mile_ledger(user_id,delta,kind,reason,admin_id,rule_snapshot) VALUES(?,?,?,?,?,?)').run(userId,delta,'manual_adjustment',reason,'admin',JSON.stringify({manual:true}));audit('admin','miles_adjustment','user',userId,{delta,reason});res.json({ok:true,balance:balance+delta});});
app.get('/api/admin/audit',requireAdmin,(req,res)=>res.json(db.prepare('SELECT * FROM admin_audit ORDER BY id DESC LIMIT 300').all()));

app.get('/admin',(req,res)=>res.sendFile(path.join(__dirname,'public','admin.html')));
app.get('/conta',(req,res)=>res.sendFile(path.join(__dirname,'public','conta.html')));
app.get('/privacidade',(req,res)=>res.sendFile(path.join(__dirname,'public','privacidade.html')));
app.use((req,res,next)=>{if(req.path.startsWith('/api/')) return next(); res.sendFile(path.join(__dirname,'public','index.html'));});
app.listen(PORT,()=>console.log(`André Aéreas online em http://localhost:${PORT}`));
