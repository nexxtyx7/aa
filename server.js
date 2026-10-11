import express from 'express';
import helmet from 'helmet';
import morgan from 'morgan';
import Database from 'better-sqlite3';
import crypto from 'node:crypto';
import nodemailer from 'nodemailer';
import path from 'node:path';
import { mkdirSync } from 'node:fs';
import { searchProviderFlights, flightProviderStatus, getProviderOffer, FlightProviderError } from './services/flightProviders/index.js';
import { fileURLToPath } from 'node:url';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const app = express();
const PORT = Number(process.env.PORT || 3000);
const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD || '';
const SESSION_SECRET = process.env.SESSION_SECRET || crypto.randomBytes(32).toString('hex');
if (process.env.NODE_ENV === 'production' && (!ADMIN_PASSWORD || !process.env.SESSION_SECRET)) { throw new Error('Defina ADMIN_PASSWORD e SESSION_SECRET no ambiente de produção.'); }
const DATABASE_PATH = process.env.DATABASE_PATH || path.join(__dirname,'data','andre-aereas.db');
mkdirSync(path.dirname(path.resolve(DATABASE_PATH)), { recursive: true });
const db = new Database(DATABASE_PATH);

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
app.get('/api/flight-provider-status',(req,res)=>res.json(flightProviderStatus()));

const DEFAULT_AIRPORTS = [
  ['São Paulo','Aeroporto Internacional de São Paulo/Guarulhos','GRU','Brasil'],
  ['São Paulo','Aeroporto de Congonhas','CGH','Brasil'],
  ['Campinas','Aeroporto Internacional de Viracopos','VCP','Brasil'],
  ['Rio de Janeiro','Aeroporto Internacional do Galeão','GIG','Brasil'],
  ['Rio de Janeiro','Aeroporto Santos Dumont','SDU','Brasil'],
  ['Belo Horizonte','Aeroporto Internacional de Confins','CNF','Brasil'],
  ['Brasília','Aeroporto Internacional de Brasília','BSB','Brasil'],
  ['Porto Alegre','Aeroporto Salgado Filho','POA','Brasil'],
  ['Curitiba','Aeroporto Afonso Pena','CWB','Brasil'],
  ['Florianópolis','Aeroporto Internacional de Florianópolis','FLN','Brasil'],
  ['Salvador','Aeroporto Internacional de Salvador','SSA','Brasil'],
  ['Recife','Aeroporto Internacional do Recife','REC','Brasil'],
  ['Fortaleza','Aeroporto Internacional de Fortaleza','FOR','Brasil'],
  ['Natal','Aeroporto Internacional de Natal','NAT','Brasil'],
  ['João Pessoa','Aeroporto Internacional de João Pessoa','JPA','Brasil'],
  ['Maceió','Aeroporto Internacional de Maceió','MCZ','Brasil'],
  ['Aracaju','Aeroporto de Aracaju','AJU','Brasil'],
  ['Teresina','Aeroporto de Teresina','THE','Brasil'],
  ['São Luís','Aeroporto de São Luís','SLZ','Brasil'],
  ['Belém','Aeroporto Internacional de Belém','BEL','Brasil'],
  ['Manaus','Aeroporto Internacional de Manaus','MAO','Brasil'],
  ['Porto Velho','Aeroporto de Porto Velho','PVH','Brasil'],
  ['Rio Branco','Aeroporto de Rio Branco','RBR','Brasil'],
  ['Macapá','Aeroporto Internacional de Macapá','MCP','Brasil'],
  ['Boa Vista','Aeroporto Internacional de Boa Vista','BVB','Brasil'],
  ['Campo Grande','Aeroporto Internacional de Campo Grande','CGR','Brasil'],
  ['Cuiabá','Aeroporto Internacional de Cuiabá','CGB','Brasil'],
  ['Goiânia','Aeroporto de Goiânia','GYN','Brasil'],
  ['Foz do Iguaçu','Aeroporto Internacional de Foz do Iguaçu','IGU','Brasil'],
  ['Londrina','Aeroporto de Londrina','LDB','Brasil'],
  ['Uberlândia','Aeroporto de Uberlândia','UDI','Brasil'],
  ['Orlando','Orlando International Airport','MCO','Estados Unidos'],
  ['Miami','Miami International Airport','MIA','Estados Unidos'],
  ['Nova York','John F. Kennedy International Airport','JFK','Estados Unidos'],
  ['Lisboa','Aeroporto Humberto Delgado','LIS','Portugal'],
  ['Paris','Aeroporto Charles de Gaulle','CDG','França'],
  ['Londres','Heathrow Airport','LHR','Reino Unido'],
  ['Madri','Adolfo Suárez Madrid–Barajas Airport','MAD','Espanha'],
  ['Roma','Leonardo da Vinci–Fiumicino Airport','FCO','Itália'],
  ['Buenos Aires','Ministro Pistarini International Airport','EZE','Argentina'],
  ['Santiago','Arturo Merino Benítez International Airport','SCL','Chile']
].map(([city,airport,code,country],index)=>({id:`default-${code}`,city,airport,code,country,region:'',latitude:null,longitude:null,active:true,default_entry:true,sort_order:index}));
app.get('/api/locations',(req,res)=>{
  const q=String(req.query.q||'').trim().toLowerCase();
  const custom=db.prepare('SELECT * FROM locations WHERE active=1 ORDER BY city, airport').all().map(row=>({...cleanLocation(row),default_entry:false}));
  const customCodes=new Set(custom.map(row=>String(row.code).toUpperCase()));
  let rows=[...custom,...DEFAULT_AIRPORTS.filter(row=>!customCodes.has(row.code))];
  rows.sort((a,b)=>a.city.localeCompare(b.city,'pt-BR')||a.airport.localeCompare(b.airport,'pt-BR'));
  if(q) rows=rows.filter(x=>`${x.city} ${x.airport} ${x.code} ${x.region||''} ${x.country||''}`.toLowerCase().includes(q));
  res.json(rows);
});
app.get('/api/admin/locations',requireAdmin,(req,res)=>res.json(db.prepare('SELECT * FROM locations ORDER BY active DESC, city, airport').all().map(cleanLocation)));
app.post('/api/admin/locations',requireAdmin,(req,res)=>{const b=req.body;try{const info=db.prepare(`INSERT INTO locations(city,region,country,airport,code,latitude,longitude,active) VALUES(?,?,?,?,?,?,?,?)`).run(String(b.city||'').trim(),String(b.region||'').trim(),String(b.country||'').trim(),String(b.airport||'').trim(),String(b.code||'').trim().toUpperCase(),b.latitude===''?null:Number(b.latitude),b.longitude===''?null:Number(b.longitude),b.active===false?0:1);res.status(201).json(cleanLocation(db.prepare('SELECT * FROM locations WHERE id=?').get(info.lastInsertRowid)));}catch(e){res.status(400).json({error:e.message.includes('UNIQUE')?'Código IATA já cadastrado':e.message});}});
app.put('/api/admin/locations/:id',requireAdmin,(req,res)=>{const b=req.body;try{db.prepare(`UPDATE locations SET city=?,region=?,country=?,airport=?,code=?,latitude=?,longitude=?,active=? WHERE id=?`).run(String(b.city||'').trim(),String(b.region||'').trim(),String(b.country||'').trim(),String(b.airport||'').trim(),String(b.code||'').trim().toUpperCase(),b.latitude===''?null:Number(b.latitude),b.longitude===''?null:Number(b.longitude),b.active===false?0:1,Number(req.params.id));const row=db.prepare('SELECT * FROM locations WHERE id=?').get(req.params.id);res.json(cleanLocation(row));}catch(e){res.status(400).json({error:e.message.includes('UNIQUE')?'Código IATA já cadastrado':e.message});}});
app.delete('/api/admin/locations/:id',requireAdmin,(req,res)=>{const used=db.prepare('SELECT COUNT(*) c FROM flights WHERE origin_id=? OR destination_id=?').get(req.params.id,req.params.id).c;if(used)return res.status(409).json({error:'Este local já está ligado a voos. Desative-o em vez de apagar.'});db.prepare('DELETE FROM locations WHERE id=?').run(req.params.id);res.json({ok:true});});

app.get('/api/flights', async (req,res)=>{
  const origin=String(req.query.origin||'').trim().toUpperCase();
  const destination=String(req.query.destination||'').trim().toUpperCase();
  const departureDate=String(req.query.date||'').trim();
  const returnDate=String(req.query.returnDate||'').trim();
  const tripType=String(req.query.tripType||'round');
  const passengers=Number(req.query.passengers||1);
  const cabin=String(req.query.cabin||'economy').toLowerCase();
  const validDate=value=>/^\d{4}-\d{2}-\d{2}$/.test(value)&&!Number.isNaN(Date.parse(`${value}T00:00:00Z`))&&new Date(`${value}T00:00:00Z`).toISOString().slice(0,10)===value;
  if(!/^[A-Z]{3}$/.test(origin)||!/^[A-Z]{3}$/.test(destination)||origin===destination) return res.status(400).json({error:'Informe códigos IATA válidos e diferentes para origem e destino.',results:[],provider:flightProviderStatus()});
  if(!validDate(departureDate)||departureDate<new Date().toISOString().slice(0,10)) return res.status(400).json({error:'A data de ida é inválida ou já passou.',results:[],provider:flightProviderStatus()});
  if(tripType!=='oneway'&&(!validDate(returnDate)||returnDate<departureDate)) return res.status(400).json({error:'Informe uma data de volta válida, igual ou posterior à ida.',results:[],provider:flightProviderStatus()});
  if(!Number.isInteger(passengers)||passengers<1||passengers>9) return res.status(400).json({error:'A quantidade de passageiros deve ser entre 1 e 9.',results:[],provider:flightProviderStatus()});
  try {
    const provider=await searchProviderFlights({origin,destination,departureDate,returnDate:tripType==='oneway'?null:returnDate,passengers,cabin});
    let sql=`SELECT f.*,o.city origin_city,o.airport origin_airport,o.code origin_code,d.city destination_city,d.airport destination_airport,d.code destination_code FROM flights f JOIN locations o ON o.id=f.origin_id JOIN locations d ON d.id=f.destination_id WHERE f.active=1 AND f.seats>=? AND o.active=1 AND d.active=1 AND o.code=? AND d.code=? AND f.departure_date=?`;
    const args=[passengers,origin,destination,departureDate];
    if(tripType==='oneway') sql+=" AND f.trip_type='oneway'";
    else { sql+=" AND f.trip_type='round' AND f.return_date=?"; args.push(returnDate); }
    sql+=' ORDER BY f.price ASC, f.departure_time ASC';
    const manual=db.prepare(sql).all(...args).map(row=>({...cleanFlight(row),source_type:'manual',source:'Cadastro administrativo',currency:'BRL',provider_offer_id:null,return_info:null,outbound_segments:[]}));
    const results=[...provider.offers,...manual].sort((a,b)=>Number(a.price)-Number(b.price));
    res.json({results,provider:{provider:provider.provider,configured:provider.configured,status:provider.status,message:provider.message},total:results.length});
  } catch(error) {
    const status=error instanceof FlightProviderError?error.statusCode:502;
    console.error('[flight-search]',error?.code||error?.name||'ERROR');
    res.status(status).json({error:error instanceof FlightProviderError?error.message:'A fonte de voos está temporariamente indisponível. Tente novamente.',results:[],provider:flightProviderStatus()});
  }
});
app.get('/api/admin/flights',requireAdmin,(req,res)=>{res.json(db.prepare(`SELECT f.*,o.city origin_city,o.code origin_code,d.city destination_city,d.code destination_code FROM flights f JOIN locations o ON o.id=f.origin_id JOIN locations d ON d.id=f.destination_id ORDER BY f.departure_date DESC,f.departure_time`).all().map(cleanFlight));});
app.post('/api/admin/flights',requireAdmin,(req,res)=>{const b=req.body;try{const info=db.prepare(`INSERT INTO flights(origin_id,destination_id,flight_code,airline_name,departure_date,return_date,departure_time,arrival_time,duration_minutes,stops,cabin,price,seats,trip_type,active) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`).run(Number(b.origin_id),Number(b.destination_id),String(b.flight_code||'').trim(),String(b.airline_name||'André Aéreas').trim(),b.departure_date,b.return_date||null,b.departure_time,b.arrival_time,Number(b.duration_minutes||0),Number(b.stops||0),String(b.cabin||'Econômica'),Number(b.price||0),Number(b.seats||0),String(b.trip_type||'round'),b.active===false?0:1);res.status(201).json({id:info.lastInsertRowid});}catch(e){res.status(400).json({error:e.message});}});
app.put('/api/admin/flights/:id',requireAdmin,(req,res)=>{const b=req.body;try{db.prepare(`UPDATE flights SET origin_id=?,destination_id=?,flight_code=?,airline_name=?,departure_date=?,return_date=?,departure_time=?,arrival_time=?,duration_minutes=?,stops=?,cabin=?,price=?,seats=?,trip_type=?,active=? WHERE id=?`).run(Number(b.origin_id),Number(b.destination_id),String(b.flight_code||'').trim(),String(b.airline_name||'André Aéreas').trim(),b.departure_date,b.return_date||null,b.departure_time,b.arrival_time,Number(b.duration_minutes||0),Number(b.stops||0),String(b.cabin||'Econômica'),Number(b.price||0),Number(b.seats||0),String(b.trip_type||'round'),b.active===false?0:1,Number(req.params.id));res.json({ok:true});}catch(e){res.status(400).json({error:e.message});}});
app.delete('/api/admin/flights/:id',requireAdmin,(req,res)=>{db.prepare('DELETE FROM flights WHERE id=?').run(req.params.id);res.json({ok:true});});


// Customer accounts: passwords are scrypt-hashed; session tokens are stored only as SHA-256 digests.
const loginAttempts=new Map();

const mailConfigured=()=>Boolean(process.env.SMTP_HOST&&process.env.SMTP_USER&&process.env.SMTP_PASS&&process.env.MAIL_FROM);
function emailEscape(value){return String(value??'').replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));}
async function sendBrandedEmail({to,subject,kicker,title,greeting,paragraph,buttonText,buttonUrl,footnote}) {
  if(!mailConfigured()) return false;
  const transporter=nodemailer.createTransport({host:process.env.SMTP_HOST,port:Number(process.env.SMTP_PORT||587),secure:String(process.env.SMTP_SECURE||'false')==='true',auth:{user:process.env.SMTP_USER,pass:process.env.SMTP_PASS}});
  const baseUrl=String(process.env.APP_BASE_URL||'https://andre-aereas-40yk.onrender.com').replace(/\/$/,'');
  const safeName=emailEscape(greeting||'');
  const button=buttonText&&buttonUrl?'<p style="margin:28px 0 22px"><a href="'+buttonUrl+'" style="display:inline-block;background:#176fc1;color:#fff;text-decoration:none;padding:15px 24px;border-radius:10px;font-weight:700;font-size:15px">'+emailEscape(buttonText)+' &nbsp; ↗</a></p>':'';
  const html='<!doctype html><html><body style="margin:0;padding:0;background:#edf2f8;font-family:Arial,Helvetica,sans-serif;color:#132d49"><div style="display:none;max-height:0;overflow:hidden;opacity:0">'+emailEscape(paragraph||'')+'</div><table role="presentation" width="100%" cellspacing="0" cellpadding="0" style="background:#edf2f8;padding:28px 12px"><tr><td align="center"><table role="presentation" width="100%" cellspacing="0" cellpadding="0" style="max-width:600px;background:#fff;border-radius:18px;overflow:hidden"><tr><td style="background:#082849;padding:28px 30px 30px;color:#fff"><div style="font-size:12px;letter-spacing:2px;font-weight:800;color:#8fc5ff">ANDRÉ AÉREAS</div><div style="font-size:11px;letter-spacing:3px;color:#c3d8ee;margin-top:8px">SUA PRÓXIMA JORNADA COMEÇA AQUI</div><div style="margin-top:24px;height:4px;width:64px;background:#4ca3ff;border-radius:5px"></div><div style="font-size:25px;line-height:1.25;font-weight:800;margin-top:18px">'+emailEscape(title)+'</div></td></tr><tr><td style="padding:30px"><div style="font-size:11px;letter-spacing:1.8px;text-transform:uppercase;color:#2877bd;font-weight:800">'+emailEscape(kicker||'ANDRÉ AÉREAS')+'</div><h1 style="font-size:23px;line-height:1.3;margin:12px 0 16px;color:#122c48">'+(safeName?'Olá, '+safeName+'!':'Olá!')+'</h1><p style="font-size:15px;line-height:1.8;color:#50657c;margin:0">'+emailEscape(paragraph||'')+'</p>'+button+'<div style="background:#f2f7fc;border:1px solid #e1ebf5;border-radius:12px;padding:16px;font-size:12px;line-height:1.7;color:#61758a">'+emailEscape(footnote||'Se você não reconhece esta mensagem, pode ignorá-la.')+'</div></td></tr><tr><td style="padding:20px 30px;background:#f7f9fc;border-top:1px solid #e7edf4;color:#7b8da1;font-size:11px;line-height:1.7">André Aéreas · Sua viagem, com mais tranquilidade.<br><a href="'+baseUrl+'" style="color:#176fc1;text-decoration:none">Visitar nosso site</a><br>Esta é uma mensagem automática; não responda a este e-mail.</td></tr></table><div style="font-size:10px;color:#8798aa;padding:16px">© André Aéreas</div></td></tr></table></body></html>';
  await transporter.sendMail({from:process.env.MAIL_FROM,to,subject,html,text:[greeting?'Olá, '+greeting+'!':'Olá!',paragraph,buttonText&&buttonUrl?buttonText+': '+buttonUrl:'',footnote||''].filter(Boolean).join('\n\n')});
  return true;
}
app.post('/api/auth/register',async(req,res)=>{const name=String(req.body.name||'').trim(),email=String(req.body.email||'').trim().toLowerCase(),password=String(req.body.password||'');if(name.length<2||name.length>100||!validEmail(email)||password.length<10||password.length>200)return res.status(400).json({error:'Informe nome, e-mail válido e senha com pelo menos 10 caracteres.'});const h=hashPassword(password);try{const info=db.prepare('INSERT INTO users(name,email,password_hash) VALUES(?,?,?)').run(name,email,`${h.salt}:${h.hash}`);if(mailConfigured()){try{const baseUrl=String(process.env.APP_BASE_URL||'https://andre-aereas-40yk.onrender.com').replace(/\/$/,'');await sendBrandedEmail({to:email,subject:'Boas-vindas à André Aéreas',kicker:'BEM-VINDO A BORDO',title:'Sua próxima jornada começa aqui',greeting:name,paragraph:'Sua conta foi criada com sucesso! Agora você pode acessar sua área pessoal e acompanhar suas cotações e informações de viagem.',buttonText:'Acessar minha conta',buttonUrl:baseUrl+'/conta',footnote:'Guarde este e-mail para consultar os dados da sua conta. Se você não criou esta conta, entre em contato com o suporte.'});}catch(mailError){console.error('Conta criada, mas falhou o e-mail de boas-vindas:',mailError.message);}}res.status(201).json({ok:true,user:{id:info.lastInsertRowid,name,email},emailSent:mailConfigured()});}catch(e){res.status(409).json({error:'Este e-mail já está cadastrado.'});}});
app.post('/api/auth/login',(req,res)=>{const ip=req.ip||'unknown',now=Date.now(),a=loginAttempts.get(ip)||{n:0,until:0};if(a.until>now&&a.n>=8)return res.status(429).json({error:'Muitas tentativas. Aguarde alguns minutos.'});const email=String(req.body.email||'').trim().toLowerCase(),password=String(req.body.password||'');const u=db.prepare('SELECT * FROM users WHERE email=? AND active=1').get(email);if(!u||!verifyPassword(password,u.password_hash)){a.n++;if(a.n>=8)a.until=now+15*60*1000;loginAttempts.set(ip,a);return res.status(401).json({error:'E-mail ou senha inválidos.'});}loginAttempts.delete(ip);const token=crypto.randomBytes(32).toString('base64url');db.prepare('INSERT INTO user_sessions(token_hash,user_id,expires_at) VALUES(?,?,?)').run(digest(token),u.id,now+7*86400000);res.setHeader('Set-Cookie',`aa_session=${encodeURIComponent(token)}; HttpOnly; SameSite=Lax; Path=/; Max-Age=604800${process.env.NODE_ENV==='production'?'; Secure':''}`);res.json({ok:true,user:{id:u.id,name:u.name,email:u.email,role:u.role}});});
app.post('/api/auth/logout',(req,res)=>{const token=(req.headers.cookie||'').split(';').map(v=>v.trim()).find(v=>v.startsWith('aa_session='))?.slice(11);if(token)db.prepare('DELETE FROM user_sessions WHERE token_hash=?').run(digest(decodeURIComponent(token)));res.setHeader('Set-Cookie','aa_session=; HttpOnly; SameSite=Lax; Path=/; Max-Age=0');res.json({ok:true});});
app.get('/api/auth/me',(req,res)=>{const u=currentUser(req);res.json({authenticated:!!u,user:u?{id:u.id,name:u.name,email:u.email,role:u.role}:null});});
app.post('/api/auth/forgot-password',async(req,res)=>{const email=String(req.body.email||'').trim().toLowerCase(),u=db.prepare('SELECT id,name,email FROM users WHERE email=? AND active=1').get(email);const generic={ok:true,message:'Se a conta existir, enviaremos instruções de recuperação para o e-mail cadastrado.'};if(!u)return res.json(generic);const token=crypto.randomBytes(32).toString('base64url');db.prepare('INSERT INTO password_resets(token_hash,user_id,expires_at) VALUES(?,?,?)').run(digest(token),u.id,Date.now()+30*60*1000);if(mailConfigured()){try{const baseUrl=String(process.env.APP_BASE_URL||'https://andre-aereas-40yk.onrender.com').replace(/\/$/,'');const link=baseUrl+'/conta?reset='+encodeURIComponent(token);await sendBrandedEmail({to:u.email,subject:'Recuperação de senha · André Aéreas',kicker:'SEGURANÇA DA CONTA',title:'Vamos recuperar seu acesso',greeting:u.name,paragraph:'Recebemos uma solicitação para redefinir a senha da sua conta. Use o botão abaixo para escolher uma nova senha.',buttonText:'Redefinir minha senha',buttonUrl:link,footnote:'Por segurança, este link expira em 30 minutos e só pode ser usado uma vez. Se você não pediu a recuperação, ignore esta mensagem.'});return res.json(generic);}catch(err){console.error('Falha no envio de recuperação:',err.message);return res.status(503).json({error:'Não foi possível enviar o e-mail agora. Confira as configurações SMTP no Render e tente novamente.'});}}if(process.env.NODE_ENV!=='production'&&process.env.EXPOSE_DEV_RESET_TOKEN==='true')return res.json({...generic,devToken:token});return res.status(503).json({error:'A recuperação por e-mail ainda não está configurada. Configure SMTP_HOST, SMTP_USER, SMTP_PASS e MAIL_FROM no ambiente do servidor.'});});
app.post('/api/auth/reset-password',(req,res)=>{const token=String(req.body.token||''),password=String(req.body.password||'');if(password.length<10)return res.status(400).json({error:'A nova senha deve ter pelo menos 10 caracteres.'});const r=db.prepare('SELECT * FROM password_resets WHERE token_hash=? AND used=0 AND expires_at>?').get(digest(token),Date.now());if(!r)return res.status(400).json({error:'Token inválido ou expirado.'});const h=hashPassword(password);const tx=db.transaction(()=>{db.prepare('UPDATE users SET password_hash=? WHERE id=?').run(`${h.salt}:${h.hash}`,r.user_id);db.prepare('UPDATE password_resets SET used=1 WHERE token_hash=?').run(digest(token));db.prepare('DELETE FROM user_sessions WHERE user_id=?').run(r.user_id);});tx();res.json({ok:true});});
app.post('/api/quotes', requireUser, async (req,res)=>{
  const u=req.user,b=req.body||{};
  const origin=String(b.origin||'').trim().slice(0,120),destination=String(b.destination||'').trim().slice(0,120);
  const date=String(b.departure_date||''),ret=String(b.return_date||'')||null,passengers=Number(b.passengers);
  const validIsoDate=value=>/^\d{4}-\d{2}-\d{2}$/.test(value)&&!Number.isNaN(Date.parse(`${value}T00:00:00Z`))&&new Date(`${value}T00:00:00Z`).toISOString().slice(0,10)===value;
  if(!origin||!destination||origin===destination||!validIsoDate(date)||date<new Date().toISOString().slice(0,10)||!Number.isInteger(passengers)||passengers<1||passengers>9) return res.status(400).json({error:'Confira origem, destino, data e quantidade de passageiros.'});
  if(ret&&(!validIsoDate(ret)||ret<date)) return res.status(400).json({error:'A data de volta deve ser válida e igual ou posterior à ida.'});
  let flight=null,providerFlight=null,flightId=null;
  if(b.provider_offer_id){
    try {
      providerFlight=await getProviderOffer(b.provider_offer_id);
      const requestedOrigin=(origin.match(/\(([A-Z]{3})\)/)||[])[1]||origin.toUpperCase();
      const requestedDestination=(destination.match(/\(([A-Z]{3})\)/)||[])[1]||destination.toUpperCase();
      if(providerFlight.origin_code!==requestedOrigin||providerFlight.destination_code!==requestedDestination||providerFlight.departure_date!==date) return res.status(409).json({error:'A oferta não corresponde mais à rota ou à data escolhida. Faça uma nova pesquisa.'});
      if(ret&&providerFlight.return_date!==ret) return res.status(409).json({error:'A data de volta da oferta mudou ou não corresponde à pesquisa. Faça uma nova pesquisa.'});
      if(providerFlight.passenger_count!==null&&providerFlight.passenger_count!==passengers) return res.status(409).json({error:'A quantidade de passageiros da oferta não corresponde à pesquisa. Faça uma nova pesquisa.'});
    } catch(error) {
      const status=error instanceof FlightProviderError?error.statusCode:502;
      return res.status(status).json({error:error instanceof FlightProviderError?error.message:'Não foi possível validar a oferta atual. Faça uma nova pesquisa.'});
    }
  } else if(b.flight_id){
    flight=db.prepare(`SELECT f.*,o.city origin_city,o.code origin_code,d.city destination_city,d.code destination_code FROM flights f JOIN locations o ON o.id=f.origin_id JOIN locations d ON d.id=f.destination_id WHERE f.id=? AND f.active=1 AND f.seats>=? AND f.departure_date=? AND o.active=1 AND d.active=1`).get(Number(b.flight_id),passengers,date);
    if(!flight)return res.status(400).json({error:'O voo cadastrado não está mais disponível. Faça uma nova pesquisa ou solicite cotação sem selecionar voo.'});
    flightId=flight.id;
  }
  const snapshot=providerFlight?JSON.stringify({source:providerFlight.source,provider_offer_id:providerFlight.provider_offer_id,airline_name:providerFlight.airline_name,flight_code:providerFlight.flight_code,departure_time:providerFlight.departure_time,arrival_time:providerFlight.arrival_time,origin_code:providerFlight.origin_code,destination_code:providerFlight.destination_code,departure_date:providerFlight.departure_date,return_date:providerFlight.return_date,cabin:providerFlight.cabin,passenger_count:providerFlight.passenger_count,return_info:providerFlight.return_info,outbound_segments:providerFlight.outbound_segments,return_segments:providerFlight.return_segments,currency:providerFlight.currency,price:providerFlight.price,price_status:providerFlight.price_status,expires_at:providerFlight.expires_at}):flight?JSON.stringify({source:'Cadastro administrativo',flight_code:flight.flight_code,airline_name:flight.airline_name,departure_time:flight.departure_time,arrival_time:flight.arrival_time,origin_code:flight.origin_code,destination_code:flight.destination_code,cabin:flight.cabin,price:flight.price,currency:'BRL'}):null;
  const price=providerFlight?.price??flight?.price??null;
  const info=db.prepare('INSERT INTO quotes(user_id,origin,destination,departure_date,return_date,passengers,selected_flight_id,flight_snapshot,quoted_price) VALUES(?,?,?,?,?,?,?,?,?)').run(u?.id||null,origin,destination,date,ret,passengers,flightId,snapshot,price);
  const priceText=providerFlight?`\nPreço retornado pela fonte: ${providerFlight.currency} ${Number(providerFlight.price).toFixed(2)} (total informado para a oferta; sujeito a nova confirmação)`:flight?`\nPreço cadastrado: R$ ${Number(flight.price).toFixed(2).replace('.',',')} (sujeito a confirmação)`:'';
  const segmentText=(segments,label)=>Array.isArray(segments)&&segments.length?`\n${label}:\n`+segments.map((seg,i)=>`${i+1}. ${seg.airline_name||'Companhia não informada'}${seg.flight_code?` · ${seg.flight_code}`:''} — ${seg.origin_city||seg.origin_code||'?'} (${seg.origin_code||'?'}) ${seg.departure_time||'horário não informado'} → ${seg.destination_city||seg.destination_code||'?'} (${seg.destination_code||'?'}) ${seg.arrival_time||'horário não informado'}${i<segments.length-1?' · conexão':''}`).join('\n'):'';
  const flightText=providerFlight?`\nCompanhia: ${providerFlight.airline_name||'Não informada'}\nVoo: ${providerFlight.flight_code||'Não informado'}\nHorário de ida: ${providerFlight.departure_time||'Não informado'}–${providerFlight.arrival_time||'Não informado'}\nClasse: ${providerFlight.cabin||'Não informada'}\nIdentificador original da oferta: ${providerFlight.provider_offer_id||'Não informado'}\nFonte: ${providerFlight.source||'Não informada'}${segmentText(providerFlight.outbound_segments,'Trechos da ida')}${segmentText(providerFlight.return_segments,'Trechos da volta')}`:flight?`\nVoo: ${flight.flight_code} — ${flight.airline_name}\nHorário: ${flight.departure_time}–${flight.arrival_time}`:'\nNão selecionei um voo; preciso de opções e valores atualizados.';
  const msg=`Olá! Quero cotar uma passagem pela André Aéreas.\nOrigem: ${origin}\nDestino: ${destination}\nIda: ${date}\nVolta: ${ret||'Não informada'}\nPassageiros: ${passengers}${flightText}${priceText}\nO preço e a disponibilidade estão sujeitos à confirmação. Esta mensagem não representa reserva ou compra.\nSolicitação nº ${info.lastInsertRowid}`;
  const phone=String(process.env.WHATSAPP_PHONE||'553591793515').replace(/\D/g,'');
  res.status(201).json({id:info.lastInsertRowid,status:'pending',whatsapp_url:`https://wa.me/${phone}?text=${encodeURIComponent(msg)}`});
});
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

function sendPage(res, filename) {
  const publicPath = path.join(__dirname, 'public', filename);
  const rootPath = path.join(__dirname, filename);
  res.sendFile(publicPath, (error) => {
    if (!error) return;
    res.sendFile(rootPath, (rootError) => {
      if (rootError) {
        console.error(`Página não encontrada: ${filename}`);
        if (!res.headersSent) res.status(404).send('Página não encontrada. Verifique os arquivos HTML do site.');
      }
    });
  });
}
app.get('/admin',(req,res)=>sendPage(res,'admin.html'));
app.get('/conta',(req,res)=>sendPage(res,'conta.html'));
app.get('/privacidade',(req,res)=>sendPage(res,'privacidade.html'));
app.use((req,res,next)=>{if(req.path.startsWith('/api/')) return next(); sendPage(res,'index.html');});
app.listen(PORT,()=>console.log(`André Aéreas online em http://localhost:${PORT}`));
