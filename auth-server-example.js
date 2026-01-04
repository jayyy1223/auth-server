// ============================================================================
// LITEWARE AUTHENTICATION SERVER v5.0 - OBFUSCATED
// ============================================================================
const _0x4e8a=['express','body-parser','crypto','fs','path'];
const _0x2f3b=a=>Buffer.from(a,'base64').toString();
const _0x9c1d=a=>require(a);
const express=_0x9c1d(_0x4e8a[0]),bodyParser=_0x9c1d(_0x4e8a[1]),crypto=_0x9c1d(_0x4e8a[2]),fs=_0x9c1d(_0x4e8a[3]),path=_0x9c1d(_0x4e8a[4]);
const app=express();
let _0xmulter=null;try{_0xmulter=_0x9c1d('multer');}catch(e){}

// Obfuscated config
const _0xCFG=(()=>{const _0x1a=[0x1e,0x3c,0x78,0xf0,0x1e];return{
sR:!0,sT:3e4,sA:_0x2f3b('c2hhMjU2'),nE:12e4,tT:3e4,
mRPS:10,mRPM:60,bT:5,seT:36e5,sRI:3e5,mSPH:2,hI:3e4,mMH:3,
rE:!0,rS:!0,hE:!0,bA:!0,aT:5,abT:3,dP:!0,cE:!0,tBD:3e5,
bUA:[_0x2f3b('Y3VybA=='),_0x2f3b('d2dldA=='),_0x2f3b('cHl0aG9uLXJlcXVlc3Rz'),_0x2f3b('cHl0aG9uLXVybGxpYg=='),
_0x2f3b('cG9zdG1hbg=='),_0x2f3b('aW5zb21uaWE='),_0x2f3b('aHR0cGll'),_0x2f3b('YXhpb3M='),
_0x2f3b('Z28taHR0cC1jbGllbnQ='),_0x2f3b('amF2YS8='),_0x2f3b('cGVybA=='),_0x2f3b('cnVieQ=='),
_0x2f3b('bGlid3d3'),_0x2f3b('bHdwLQ=='),_0x2f3b('bWVjaGFuaXpl'),_0x2f3b('c2NyYXB5'),
_0x2f3b('aHR0cGNsaWVudA=='),_0x2f3b('b2todHRw'),_0x2f3b('cmVxdWVzdC8='),_0x2f3b('bm9kZS1mZXRjaA==')],
iPE:!0,sC:[],eA:_0x2f3b('YWVzLTI1Ni1nY20='),kRI:864e5};})();

// Obfuscated secrets - Use env vars in production!
const _0xSEC=(()=>{
const _e=process.env;
const _k1=_0x2f3b('QUJDSkRXUTkxRDkyMTlEMjFKS1dEREtRQUQ5MTJR');
const _k2=_0x2f3b('TElURVdBUkVfU0VDUkVUX0tFWV8yMDI2X1Yz');
return{
aS:_e.AUTH_APP_SECRET||_k1,
rK:_e.AUTH_RESPONSE_KEY||_k2,
eK:_e.AUTH_ENCRYPTION_KEY||crypto.randomBytes(32),
adS:_e.AUTH_ADMIN_SECRET||crypto.randomBytes(32).toString('hex')
};})();

// Data stores
const _0xDS={
uN:new Map(),rL:new Map(),sW:new Map(),bT:new Map(),
bIP:new Set(),tBIP:new Map(),sIP:new Set(),iPR:new Map(),
bHW:new Set(),aS:new Map(),sHB:new Map(),rP:new Map(),hH:new Map(),
cA:[],cAC:new Map(),
wIP:new Set([_0x2f3b('Ojox'),_0x2f3b('MTI3LjAuMC4x'),_0x2f3b('OjpmZmZmOjEyNy4wLjAuMQ==')]),
wK:new Set(),
lic:new Map([[_0x2f3b('TElURS1URVNULTEyMzQtNTY3OA=='),{v:!0,h:null,a:!1,c:Date.now(),e:Date.now()+315576e5,t:'premium'}],
[_0x2f3b('TElURS1ERU1PLUFBQUEtQkJCQg=='),{v:!0,h:null,a:!1,c:Date.now(),e:Date.now()+2592e6,t:'trial'}]]),
oK:{k:process.env.OWNER_KEY||'c441afdc097e1b93b9835335ef049b27740c0fd6113d2de095c36d6364bb1298',c:Date.now(),lU:null,rA:Date.now()+864e5,h:'GPU-7af1ba56-2242-cd8c-f9e3-cb91eede2235',allowedIP:null},
sS:{e:!0,m:!1,l:!1,wL:!1,aE:!0,sT:Date.now()},
st:{tR:0,bR:0,sA:0,fA:0,cA:0,dB:0}
};

// Crypto utils
const _0xCU={
gT:(l=32)=>crypto.randomBytes(l).toString('hex'),
s:(d,k=_0xSEC.aS)=>crypto.createHmac('sha256',k).update(d).digest('hex'),
v:(d,sig,k=_0xSEC.aS)=>{const exp=_0xCU.s(d,k);try{return crypto.timingSafeEqual(Buffer.from(sig,'hex'),Buffer.from(exp,'hex'));}catch{return!1;}},
enc:(d,k=_0xSEC.eK)=>{const iv=crypto.randomBytes(16);const kB=typeof k==='string'?Buffer.from(k,'hex'):k;
const c=crypto.createCipheriv('aes-256-gcm',kB.slice(0,32),iv);let e=c.update(JSON.stringify(d),'utf8','hex');
e+=c.final('hex');return{iv:iv.toString('hex'),d:e,t:c.getAuthTag().toString('hex')};},
dec:(eD,k=_0xSEC.eK)=>{try{const kB=typeof k==='string'?Buffer.from(k,'hex'):k;
const dc=crypto.createDecipheriv('aes-256-gcm',kB.slice(0,32),Buffer.from(eD.iv,'hex'));
dc.setAuthTag(Buffer.from(eD.t,'hex'));let d=dc.update(eD.d,'hex','utf8');d+=dc.final('utf8');
return JSON.parse(d);}catch{return null;}},
h:d=>crypto.createHash('sha256').update(d).digest('hex'),
gLK:()=>{const s=[];for(let i=0;i<3;i++)s.push(crypto.randomBytes(2).toString('hex').toUpperCase());return`LITE-${s.join('-')}`;},
gST:(hw,ip)=>_0xCU.h(JSON.stringify({hw,ip,c:Date.now(),r:crypto.randomBytes(16).toString('hex')})+_0xSEC.aS)
};

// Response builder
const _0xRB={
b:(d,ch=null,enc=_0xCFG.rE)=>{const ts=Date.now().toString(),nc=_0xCU.gT(8);
const r={...d,server_time:Date.now(),server_version:'5.0'};
const sD=JSON.stringify(r)+'|'+(ch||'')+'|'+ts;const sig=_0xCU.s(sD,_0xSEC.rK);
const sR={...r,_ts:ts,_nonce:nc,_challenge:ch||'',_sig:sig};
if(enc&&d.success)return{encrypted:!0,payload:_0xCU.enc(sR),_ts:ts};return sR;},
e:(m,c=400)=>({success:!1,message:m,error_code:c,server_time:Date.now()}),
s:(d,ch=null)=>_0xRB.b({success:!0,...d},ch)
};

// Helpers
const gIP=r=>{const f=r.headers['x-forwarded-for'];if(f)return f.split(',')[0].trim();return r.ip||r.connection?.remoteAddress||'unknown';};
const isWL=ip=>{if(!ip)return!1;const c=ip.replace('::ffff:','');return _0xDS.wIP.has(ip)||_0xDS.wIP.has(c);};

// Security headers
app.use((req,res,next)=>{
res.header('Access-Control-Allow-Origin','*');
res.header('Access-Control-Allow-Methods','GET, POST, OPTIONS');
res.header('Access-Control-Allow-Headers','Origin, X-Requested-With, Content-Type, Accept, Authorization, X-Signature, X-Timestamp, X-Nonce, X-Challenge, X-DDoS-Challenge');
res.header('X-Content-Type-Options','nosniff');res.header('X-Frame-Options','DENY');
res.header('X-XSS-Protection','1; mode=block');res.header('Strict-Transport-Security','max-age=31536000; includeSubDomains; preload');
res.header('Content-Security-Policy',"default-src 'self'");res.header('Referrer-Policy','strict-origin-when-cross-origin');
res.header('Permissions-Policy','geolocation=(), microphone=(), camera=()');
res.header('Cache-Control','no-store, no-cache, must-revalidate, proxy-revalidate');
res.header('Pragma','no-cache');res.header('Expires','0');res.removeHeader('X-Powered-By');
if(req.method==='OPTIONS')return res.sendStatus(200);_0xDS.st.tR++;next();
});

// UA filter
app.use((req,res,next)=>{const ip=gIP(req);if(isWL(ip))return next();
const ua=(req.headers['user-agent']||'').toLowerCase();
for(const b of _0xCFG.bUA){if(ua.includes(b.toLowerCase())){_0xDS.st.bR++;
return setTimeout(()=>res.status(400).json(_0xRB.e('Bad request')),1e3+Math.random()*2e3);}}
if(!ua||ua.length<10)return res.status(400).json(_0xRB.e('Bad request'));next();
});

// Ban check
app.use((req,res,next)=>{const ip=gIP(req);
if(_0xDS.bIP.has(ip)){_0xDS.st.bR++;return res.status(403).json(_0xRB.e('Access denied',403));}
const tB=_0xDS.tBIP.get(ip);if(tB&&Date.now()<tB.e){_0xDS.st.bR++;
return res.status(429).json({success:!1,message:'Too many requests',retry_after:Math.ceil((tB.e-Date.now())/1e3)});}
else if(tB)_0xDS.tBIP.delete(ip);next();
});

// DDoS protection
app.use((req,res,next)=>{if(!_0xCFG.dP)return next();const ip=gIP(req);if(isWL(ip))return next();
const now=Date.now(),sec=Math.floor(now/1e3),min=Math.floor(now/6e4);
const sK=`${ip}:${sec}`,mK=`${ip}:m:${min}`,bK=`${ip}:b:${Math.floor(now/100)}`;
const sC=(_0xDS.sW.get(sK)||0)+1,mC=(_0xDS.sW.get(mK)||0)+1,bC=(_0xDS.bT.get(bK)||0)+1;
_0xDS.sW.set(sK,sC);_0xDS.sW.set(mK,mC);_0xDS.bT.set(bK,bC);
let blocked=!1,reason='';
if(bC>_0xCFG.bT){blocked=!0;reason='Burst';}
else if(sC>_0xCFG.mRPS){blocked=!0;reason='Rate/s';}
else if(mC>_0xCFG.mRPM){blocked=!0;reason='Rate/m';}
if(blocked){_0xDS.st.dB++;if(!_0xDS.sIP.has(ip)){_0xDS.sIP.add(ip);return res.status(429).json({success:!1,message:'Slow down',warning:!0});}
_0xDS.tBIP.set(ip,{r:reason,c:now,e:now+_0xCFG.tBD});console.log(`[DDoS] Banned ${ip} - ${reason}`);
return res.status(429).json({success:!1,message:'Blocked',retry_after:_0xCFG.tBD/1e3});}next();
});

// Behavioral analysis
app.use((req,res,next)=>{if(!_0xCFG.bA)return next();const ip=gIP(req);if(isWL(ip))return next();
if(!_0xDS.rP.has(ip))_0xDS.rP.set(ip,{ep:{},rT:[],aS:0,lR:Date.now()});
const p=_0xDS.rP.get(ip),now=Date.now();p.ep[req.path]=(p.ep[req.path]||0)+1;
p.rT.push(now);if(p.rT.length>100)p.rT.shift();let aS=0;
if(p.rT.length>=10){const r=p.rT.slice(-10);if((r[9]-r[0])/9<100)aS+=2;}
if(Object.keys(p.ep).filter(e=>e.includes('admin')).length>5)aS+=2;
if(Object.keys(p.ep).length>20)aS+=2;p.aS=aS;p.lR=now;
if(aS>=_0xCFG.aT){console.log(`[Anomaly] ${ip} (${aS})`);_0xDS.sIP.add(ip);}next();
});

app.use(bodyParser.urlencoded({extended:!0,limit:'1mb'}));
app.use(bodyParser.json({limit:'1mb'}));

// Honeypots
const _0xHP=['/admin','/wp-admin','/phpmyadmin','/.env','/config.php','/backup','/db','/database','/sql','/mysql','/dump',
'/api/v1/admin','/api/admin','/administrator','/cpanel','/.git','/.svn','/debug','/test','/dev','/staging',
'/wp-login.php','/xmlrpc.php','/wp-content','/wp-includes','/shell','/cmd','/exec','/eval','/system'];
_0xHP.forEach(p=>{app.all(p,(req,res)=>{const ip=gIP(req);console.log(`[HP] ${ip} -> ${p}`);
const h=(_0xDS.hH.get(ip)||0)+1;_0xDS.hH.set(ip,h);
if(h>=_0xCFG.abT){_0xDS.bIP.add(ip);console.log(`[HP] Banned ${ip}`);}
setTimeout(()=>res.status(404).json({error:'Not found'}),2e3+Math.random()*3e3);});});

// Health
app.get('/',(req,res)=>res.json({status:'online',version:'5.0',time:Date.now(),uptime:Math.floor((Date.now()-_0xDS.sS.sT)/1e3)}));
app.get('/health',(req,res)=>res.json({status:'ok',uptime:process.uptime(),memory:process.memoryUsage().heapUsed}));
app.get('/auth/health',(req,res)=>res.json({status:'ok',server_time:Date.now(),auth_enabled:_0xDS.sS.aE}));

// Status
app.all('/auth/status',(req,res)=>{const ip=gIP(req),hw=req.body?.hwid;
const isB=_0xDS.bIP.has(ip)||(hw&&_0xDS.bHW.has(hw));
res.json({success:!0,server_enabled:_0xDS.sS.e,server_disabled:!_0xDS.sS.e,auth_enabled:_0xDS.sS.aE,
maintenance:_0xDS.sS.m,lockdown:_0xDS.sS.l,website_locked:_0xDS.sS.wL,banned:isB,server_time:Date.now(),version:'5.0'});});

// Auth endpoint
app.post('/auth/validate',(req,res)=>{const ip=gIP(req);const{license_key:lk,hwid:hw,app_secret:as,challenge:ch}=req.body;
if(as!==_0xSEC.aS){_0xDS.st.fA++;return res.status(401).json(_0xRB.e('Invalid credentials',401));}
if(!_0xDS.sS.e||_0xDS.sS.l)return res.json(_0xRB.b({success:!1,message:_0xDS.sS.l?'Lockdown':'Disabled'},ch,!1));
if(_0xDS.sS.m)return res.json(_0xRB.b({success:!1,message:'Maintenance'},ch,!1));
if(_0xDS.bIP.has(ip))return res.status(403).json(_0xRB.e('Access denied',403));
if(hw&&_0xDS.bHW.has(hw))return res.status(403).json(_0xRB.e('Hardware banned',403));
if(!lk||!hw){_0xDS.st.fA++;return res.json(_0xRB.b({success:!1,message:'Missing key/HWID'},ch,!1));}
const lic=_0xDS.lic.get(lk);
if(!lic){_0xDS.st.fA++;const att=(_0xDS.cAC.get(hw)||{count:0}).count+1;
_0xDS.cAC.set(hw,{count:att,lastAttempt:Date.now()});
_0xDS.cA.push({ts:Date.now(),ip,hw,lk,type:'invalid_key'});
return res.json(_0xRB.b({success:!1,message:'Invalid key'},ch,!1));}
if(!lic.v){_0xDS.st.fA++;return res.json(_0xRB.b({success:!1,message:'Revoked'},ch,!1));}
if(Date.now()>lic.e){_0xDS.st.fA++;return res.json(_0xRB.b({success:!1,message:'Expired'},ch,!1));}
if(lic.h&&lic.h!==hw){_0xDS.st.fA++;_0xDS.cA.push({ts:Date.now(),ip,hw,lk,type:'hwid_mismatch',expected:lic.h});
return res.json(_0xRB.b({success:!1,message:'Wrong hardware'},ch,!1));}
if(!lic.h){lic.h=hw;lic.a=!0;lic.aAt=Date.now();lic.aIP=ip;}
const exS=Array.from(_0xDS.aS.values()).filter(s=>s.hw===hw);
if(exS.length>=_0xCFG.mSPH){const old=exS.sort((a,b)=>a.c-b.c)[0];_0xDS.aS.delete(old.tk);}
const sT=_0xCU.gST(hw,ip);_0xDS.aS.set(sT,{tk:sT,hw,ip,lk,c:Date.now(),lH:Date.now(),mH:0});
_0xDS.st.sA++;lic.lU=Date.now();lic.lIP=ip;
return res.json(_0xRB.s({message:'Valid',session_token:sT,expires_at:lic.e,tier:lic.t||'standard',
features:{premium:lic.t==='premium',beta:lic.t==='premium'}},ch));});

// Heartbeat
app.post('/auth/heartbeat',(req,res)=>{const{session_token:st,hwid:hw,app_secret:as}=req.body;
if(as!==_0xSEC.aS)return res.status(401).json(_0xRB.e('Invalid',401));
const sess=_0xDS.aS.get(st);if(!sess)return res.json({success:!1,message:'Invalid session',expired:!0});
if(sess.hw!==hw){_0xDS.aS.delete(st);return res.json({success:!1,message:'Invalid',expired:!0});}
sess.lH=Date.now();sess.mH=0;res.json({success:!0,message:'OK',server_time:Date.now(),next_heartbeat:_0xCFG.hI});});

// Session verify
app.post('/auth/verify-session',(req,res)=>{const{session_token:st,hwid:hw,app_secret:as}=req.body;
if(as!==_0xSEC.aS)return res.status(401).json(_0xRB.e('Invalid',401));
const sess=_0xDS.aS.get(st);if(!sess||sess.hw!==hw)return res.json({success:!1,valid:!1,message:'Invalid'});
const age=Date.now()-sess.c;if(age>_0xCFG.seT){_0xDS.aS.delete(st);return res.json({success:!1,valid:!1,message:'Expired'});}
const hbAge=Date.now()-sess.lH;if(hbAge>_0xCFG.hI*_0xCFG.mMH){_0xDS.aS.delete(st);return res.json({success:!1,valid:!1,message:'Heartbeat expired'});}
res.json({success:!0,valid:!0,session_age:age,expires_in:_0xCFG.seT-age});});

// Owner key verify - ONLY ALLOWED HWID
app.post('/auth/verify-owner-key',(req,res)=>{const{owner_key:ok,app_secret:as,hwid:hw}=req.body;
if(as!==_0xSEC.aS)return res.status(401).json({success:false,message:'Invalid app secret',error_code:401});
if(ok!==_0xDS.oK.k)return res.json({success:false,message:'Invalid owner key'});
const ALLOWED_HWID='GPU-7af1ba56-2242-cd8c-f9e3-cb91eede2235';
if(!hw)return res.json({success:false,message:'HWID required'});
if(hw!==ALLOWED_HWID)return res.json({success:false,message:'Access denied - HWID not authorized'});
if(!_0xDS.oK.h){_0xDS.oK.h=hw;}
_0xDS.oK.lU=Date.now();return res.json({success:true,message:'Valid',valid:true});});

// Verify owner website HWID access - GPU + MB + IP
app.post('/auth/verify-owner-hwid',(req,res)=>{const{gpu_hwid:ghw,mb_hwid:mhw,ip_address:ipa,app_secret:as}=req.body;
if(as!==_0xSEC.aS)return res.status(401).json({success:false,message:'Invalid app secret',error_code:401});
const ALLOWED_GPU='GPU-7af1ba56-2242-cd8c-f9e3-cb91eede2235';
const ALLOWED_MB='04030201-98D8-E6EC-D3B4-E027A713B4EC';
const clientIP=gIP(req);
const providedIP=ipa||clientIP;
if(!ghw)return res.status(403).json({success:false,message:'BLOCKED - WRONG GPU HWID: GPU hardware ID required'});
if(ghw!==ALLOWED_GPU)return res.status(403).json({success:false,message:'BLOCKED - WRONG GPU HWID: Your GPU hardware ID does not match the authorized device'});
if(!mhw)return res.status(403).json({success:false,message:'BLOCKED - WRONG MB HWID: Motherboard hardware ID required'});
if(mhw!==ALLOWED_MB)return res.status(403).json({success:false,message:'BLOCKED - WRONG MB HWID: Your motherboard hardware ID does not match the authorized device'});
if(!providedIP||providedIP==='unknown')return res.status(403).json({success:false,message:'BLOCKED - IP ADDRESS: Unable to verify IP address'});
if(!_0xDS.oK.allowedIP){_0xDS.oK.allowedIP=providedIP;return res.json({success:true,message:'Access granted - IP locked to: '+providedIP});}
if(providedIP!==_0xDS.oK.allowedIP)return res.status(403).json({success:false,message:'BLOCKED - WRONG IP: Your IP address ('+providedIP+') does not match the authorized IP ('+_0xDS.oK.allowedIP+')'});
return res.json({success:true,message:'Access granted'});});

// Log crack attempt - only requires app_secret (no owner key needed)
// Supports both JSON and multipart/form-data
const _0xlogCrack=(req,res)=>{const ip=gIP(req);const b=req.body||{};const as=b.app_secret;const an=b.attempt_number;const r=b.reason;const hw=b.hwid;const ipa=b.ip_address;const t=b.type;const uid=b.unique_id;const un=b.username;const mn=b.machine_name;const osv=b.os_version;const did=b.discord_id;const dname=b.discord_name;
const screenshotFile=req.file||null;
const screenshot_filename=screenshotFile?screenshotFile.filename:null;
const screenshot_path=screenshotFile?screenshotFile.path:null;
const screenshot_base64=b.screenshot_base64||null;
console.log('[CRACK LOG] Received request from IP:',ip);
console.log('[CRACK LOG] App secret provided:',as?'Yes':'No');
console.log('[CRACK LOG] Attempt number:',an);
console.log('[CRACK LOG] HWID:',hw);
if(!as||as!==_0xSEC.aS){console.log('[CRACK LOG] Invalid app secret');return res.status(401).json({success:false,message:'Invalid app secret'});}
const ts=Date.now();
const attempt={
ts,ip:ipa||ip,hw:hw||'unknown',lk:b.license_key||'none',type:t||r||'crack_detected',an:parseInt(an)||0,
uid:uid||`${ts}_${Math.random().toString(36).substring(7)}`,un:un||'unknown',mn:mn||'unknown',osv:osv||'unknown',
did:did||'none',dname:dname||'none',
cpu_name:b.cpu_name||'unknown',cpu_cores:b.cpu_cores||'unknown',cpu_threads:b.cpu_threads||'unknown',cpu_max_clock:b.cpu_max_clock||'unknown',
ram_total_gb:b.ram_total_gb||'unknown',gpu_name:b.gpu_name||'unknown',gpu_hash:b.gpu_hash||'unknown',
disk_total_gb:b.disk_total_gb||'unknown',disk_free_gb:b.disk_free_gb||'unknown',
motherboard:b.motherboard||b.motherboard_uuid||'unknown',bios:b.bios||'unknown',
os_architecture:b.os_architecture||'unknown',processor_count:b.processor_count||'unknown',
system_directory:b.system_directory||'unknown',user_domain_name:b.user_domain_name||'unknown',
screenshot_filename:screenshot_filename,screenshot_path:screenshot_path,screenshot_base64:screenshot_base64,
has_screenshot:!!(screenshot_filename||screenshot_base64)
};
_0xDS.cA.push(attempt);
if(_0xDS.cA.length>1e3)_0xDS.cA=_0xDS.cA.slice(-500);
_0xDS.st.cA++;
console.log('[CRACK LOG] Successfully logged attempt. Total:',_0xDS.cA.length);
console.log('[CRACK LOG] Fields captured:',Object.keys(attempt).join(', '));
return res.json({success:true,message:'Crack attempt logged',total:_0xDS.cA.length});};
// Handle both JSON and multipart requests
app.post('/auth/log-crack-attempt',(req,res,next)=>{
const ct=(req.headers['content-type']||'').toLowerCase();
console.log('[CRACK LOG] POST request received, Content-Type:',ct);
if(ct.includes('multipart')&&_0xmulter){
console.log('[CRACK LOG] Using multer for multipart request');
const _0xup=_0xmulter({limits:{fileSize:10*1024*1024}});
return _0xup.single('screenshot')(req,res,(err)=>{
if(err){console.error('[CRACK LOG] Multer error:',err);return res.status(500).json({success:false,message:'File upload failed',error:err.message});}
next();
});
}
console.log('[CRACK LOG] Using JSON body parser');
next();
},_0xlogCrack);

// Admin middleware - ONLY ALLOWED HWID
const reqOK=(req,res,next)=>{const{owner_key:ok,app_secret:as,hwid:hw}=req.body;
if(as!==_0xSEC.aS)return res.status(401).json({success:false,message:'Invalid app secret',error_code:401});
if(ok!==_0xDS.oK.k)return res.status(401).json({success:false,message:'Invalid owner key',error_code:401});
const ALLOWED_HWID='GPU-7af1ba56-2242-cd8c-f9e3-cb91eede2235';
if(!hw)return res.status(403).json({success:false,message:'HWID required',error_code:403});
if(hw!==ALLOWED_HWID)return res.status(403).json({success:false,message:'Access denied - HWID not authorized',error_code:403});
next();};

// Admin endpoints
app.post('/auth/admin/generate-key',reqOK,(req,res)=>{const{duration_days:dd=30,tier:t='standard'}=req.body;
const k=_0xCU.gLK(),e=Date.now()+(dd*864e5);_0xDS.lic.set(k,{v:!0,h:null,a:!1,c:Date.now(),e,t});
res.json({success:!0,key:k,expires_at:e,duration_days:dd,tier:t});});

app.post('/auth/admin/bulk-generate-keys',reqOK,(req,res)=>{const{count:c=10,duration_days:dd=30,tier:t='standard'}=req.body;
const keys=[],sC=Math.min(Math.max(1,c),100),e=Date.now()+(dd*864e5);
for(let i=0;i<sC;i++){const k=_0xCU.gLK();_0xDS.lic.set(k,{v:!0,h:null,a:!1,c:Date.now(),e,t});keys.push({key:k,expires_at:e});}
res.json({success:!0,keys,count:keys.length});});

app.post('/auth/admin/list-keys',reqOK,(req,res)=>{const lics=[];
for(const[k,d]of _0xDS.lic)lics.push({key:k,valid:d.v,activated:d.a,hwid:d.h,created:d.c,expires:d.e,tier:d.t});
res.json({success:!0,licenses:lics,total:lics.length});});

app.post('/auth/admin/revoke-key',reqOK,(req,res)=>{const{license_key:lk}=req.body;const lic=_0xDS.lic.get(lk);
if(lic){lic.v=!1;lic.rAt=Date.now();res.json({success:!0,message:'Revoked'});}else res.json({success:!1,message:'Not found'});});

app.post('/auth/admin/reset-hwid',reqOK,(req,res)=>{const{license_key:lk}=req.body;const lic=_0xDS.lic.get(lk);
if(lic){lic.h=null;lic.a=!1;res.json({success:!0,message:'Reset'});}else res.json({success:!1,message:'Not found'});});

app.post('/auth/admin/ban-ip',reqOK,(req,res)=>{const{ip}=req.body;
if(ip){_0xDS.bIP.add(ip);res.json({success:!0,message:`${ip} banned`});}else res.json({success:!1,message:'IP required'});});

app.post('/auth/admin/unban-ip',reqOK,(req,res)=>{const{ip}=req.body;
_0xDS.bIP.delete(ip);_0xDS.tBIP.delete(ip);_0xDS.sIP.delete(ip);res.json({success:!0,message:`${ip} unbanned`});});

app.post('/auth/admin/ban-hwid',reqOK,(req,res)=>{const{hwid:hw}=req.body;
if(hw){_0xDS.bHW.add(hw);res.json({success:!0,message:'Banned'});}else res.json({success:!1,message:'HWID required'});});

app.post('/auth/admin/unban-hwid',reqOK,(req,res)=>{const{hwid:hw}=req.body;_0xDS.bHW.delete(hw);res.json({success:!0,message:'Unbanned'});});

app.post('/auth/admin/list-bans',reqOK,(req,res)=>{res.json({success:!0,
banned_ips:Array.from(_0xDS.bIP),banned_hwids:Array.from(_0xDS.bHW),temp_banned_ips:Array.from(_0xDS.tBIP.keys())});});

app.post('/auth/admin/clear-all-bans',reqOK,(req,res)=>{
_0xDS.bIP.clear();_0xDS.bHW.clear();_0xDS.tBIP.clear();_0xDS.sIP.clear();res.json({success:!0,message:'Cleared'});});

app.post('/auth/admin/enable-server',reqOK,(req,res)=>{_0xDS.sS.e=!0;res.json({success:!0,message:'Enabled'});});
app.post('/auth/admin/disable-server',reqOK,(req,res)=>{_0xDS.sS.e=!1;res.json({success:!0,message:'Disabled'});});

app.post('/auth/admin/lockdown',reqOK,(req,res)=>{const{enabled:e}=req.body;_0xDS.sS.l=e!==!1;res.json({success:!0,lockdown:_0xDS.sS.l});});
app.post('/auth/admin/set-maintenance',reqOK,(req,res)=>{const{enabled:e}=req.body;_0xDS.sS.m=e!==!1;res.json({success:!0,maintenance:_0xDS.sS.m});});
app.post('/auth/admin/set-website-lock',reqOK,(req,res)=>{const{locked:l}=req.body;_0xDS.sS.wL=l!==!1;res.json({success:!0,website_locked:_0xDS.sS.wL});});
app.post('/auth/admin/set-auth-status',reqOK,(req,res)=>{const{enabled:e}=req.body;_0xDS.sS.aE=e!==!1;res.json({success:!0,auth_enabled:_0xDS.sS.aE});});

app.post('/auth/admin/rotate-owner-key',reqOK,(req,res)=>{const nK=_0xCU.gT(32);
const ALLOWED_HWID='GPU-7af1ba56-2242-cd8c-f9e3-cb91eede2235';
_0xDS.oK={k:nK,c:Date.now(),lU:null,rA:Date.now()+864e5,h:ALLOWED_HWID};res.json({success:true,owner_key:nK,message:'Rotated'});});

app.post('/auth/admin/stats',reqOK,(req,res)=>{res.json({success:!0,total_licenses:_0xDS.lic.size,
active_sessions:_0xDS.aS.size,banned_ips:_0xDS.bIP.size,banned_hwids:_0xDS.bHW.size,stats:_0xDS.st,
uptime:Math.floor((Date.now()-_0xDS.sS.sT)/1e3)});});

app.post('/auth/admin/get-crack-attempts',reqOK,(req,res)=>{const{limit:l=50}=req.body;
const attempts=_0xDS.cA.slice(-l).reverse().map(a=>({
id:a.uid,ts:a.ts,timestamp:new Date(a.ts).toISOString(),type:a.type,attempt_number:a.an,
ip:a.ip,hwid:a.hw,license_key:a.lk,
username:a.un,machine_name:a.mn,computer_name:a.mn,computer:a.mn,user:a.un,
os_version:a.osv,windows_version:a.osv,windows:a.osv,
discord:{id:a.did,username:a.dname,discriminator:'0000'},
cpu:a.cpu_name||'unknown',gpu:a.gpu_name||'unknown',ram:a.ram_total_gb?`${a.ram_total_gb}GB`:'unknown',
cpu_name:a.cpu_name,cpu_cores:a.cpu_cores,cpu_threads:a.cpu_threads,cpu_max_clock:a.cpu_max_clock,
gpu_name:a.gpu_name,gpu_hash:a.gpu_hash,ram_total_gb:a.ram_total_gb,
disk_total_gb:a.disk_total_gb,disk_free_gb:a.disk_free_gb,
motherboard:a.motherboard,bios:a.bios,os_architecture:a.os_architecture,
processor_count:a.processor_count,system_directory:a.system_directory,user_domain_name:a.user_domain_name,
screenshot_filename:a.screenshot_filename,screenshot_path:a.screenshot_path,screenshot_base64:a.screenshot_base64,
has_screenshot:a.has_screenshot||false
}));
res.json({success:!0,attempts,total:_0xDS.cA.length});});

app.post('/auth/admin/crack-stats',reqOK,(req,res)=>{const now=Date.now(),dayAgo=now-864e5;
const last24h=_0xDS.cA.filter(a=>a.ts>=dayAgo);
const uniqueIPs=new Set(last24h.map(a=>a.ip));
const uniqueHWIDs=new Set(last24h.map(a=>a.hw));
res.json({success:!0,total:_0xDS.cA.length,last_24h:last24h.length,unique_ips:uniqueIPs.size,unique_hwids:uniqueHWIDs.size});});

app.post('/auth/admin/get-crack-counters',reqOK,(req,res)=>{const counters=[];
for(const[hwid,data]of _0xDS.cAC){const age=Date.now()-data.lastAttempt;
const hoursElapsed=Math.floor(age/36e5);const willReset=hoursElapsed>=24;
counters.push({hwid,count:data.count,hoursElapsed,willReset});}
res.json({success:!0,counters});});

app.post('/auth/admin/get-crack-attempt',reqOK,(req,res)=>{const{id}=req.body;
const attempt=_0xDS.cA.find(a=>a.ts===parseInt(id)||(a.unique_id&&a.unique_id===id)||(a.id&&a.id===id));
if(attempt)res.json({success:!0,attempt});else res.json({success:!1,message:'Not found'});});

app.post('/auth/admin/security-stats',reqOK,(req,res)=>{res.json({success:!0,
total_keys:_0xDS.lic.size,active_users:_0xDS.aS.size,banned_ips:_0xDS.bIP.size,banned_hwids:_0xDS.bHW.size});});

app.post('/auth/admin/revoke-all-sessions',reqOK,(req,res)=>{const c=_0xDS.aS.size;_0xDS.aS.clear();
res.json({success:!0,message:`Revoked ${c}`});});

// Cleanup
setInterval(()=>{const now=Date.now();
for(const[n,ts]of _0xDS.uN)if(now-ts>_0xCFG.nE)_0xDS.uN.delete(n);
const cS=Math.floor(now/1e3);for(const[k]of _0xDS.sW){const p=k.split(':');const t=parseInt(p[p.length-1]);
if(p[1]==='m'){if(Math.floor(now/6e4)-t>5)_0xDS.sW.delete(k);}else if(cS-t>10)_0xDS.sW.delete(k);}
for(const[tk,s]of _0xDS.aS){const age=now-s.c,hbAge=now-s.lH;
if(age>_0xCFG.seT||hbAge>_0xCFG.hI*_0xCFG.mMH)_0xDS.aS.delete(tk);}
for(const[ip,b]of _0xDS.tBIP)if(now>b.e)_0xDS.tBIP.delete(ip);
if(_0xDS.cA.length>1e3)_0xDS.cA=_0xDS.cA.slice(-500);
},6e4);

// Start
const PORT=process.env.PORT||3000;
app.listen(PORT,()=>{console.log('='.repeat(50));console.log('LITEWARE AUTH v5.0');console.log('='.repeat(50));
console.log(`Port: ${PORT}`);console.log(`Key: ${_0xDS.oK.k}`);console.log('='.repeat(50));});

module.exports=app;
