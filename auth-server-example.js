// Liteware Authentication Server v3.0 - Obfuscated
const _0x4a7b=['express','body-parser','crypto','fs','path'];
const _0x2c9d=(_0x1)=>require(_0x4a7b[_0x1]);
const _0x5e3f=_0x2c9d(0),_0x8b1a=_0x2c9d(1),_0x3d7c=_0x2c9d(2),_0x9f4e=_0x2c9d(3),_0x6a2b=_0x2c9d(4);
const _0xapp=_0x5e3f();

// Encoded configuration
const _0x7d8e=(s)=>Buffer.from(s,'base64').toString('utf8');
const _0x1f3a=new Set([_0x7d8e('Ojox'),_0x7d8e('MTI3LjAuMC4x'),_0x7d8e('OjpmZmZmOjEyNy4wLjAuMQ==')]);
const _0x4c5b=new Map(),_0x2e9f=new Set(),_0x8d3a=new Set(),_0x5f7c=new Map();
const _0x9a1b=60000,_0x3e4d=30,_0x7b2c=3600000;
let _0x6f8e=!1,_0x1d4a=!1;

// Obfuscated secrets (XOR encoded)
const _0xk1=[0x41,0x42,0x43,0x4a,0x44,0x57,0x51,0x39,0x31,0x44,0x39,0x32,0x31,0x39,0x44,0x32,0x31,0x4a,0x4b,0x57,0x44,0x44,0x4b,0x51,0x41,0x44,0x39,0x31,0x32,0x51];
const _0xk2=[0x4c,0x49,0x54,0x45,0x57,0x41,0x52,0x45,0x5f,0x53,0x45,0x43,0x52,0x45,0x54,0x5f,0x4b,0x45,0x59,0x5f,0x32,0x30,0x32,0x36,0x5f,0x56,0x33];
const _0x4s=()=>String.fromCharCode(..._0xk1);
const _0x5r=()=>String.fromCharCode(..._0xk2);

// License store with obfuscated keys
const _0xlics={};
_0xlics[_0x7d8e('TElURS1URVNULTEyMzQtNTY3OA==')]={v:!0,h:null,a:!1,c:Date.now(),e:Date.now()+31536000000};
_0xlics[_0x7d8e('TElURS1ERU1PLUFBQUEtQkJCQg==')]={v:!0,h:null,a:!1,c:Date.now(),e:Date.now()+2592000000};

// Owner key with rotation
let _0xowk={k:_0x3d7c.randomBytes(32).toString('hex'),c:Date.now(),n:Date.now()+86400000};

// Utility functions with obfuscated names
const _0xchkip=(ip)=>{if(!ip)return!1;const c=ip.split(',')[0].trim();return _0x1f3a.has(c)||_0x1f3a.has(c.replace('::ffff:',''));};
const _0xgetip=(r)=>r.ip||r.connection?.remoteAddress||'unknown';
const _0xgentkn=()=>_0x3d7c.randomBytes(32).toString('hex');
const _0xsign=(d,ch)=>{const t=Date.now().toString();const s=JSON.stringify(d)+'|'+(ch||'')+'|'+t;const sig=_0x3d7c.createHmac('sha256',_0x5r()).update(s).digest('hex');return{...d,_sig:sig,_ts:t,_challenge:ch||''};};

// Middleware
_0xapp.use((q,s,n)=>{s.header('Access-Control-Allow-Origin','*');s.header('Access-Control-Allow-Methods','GET, POST, PUT, DELETE, OPTIONS');s.header('Access-Control-Allow-Headers','Origin, X-Requested-With, Content-Type, Accept, Authorization');if(q.method==='OPTIONS')return s.sendStatus(200);n();});
_0xapp.use(_0x8b1a.urlencoded({extended:!0,limit:'50mb'}));
_0xapp.use(_0x8b1a.json({limit:'50mb'}));

// Rate limiter with anti-tamper
_0xapp.use((q,s,n)=>{const ip=_0xgetip(q);if(_0xchkip(ip))return n();if(_0x2e9f.has(ip))return s.status(403).json({success:!1,message:_0x7d8e('SVAgYmFubmVk')});const now=Date.now();const r=_0x4c5b.get(ip)||{c:0,t:now+_0x9a1b};if(now>r.t){r.c=0;r.t=now+_0x9a1b;}_0x4c5b.set(ip,{c:++r.c,t:r.t});if(r.c>_0x3e4d)return s.status(429).json({success:!1,message:_0x7d8e('UmF0ZSBsaW1pdGVk')});n();});

// Health endpoints
_0xapp.get('/',(q,s)=>s.json({status:'online',version:'3.0',time:Date.now()}));
_0xapp.get('/health',(q,s)=>s.json({status:'ok',uptime:process.uptime()}));
_0xapp.get('/auth/health',(q,s)=>s.json({status:'ok',server_time:Date.now()}));

// Auth middleware
const _0xvalsec=(q,s,n)=>{if(q.body.app_secret!==_0x4s())return s.status(401).json(_0xsign({success:!1,message:'Invalid app secret'},q.body._challenge));n();};

// Test endpoint
_0xapp.post('/auth/test',(q,s)=>s.json(_0xsign({success:!0,message:'Server online',version:'3.0'},q.body._challenge)));

// Validate license
_0xapp.post('/auth/validate',_0xvalsec,(q,s)=>{
    const{license_key:lk,hwid:hw,_challenge:ch}=q.body;
    if(_0x6f8e)return s.json(_0xsign({success:!1,message:'Server is disabled'},ch));
    if(!lk)return s.json(_0xsign({success:!1,message:'License key required'},ch));
    const lic=_0xlics[lk];
    if(!lic)return s.json(_0xsign({success:!1,message:'Invalid license key'},ch));
    if(!lic.v)return s.json(_0xsign({success:!1,message:'License has been revoked'},ch));
    if(lic.e<Date.now())return s.json(_0xsign({success:!1,message:'License has expired'},ch));
    if(lic.h&&lic.h!==hw)return s.json(_0xsign({success:!1,message:'License bound to different hardware'},ch));
    if(!lic.h&&hw){lic.h=hw;lic.a=!0;console.log(`License ${lk} bound to HWID: ${hw}`);}
    const tk=_0xgentkn();
    _0x5f7c.set(tk,{l:lk,h:hw,c:Date.now(),e:Date.now()+3600000});
    s.json(_0xsign({success:!0,message:'License valid',session_token:tk,expires:lic.e},ch));
});

// Activate license
_0xapp.post('/auth/activate',_0xvalsec,(q,s)=>{
    const{license_key:lk,hwid:hw,_challenge:ch}=q.body;
    if(!lk||!hw)return s.json(_0xsign({success:!1,message:'License key and HWID required'},ch));
    const lic=_0xlics[lk];
    if(!lic)return s.json(_0xsign({success:!1,message:'Invalid license key'},ch));
    if(lic.h&&lic.h!==hw)return s.json(_0xsign({success:!1,message:'License already bound to different hardware'},ch));
    lic.h=hw;lic.a=!0;
    const tk=_0xgentkn();
    _0x5f7c.set(tk,{l:lk,h:hw,c:Date.now(),e:Date.now()+3600000});
    s.json(_0xsign({success:!0,message:'License activated successfully',session_token:tk},ch));
});

// Heartbeat
_0xapp.post('/auth/heartbeat',_0xvalsec,(q,s)=>{
    const{session_token:tk,_challenge:ch}=q.body;
    const ss=_0x5f7c.get(tk);
    if(!ss)return s.json(_0xsign({success:!1,message:'Invalid session'},ch));
    if(ss.e<Date.now()){_0x5f7c.delete(tk);return s.json(_0xsign({success:!1,message:'Session expired'},ch));}
    ss.e=Date.now()+3600000;
    s.json(_0xsign({success:!0,message:'Session valid'},ch));
});

// Admin: Owner key
_0xapp.post('/auth/get-owner-key',(q,s)=>s.json({success:!0,owner_key:_0xowk.k,next_rotation:_0xowk.n}));
_0xapp.post('/auth/get-owner-key-by-hwid',(q,s)=>s.json({success:!0,owner_key:_0xowk.k,next_rotation:_0xowk.n}));

_0xapp.post('/auth/admin/rotate-owner-key',(q,s)=>{
    _0xowk={k:_0x3d7c.randomBytes(32).toString('hex'),c:Date.now(),n:Date.now()+86400000};
    s.json({success:!0,message:'Owner key rotated',owner_key:_0xowk.k,next_rotation:_0xowk.n});
});

// Admin: Generate key
_0xapp.post('/auth/admin/generate-key',(q,s)=>{
    const{duration_days:dd=30}=q.body;
    const k=`LITE-${_0x3d7c.randomBytes(2).toString('hex').toUpperCase()}-${_0x3d7c.randomBytes(2).toString('hex').toUpperCase()}-${_0x3d7c.randomBytes(2).toString('hex').toUpperCase()}`;
    _0xlics[k]={v:!0,h:null,a:!1,c:Date.now(),e:Date.now()+(dd*86400000)};
    s.json({success:!0,license_key:k,expires:_0xlics[k].e});
});

// Admin: List keys
_0xapp.post('/auth/admin/list-keys',(q,s)=>{
    const ks=Object.entries(_0xlics).map(([k,d])=>({key:k,valid:d.v,activated:d.a,hwid:d.h,expires:d.e}));
    s.json({success:!0,licenses:ks});
});

// Admin: Revoke key
_0xapp.post('/auth/admin/revoke-key',(q,s)=>{
    const{license_key:lk}=q.body;
    if(_0xlics[lk]){_0xlics[lk].v=!1;s.json({success:!0,message:'License revoked'});}
    else s.json({success:!1,message:'License not found'});
});

// Admin: Status
_0xapp.post('/auth/admin/status',(q,s)=>s.json({success:!0,server_enabled:!_0x6f8e,maintenance_mode:_0x1d4a,active_sessions:_0x5f7c.size,total_licenses:Object.keys(_0xlics).length,banned_ips:_0x2e9f.size,uptime:process.uptime()}));

// Admin: Toggle server
_0xapp.post('/auth/admin/toggle-server',(q,s)=>{_0x6f8e=!_0x6f8e;s.json({success:!0,server_enabled:!_0x6f8e});});

// Admin: IP whitelist
_0xapp.post('/auth/admin/whitelist-ip',(q,s)=>{const{ip}=q.body;if(ip){_0x1f3a.add(ip);s.json({success:!0,message:`IP ${ip} whitelisted`});}else s.json({success:!1,message:'IP required'});});
_0xapp.post('/auth/admin/unwhitelist-ip',(q,s)=>{const{ip}=q.body;if(ip){_0x1f3a.delete(ip);s.json({success:!0,message:`IP ${ip} removed from whitelist`});}else s.json({success:!1,message:'IP required'});});
_0xapp.post('/auth/admin/list-whitelisted-ips',(q,s)=>s.json({success:!0,whitelisted_ips:Array.from(_0x1f3a)}));
_0xapp.post('/auth/admin/get-my-ip',(q,s)=>{const ip=_0xgetip(q);s.json({success:!0,ip:ip,is_whitelisted:_0xchkip(ip)});});
_0xapp.post('/auth/admin/whitelist-my-ip',(q,s)=>{const ip=_0xgetip(q);_0x1f3a.add(ip);s.json({success:!0,message:`Your IP ${ip} has been whitelisted`});});

// Admin: Ban IP
_0xapp.post('/auth/admin/ban-ip',(q,s)=>{const{ip}=q.body;if(ip){_0x2e9f.add(ip);s.json({success:!0,message:`IP ${ip} banned`});}else s.json({success:!1,message:'IP required'});});
_0xapp.post('/auth/admin/unban-ip',(q,s)=>{const{ip}=q.body;if(ip){_0x2e9f.delete(ip);s.json({success:!0,message:`IP ${ip} unbanned`});}else s.json({success:!1,message:'IP required'});});
_0xapp.post('/auth/admin/list-banned-ips',(q,s)=>s.json({success:!0,banned_ips:Array.from(_0x2e9f)}));

// Admin: Stats
_0xapp.post('/auth/admin/stats',(q,s)=>s.json({success:!0,total_licenses:Object.keys(_0xlics).length,active_licenses:Object.values(_0xlics).filter(l=>l.v&&l.a).length,active_sessions:_0x5f7c.size,banned_ips:_0x2e9f.size,whitelisted_ips:_0x1f3a.size}));

// Emergency reset
_0xapp.post('/auth/emergency-reset',(q,s)=>{_0x2e9f.clear();_0x4c5b.clear();_0x6f8e=!1;_0x1d4a=!1;s.json({success:!0,message:'Emergency reset complete'});});

// HWID verify
_0xapp.post('/auth/verify-hwid',_0xvalsec,(q,s)=>{const{hwid:hw,_challenge:ch}=q.body;if(_0x8d3a.has(hw))return s.json(_0xsign({success:!1,message:'HWID banned'},ch));s.json(_0xsign({success:!0,message:'HWID valid'},ch));});

// Start server
const _0xport=process.env.PORT||3000;
_0xapp.listen(_0xport,()=>{console.log(`Server running on port ${_0xport}`);});
process.on('uncaughtException',(e)=>console.error('Error:',e.message));
process.on('unhandledRejection',(r)=>console.error('Rejection:',r));
