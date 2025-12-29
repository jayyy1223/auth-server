// Simple Node.js Authentication Server Example
// Install dependencies: npm install express body-parser crypto mysql2 (or use SQLite for simplicity)

const express = require('express');
const bodyParser = require('body-parser');
const crypto = require('crypto');
const app = express();

app.use(bodyParser.urlencoded({ extended: true }));
app.use(bodyParser.json());

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
    // Format: license_key: { valid: true, used: false, hwid: null, expiry: null }
    'LICENSE-KEY-12345': {
        valid: true,
        used: false,
        hwid: null,
        expiry: null // null = never expires
    }
};

// Application secret (keep this secure!)
const APP_SECRET = 'your-secret-key-here';

// Middleware to validate app secret
function validateAppSecret(req, res, next) {
    const appSecret = req.body.app_secret || req.body.app_secret;
    if (appSecret !== APP_SECRET) {
        return res.json({ success: false, message: 'Invalid application secret' });
    }
    next();
}

// License validation endpoint
app.post('/auth/license', validateAppSecret, (req, res) => {
    const { license_key, hwid, app_name } = req.body;
    
    if (!license_key) {
        return res.json({ success: false, message: 'License key required' });
    }
    
    const license = licenses[license_key];
    
    if (!license || !license.valid) {
        return res.json({ success: false, message: 'Invalid license key' });
    }
    
    if (license.used && license.hwid !== hwid) {
        return res.json({ success: false, message: 'License already used on different hardware' });
    }
    
    // Check expiry
    if (license.expiry && new Date() > new Date(license.expiry)) {
        return res.json({ success: false, message: 'License has expired' });
    }
    
    // Mark as used and bind to HWID
    if (!license.used) {
        license.used = true;
        license.hwid = hwid;
    }
    
    // Generate session token
    const token = crypto.randomBytes(32).toString('hex');
    
    res.json({
        success: true,
        valid: true,
        token: token,
        message: 'License validated successfully'
    });
});

// Username/Password validation endpoint
app.post('/auth/login', validateAppSecret, (req, res) => {
    const { username, password, hwid, app_name } = req.body;
    
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
    const { token } = req.body;
    
    // In real implementation, store tokens and check them
    // For now, just return success (you'd want to check if token is valid)
    
    res.json({
        success: true,
        valid: true,
        message: 'Session valid'
    });
});

// Health check
app.get('/', (req, res) => {
    res.json({ status: 'Auth server running' });
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
    console.log(`Authentication server running on port ${PORT}`);
});

