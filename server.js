import express from 'express';
import crypto from 'crypto';
import db from './db.js';

const app = express();
const PORT = process.env.PORT || 3000;

const rateLimitMap = new Map();
const tokenStore = new Map();
const RATE_LIMIT_WINDOW = 60000;
const MAX_REQUESTS_PER_WINDOW = 10;
const TOKEN_EXPIRY = 300000;

app.disable('x-powered-by');
app.set('trust proxy', false);

const originalLog = console.log;
const originalError = console.error;
const safeLog = (...args) => {
  const str = args.join(' ');
  if (str.includes('/api/') || str.includes('POST') || str.includes('GET')) {
    return;
  }
  originalLog.apply(console, args);
};
console.log = safeLog;
console.error = (...args) => {
  const str = args.join(' ');
  if (str.includes('/api/')) return;
  originalError.apply(console, args);
};

function rateLimit(ip) {
  const now = Date.now();
  const record = rateLimitMap.get(ip) || { count: 0, resetTime: now + RATE_LIMIT_WINDOW };
  
  if (now > record.resetTime) {
    record.count = 0;
    record.resetTime = now + RATE_LIMIT_WINDOW;
  }
  
  record.count++;
  rateLimitMap.set(ip, record);
  
  return record.count <= MAX_REQUESTS_PER_WINDOW;
}

function generateToken() {
  return crypto.randomBytes(32).toString('hex');
}

function validateToken(token, clientFingerprint) {
  const stored = tokenStore.get(token);
  if (!stored) return false;
  if (Date.now() > stored.expiry) {
    tokenStore.delete(token);
    return false;
  }
  return stored.fingerprint === clientFingerprint;
}

setInterval(() => {
  const now = Date.now();
  for (const [ip, record] of rateLimitMap.entries()) {
    if (now > record.resetTime) {
      rateLimitMap.delete(ip);
    }
  }
  for (const [token, data] of tokenStore.entries()) {
    if (now > data.expiry) {
      tokenStore.delete(token);
    }
  }
}, RATE_LIMIT_WINDOW);

app.use(express.json({ limit: '1mb' }));
app.use((req, res, next) => {
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('X-Frame-Options', 'DENY');
  res.setHeader('X-XSS-Protection', '1; mode=block');
  res.setHeader('Referrer-Policy', 'no-referrer');
  next();
});
app.use(express.static('public'));

app.get('/api/token', (req, res) => {
  const userAgent = req.headers['user-agent'] || '';
  const acceptLang = req.headers['accept-language'] || '';
  const fingerprint = crypto.createHash('sha256')
    .update(userAgent + acceptLang + Date.now())
    .digest('hex');
  
  const token = generateToken();
  tokenStore.set(token, {
    fingerprint,
    expiry: Date.now() + TOKEN_EXPIRY
  });
  
  res.json({ token, fingerprint });
});

function generateId(length = 12) {
  const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
  let result = '';
  for (let i = 0; i < length; i++) {
    result += chars[Math.floor(Math.random() * chars.length)];
  }
  return result;
}

function encrypt(text, key) {
  const iv = crypto.randomBytes(16);
  const keyHash = crypto.createHash('sha256').update(key).digest();
  const cipher = crypto.createCipheriv('aes-256-cbc', keyHash, iv);
  let encrypted = cipher.update(text, 'utf8', 'hex');
  encrypted += cipher.final('hex');
  return iv.toString('hex') + ':' + encrypted;
}

function decrypt(text, key) {
  const parts = text.split(':');
  const iv = Buffer.from(parts[0], 'hex');
  const encrypted = parts[1];
  const keyHash = crypto.createHash('sha256').update(key).digest();
  const decipher = crypto.createDecipheriv('aes-256-cbc', keyHash, iv);
  let decrypted = decipher.update(encrypted, 'hex', 'utf8');
  decrypted += decipher.final('utf8');
  return decrypted;
}

app.post('/api/create', async (req, res) => {
  const { content, password, customUrl, token, fingerprint, timestamp } = req.body;
  
  if (!token || !fingerprint || !timestamp) {
    return res.status(403).json({ error: 'Forbidden' });
  }
  
  if (!validateToken(token, fingerprint)) {
    return res.status(403).json({ error: 'Invalid token' });
  }
  
  const timeDiff = Math.abs(Date.now() - timestamp);
  if (timeDiff > 60000) {
    return res.status(403).json({ error: 'Request expired' });
  }
  
  if (!content) {
    return res.status(400).json({ error: 'Content required' });
  }

  if (content.length > 100000) {
    return res.status(400).json({ error: 'Content too large' });
  }

  let id = customUrl || generateId();
  
  if (customUrl && !/^[a-zA-Z0-9_-]{3,32}$/.test(customUrl)) {
    return res.status(400).json({ error: 'Invalid custom URL' });
  }
  
  const existing = await db.get('SELECT id FROM memos WHERE id = ?', [id]);
  if (existing) {
    if (customUrl) {
      return res.status(400).json({ error: 'URL already exists' });
    }
    id = generateId();
  }

  const encryptionKey = crypto.randomBytes(32).toString('hex');
  const encryptedContent = encrypt(content, encryptionKey);
  const hashedPassword = password ? crypto.createHash('sha256').update(password).digest('hex') : null;

  await db.run(
    'INSERT INTO memos (id, content, password, created_at) VALUES (?, ?, ?, ?)',
    [id, encryptedContent, hashedPassword, Date.now()]
  );

  tokenStore.delete(token);
  res.json({ id, key: encryptionKey });
});

app.post('/api/get', async (req, res) => {
  const ip = req.headers['x-forwarded-for'] || req.connection.remoteAddress;
  
  if (!rateLimit(ip)) {
    return res.status(429).json({ error: 'Too many requests' });
  }

  const { id, key, password, timestamp } = req.body;

  if (!id || !key || !timestamp) {
    return res.status(400).json({ error: 'Invalid request' });
  }

  const timeDiff = Math.abs(Date.now() - timestamp);
  if (timeDiff > 120000) {
    return res.status(403).json({ error: 'Request expired' });
  }

  if (!/^[a-zA-Z0-9_-]{3,32}$/.test(id)) {
    return res.status(400).json({ error: 'Invalid request' });
  }

  const memo = await db.get('SELECT * FROM memos WHERE id = ?', [id]);
  
  if (!memo) {
    return res.status(404).json({ error: 'Not found' });
  }

  if (memo.password) {
    if (!password) {
      return res.status(401).json({ error: 'Password required' });
    }
    const hashedPassword = crypto.createHash('sha256').update(password).digest('hex');
    if (hashedPassword !== memo.password) {
      return res.status(401).json({ error: 'Invalid password' });
    }
  }

  try {
    const decryptedContent = decrypt(memo.content, key);
    res.json({ content: decryptedContent });
  } catch (error) {
    res.status(400).json({ error: 'Invalid key' });
  }
});

app.listen(PORT, '0.0.0.0', () => {
  originalLog(`Server running on port ${PORT}`);
});
