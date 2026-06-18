const express = require('express');
const cors = require('cors');
const jwt = require('jsonwebtoken');
const crypto = require('crypto');
const path = require('path');
const db = require('./db');

const app = express();
const PORT = 3000;
const JWT_SECRET = 'secure-key-987654321';

app.use(cors());
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(express.static(path.join(__dirname, 'public')));

// pkce helper
function base64UrlEncode(buffer) {
  return buffer.toString('base64')
    .replace(/\+/g, '-')
    .replace(/\//g, '_')
    .replace(/=/g, '');
}

// verify verifier against challenge
function verifyPkce(verifier, challenge, method) {
  if (!verifier || !challenge) return false;
  if (method === 'plain') {
    return verifier === challenge;
  }
  if (method === 'S256') {
    const hash = crypto.createHash('sha256').update(verifier).digest();
    const computed = base64UrlEncode(hash);
    return computed === challenge;
  }
  return false;
}

// auth server endpoints

// login form
app.get('/oauth/authorize', (req, res) => {
  const { client_id, redirect_uri, response_type, code_challenge, code_challenge_method, state } = req.query;
  
  const client = db.getClient(client_id);
  if (!client || !client.redirectUris.includes(redirect_uri)) {
    return res.status(400).send('invalid client or redirect uri');
  }
  
  res.send(`
    <!DOCTYPE html>
    <html>
    <head>
      <meta charset="utf-8">
      <title>oauth2 login</title>
      <style>
        body {
          font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
          background: #0d1117;
          color: #c9d1d9;
          display: flex;
          align-items: center;
          justify-content: center;
          height: 100vh;
          margin: 0;
        }
        .card {
          background: #161b22;
          border: 1px solid #30363d;
          border-radius: 12px;
          padding: 2.5rem;
          width: 360px;
          box-shadow: 0 8px 24px rgba(0,0,0,0.5);
        }
        h2 {
          margin-top: 0;
          color: #f0f6fc;
          text-align: center;
          font-weight: 600;
        }
        .input-group {
          margin-bottom: 1.25rem;
        }
        label {
          display: block;
          margin-bottom: 0.5rem;
          font-size: 0.875rem;
          color: #8b949e;
        }
        input {
          width: 100%;
          padding: 0.75rem;
          background: #0d1117;
          border: 1px solid #30363d;
          border-radius: 6px;
          color: #c9d1d9;
          box-sizing: border-box;
          font-size: 1rem;
        }
        input:focus {
          outline: none;
          border-color: #58a6ff;
        }
        button {
          width: 100%;
          padding: 0.75rem;
          background: #238636;
          border: 1px solid #2ea44f;
          border-radius: 6px;
          color: #ffffff;
          font-size: 1rem;
          font-weight: 600;
          cursor: pointer;
          margin-top: 0.5rem;
        }
        button:hover {
          background: #2ea44f;
        }
        .error {
          color: #f85149;
          font-size: 0.875rem;
          margin-bottom: 1rem;
          text-align: center;
        }
        .info {
          font-size: 0.75rem;
          color: #8b949e;
          text-align: center;
          margin-top: 1.5rem;
        }
      </style>
    </head>
    <body>
      <div class="card">
        <h2>OAuth 2.0 Auth Server</h2>
        ${req.query.error ? `<div class="error">invalid username or password</div>` : ''}
        <form action="/oauth/login" method="POST">
          <input type="hidden" name="client_id" value="${client_id || ''}">
          <input type="hidden" name="redirect_uri" value="${redirect_uri || ''}">
          <input type="hidden" name="response_type" value="${response_type || ''}">
          <input type="hidden" name="code_challenge" value="${code_challenge || ''}">
          <input type="hidden" name="code_challenge_method" value="${code_challenge_method || 'plain'}">
          <input type="hidden" name="state" value="${state || ''}">
          
          <div class="input-group">
            <label for="username">username</label>
            <input type="text" id="username" name="username" required autocomplete="off">
          </div>
          
          <div class="input-group">
            <label for="password">password</label>
            <input type="password" id="password" name="password" required>
          </div>
          
          <button type="submit">authorize</button>
        </form>
        <div class="info">
          client: <code>${client_id}</code><br>
          challenge: <code>${code_challenge ? code_challenge.substring(0, 15) + '...' : 'none'}</code>
        </div>
      </div>
    </body>
    </html>
  `);
});

// login form handler
app.post('/oauth/login', (req, res) => {
  const { username, password, client_id, redirect_uri, response_type, code_challenge, code_challenge_method, state } = req.body;
  
  const user = db.getUser(username);
  if (!user || user.password !== password) {
    const errorUrl = `/oauth/authorize?client_id=${encodeURIComponent(client_id)}&redirect_uri=${encodeURIComponent(redirect_uri)}&response_type=${encodeURIComponent(response_type)}&code_challenge=${encodeURIComponent(code_challenge)}&code_challenge_method=${encodeURIComponent(code_challenge_method)}&state=${encodeURIComponent(state)}&error=1`;
    return res.redirect(errorUrl);
  }
  
  // generate auth code
  const code = crypto.randomBytes(16).toString('hex');
  db.saveAuthCode(code, code_challenge, code_challenge_method, user.id, client_id);
  
  // redirect back to client
  const redirectUrl = new URL(redirect_uri);
  redirectUrl.searchParams.set('code', code);
  if (state) redirectUrl.searchParams.set('state', state);
  
  res.redirect(redirectUrl.toString());
});

// token exchange endpoint
app.post('/oauth/token', (req, res) => {
  const { grant_type, code, client_id, redirect_uri, code_verifier } = req.body;
  
  if (grant_type !== 'authorization_code') {
    return res.status(400).json({ error: 'unsupported_grant_type' });
  }
  
  const authCode = db.getAndRemoveAuthCode(code);
  if (!authCode) {
    return res.status(400).json({ error: 'invalid_grant', error_description: 'code invalid or expired' });
  }
  
  if (authCode.clientId !== client_id) {
    return res.status(400).json({ error: 'invalid_client' });
  }
  
  // pkce validation
  if (authCode.challenge) {
    const valid = verifyPkce(code_verifier, authCode.challenge, authCode.method);
    if (!valid) {
      return res.status(400).json({ error: 'invalid_grant', error_description: 'pkce verification failed' });
    }
  }
  
  // get user and sign token
  const data = require('./db.json');
  const user = data.users.find(u => u.id === authCode.userId);
  if (!user) {
    return res.status(400).json({ error: 'invalid_grant' });
  }
  
  // generate token
  const payload = {
    sub: user.id,
    username: user.username,
    role: user.role,
    name: user.name
  };
  
  const token = jwt.sign(payload, JWT_SECRET, { expiresIn: '1h' });
  
  res.json({
    access_token: token,
    token_type: 'Bearer',
    expires_in: 3600
  });
});

// resource server / backend api

// jwt verify middleware
function authenticateJWT(req, res, next) {
  const authHeader = req.headers.authorization;
  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    return res.status(401).json({ error: 'unauthorized', message: 'missing token' });
  }
  
  const token = authHeader.split(' ')[1];
  jwt.verify(token, JWT_SECRET, (err, decoded) => {
    if (err) {
      return res.status(401).json({ error: 'unauthorized', message: 'invalid or expired token' });
    }
    req.user = decoded;
    next();
  });
}

// role check middleware
function requireRole(role) {
  return (req, res, next) => {
    if (req.user && req.user.role === role) {
      next();
    } else {
      res.status(403).json({ error: 'forbidden', message: 'access denied: role required ' + role });
    }
  };
}

// 1. health check endpoint - unsecured
app.get('/api/health', (req, res) => {
  res.json({
    status: 'ok',
    timestamp: new Date().toISOString()
  });
});

// 2. profile endpoint - secured
app.get('/api/user/profile', authenticateJWT, (req, res) => {
  res.json({
    message: 'profile loaded',
    user: {
      id: req.user.sub,
      username: req.user.username,
      name: req.user.name,
      role: req.user.role
    }
  });
});

// 3. settings endpoint - secured
app.get('/api/user/settings', authenticateJWT, (req, res) => {
  res.json({
    message: 'settings loaded',
    settings: {
      theme: 'dark',
      notifications: true,
      mfa_enabled: false
    }
  });
});

// 4. generic data endpoint - secured
app.get('/api/data', authenticateJWT, (req, res) => {
  res.json({
    message: 'secured items loaded',
    items: [
      { id: 101, name: 'resource alpha', category: 'confidential' },
      { id: 102, name: 'resource beta', category: 'internal' }
    ]
  });
});

// 5. admin endpoint - role based (admin only)
app.get('/api/admin/dashboard', authenticateJWT, requireRole('admin'), (req, res) => {
  res.json({
    message: 'welcome to admin dashboard',
    stats: {
      total_users: 2,
      active_connections: 1,
      system_load: 'low'
    }
  });
});

app.listen(PORT, () => {
  console.log(`server running at http://localhost:${PORT}`);
});
