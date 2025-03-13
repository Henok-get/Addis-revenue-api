const express = require('express');
const jwt = require('jsonwebtoken');
const app = express();

// Middleware to parse JSON bodies
app.use(express.json());

// Mock client database for token-based auth (replace with real DB in production)
const clients = [
  {
    client_id: 'app123',
    client_secret: 'secret456',
    allowed_scope: 'Unified_Outgoing', // Single allowed scope
  },
];

// Mock user database for Basic Auth (replace with real DB in production)
const users = [
  { username: 'user1', password: 'pass123' },
];

// Secret key for signing JWT (store in environment variables in production)
const JWT_SECRET = 'your_secret_key_here';

// Token endpoint (updated to use default scope "Unified_Outgoing")
app.post('/token', (req, res) => {
  const { grant_type, client_id, client_secret, scope = 'Unified_Outgoing' } = req.body;

  if (!grant_type || !client_id || !client_secret) {
    return res.status(400).json({
      error: 'invalid_request',
      error_description: 'Missing required fields',
    });
  }

  if (grant_type !== 'client_credentials') {
    return res.status(400).json({
      error: 'unsupported_grant_type',
      error_description: 'Only client_credentials is supported',
    });
  }

  const client = clients.find(
    (c) => c.client_id === client_id && c.client_secret === client_secret
  );
  if (!client) {
    return res.status(401).json({
      error: 'invalid_client',
      error_description: 'Invalid client_id or client_secret',
    });
  }

  // Validate scope (only "Unified_Outgoing" is allowed)
  if (scope !== client.allowed_scope) {
    return res.status(400).json({
      error: 'invalid_scope',
      error_description: 'Only scope "Unified_Outgoing" is allowed',
    });
  }

  const payload = {
    client_id: client.client_id,
    scope: scope, // Single scope value
    iat: Math.floor(Date.now() / 1000),
  };
  const access_token = jwt.sign(payload, JWT_SECRET, { expiresIn: '1h' });

  res.json({
    token_type: 'Bearer',
    access_token: access_token,
    scope: scope,
    expires_in: '3600',
    consented_on: Math.floor(Date.now() / 1000).toString(),
  });
});

// Middleware to validate Bearer Token
const authenticateBearer = (req, res, next) => {
  const authHeader = req.headers['authorization'];

  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    return res.status(401).json({
      error: 'unauthorized',
      error_description: 'Bearer token missing or invalid',
    });
  }

  const token = authHeader.split(' ')[1];
  jwt.verify(token, JWT_SECRET, (err, decoded) => {
    if (err) {
      return res.status(403).json({
        error: 'invalid_token',
        error_description: 'Bearer token is invalid or expired',
      });
    }
    req.client = decoded;
    next();
  });
};

// Middleware to validate Basic Auth
const authenticateBasic = (req, res, next) => {
  const basicAuthHeader = req.headers['x-basic-auth']; // Custom header for Basic Auth

  if (!basicAuthHeader) {
    res.setHeader('WWW-Authenticate', 'Basic realm="Restricted Area"');
    return res.status(401).json({
      error: 'unauthorized',
      error_description: 'Basic auth credentials missing',
    });
  }

  const credentials = Buffer.from(basicAuthHeader, 'base64').toString('ascii');
  const [username, password] = credentials.split(':');

  const user = users.find(
    (u) => u.username ===username && u.password === password
  );

  if (!user) {
    res.setHeader('WWW-Authenticate', 'Basic realm="Restricted Area"');
    return res.status(401).json({
      error: 'invalid_credentials',
      error_description: 'Invalid username or password',
    });
  }

  req.user = user;
  next();
};

// Protected route requiring both Bearer and Basic Auth
app.get('/protected', authenticateBearer, authenticateBasic, (req, res) => {
  res.json({
    message: 'Access granted with both Bearer and Basic Auth',
    client_id: req.client.client_id,
    scope: req.client.scope, // Single scope "Unified_Outgoing"
    username: req.user.username,
  });
});

// Start server
const PORT = 3000;
app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});