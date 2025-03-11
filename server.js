const express = require('express');
const bodyParser = require('body-parser');
const jwt = require('jsonwebtoken');
const fs = require('fs');
const path = require('path');

const app = express();
app.use(bodyParser.json());

// Secret key for JWT signing (store securely in production)
const JWT_SECRET = 'your_jwt_secret';
// Token expiry time (in seconds)
const TOKEN_EXPIRY = 3600;

// Load the client credentials from the JSON file
const clientsFilePath = path.join(__dirname, 'clients.json');
let clients = [];
try {
  const data = fs.readFileSync(clientsFilePath, 'utf8');
  clients = JSON.parse(data);
} catch (error) {
  console.error('Error reading clients.json file:', error);
}

// Middleware to protect routes by verifying JWT tokens
function authenticateToken(req, res, next) {
  const authHeader = req.headers.authorization;
  const token = authHeader && authHeader.split(' ')[1];

  if (!token) {
    return res.status(403).json({ error: 'Token is required' });
  }

  jwt.verify(token, JWT_SECRET, (err, decoded) => {
    if (err) {
      return res.status(401).json({ error: 'Invalid or expired token' });
    }
    req.user = decoded;
    next();
  });
}

// Token generation endpoint (POST /token)
app.post('/token', (req, res) => {
  const { grant_type, client_id, client_secret, scope } = req.body;

  // Validate mandatory fields
  if (!grant_type || !client_id || !client_secret) {
    return res.status(400).json({
      error: 'Missing required fields. grant_type, client_id, and client_secret are required.'
    });
  }

  // Enforce expected grant_type for client credentials flow
  if (grant_type !== 'client_credentials') {
    return res.status(400).json({
      error: 'Invalid grant_type. Expected "client_credentials".'
    });
  }

  // Find matching client from the JSON file
  const client = clients.find(
    (c) => c.client_id === client_id && c.client_secret === client_secret
  );

  if (!client) {
    return res.status(401).json({ error: 'Invalid client_id or client_secret' });
  }

  // Use provided scope or default to the one from stored client record
  const finalScope = scope || client.scope || 'Unified_Outgoing';

  // Create token payload
  const tokenPayload = { client_id, scope: finalScope };

  // Generate the JWT token
  const access_token = jwt.sign(tokenPayload, JWT_SECRET, { expiresIn: TOKEN_EXPIRY });

  // Respond with token details
  res.json({
    token_type: 'Bearer',
    access_token: access_token,
    scope: finalScope,
    expires_in: TOKEN_EXPIRY.toString(),
    consented_on: new Date().toISOString()
  });
});

// Protected route example (GET /protected)
app.get('/protected', authenticateToken, (req, res) => {
  res.json({
    message: 'Access granted to protected resource',
    clientData: req.user
  });
});

// Start the Express server
const PORT = 3000;
app.listen(PORT, () => {
  console.log(`Token service API running on port ${PORT}`);
});
