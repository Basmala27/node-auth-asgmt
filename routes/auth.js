const express = require('express');
const router = express.Router();

const { hashPassword, verifyPassword } = require('../password-utils');
const { signJWT, verifyJWT } = require('../jwt-utils');

// In-memory user store (just for demo purposes)
const users = {};

// 🟩 Register Route
router.post('/register', (req, res) => {
  const { username, password } = req.body;

  if (users[username]) {
    return res.status(400).json({ message: 'Username already exists' });
  }

  const hashedPassword = hashPassword(password);
  users[username] = hashedPassword;

  res.json({ message: 'User registered successfully' });
});

// 🟩 Login Route
router.post('/login', (req, res) => {
  const { username, password } = req.body;

  const storedHash = users[username];

  if (!storedHash || !verifyPassword(password, storedHash)) {
    return res.status(401).json({ message: 'Invalid credentials' });
  }

  const token = signJWT({ username }, 'your-secret-key');
  res.json({ token });
});

// 🟩 Protected Route
router.get('/protected', (req, res) => {
  const authHeader = req.headers.authorization;

  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    return res.status(401).json({ message: 'Unauthorized' });
  }

  const token = authHeader.split(' ')[1];

  try {
    const decoded = verifyJWT(token, 'your-secret-key');
    req.user = decoded;
    res.json({ message: 'Access granted', user: decoded });
  } catch (err) {
    res.status(401).json({ message: 'Invalid or expired token' });
  }
});

module.exports = router;
