require('dotenv').config();
const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const User = require('./models/User');
const authMiddleware = require('./middleware/auth');
const { generateTokens } = require('./utils/tokens');

const app = express();
const PORT = process.env.PORT || 5001;

// ----------------------
// CORS (VERY IMPORTANT)
// ----------------------
app.use(cors({
  origin: process.env.FRONTEND_URL || '*',
  methods: ['GET', 'POST', 'PUT', 'DELETE'],
  credentials: true,
}));

app.use(express.json());

// ----------------------
// HEALTH CHECK (REQUIRED BY RENDER)
// ----------------------
app.get('/health', (req, res) => {
  res.json({ status: 'ok' });
});

// ----------------------
// MongoDB connection
// ----------------------
mongoose.connect(process.env.MONGO_URI)
  .then(() => console.log('✓ MongoDB connected'))
  .catch(err => console.error('✗ MongoDB connection error:', err));

// ----------------------
// Register
// ----------------------
app.post('/auth/register', async (req, res) => {
  try {
    const { name, email, password } = req.body;
    if (!name || !email || !password) {
      return res.status(400).json({ error: 'Name, email, and password required' });
    }

    const already = await User.findOne({ email });
    if (already) return res.status(400).json({ error: 'Email already used' });

    const passwordHash = await bcrypt.hash(password, 10);
    const user = new User({
      name,
      email,
      passwordHash,
      role: 'user',
      addresses: [],
      phone: '',
      refreshTokens: []
    });

    await user.save();

    const tokens = generateTokens(user._id.toString(), user.role);
    user.refreshTokens.push(tokens.refreshToken);
    await user.save();

    res.status(201).json({
      accessToken: tokens.accessToken,
      refreshToken: tokens.refreshToken,
      user: {
        id: user._id,
        name: user.name,
        email: user.email,
        role: user.role
      }
    });
  } catch (error) {
    console.error('Register error:', error);
    res.status(500).json({ error: 'Registration failed' });
  }
});

// ----------------------
// Login
// ----------------------
app.post('/auth/login', async (req, res) => {
  try {
    const { email, password } = req.body;
    if (!email || !password)
      return res.status(400).json({ error: 'Email and password required' });

    const user = await User.findOne({ email });
    if (!user) return res.status(401).json({ error: 'Invalid credentials' });

    const match = await bcrypt.compare(password, user.passwordHash);
    if (!match) return res.status(401).json({ error: 'Invalid credentials' });

    const tokens = generateTokens(user._id.toString(), user.role);
    user.refreshTokens.push(tokens.refreshToken);
    await user.save();

    res.json({
      accessToken: tokens.accessToken,
      refreshToken: tokens.refreshToken,
      user: {
        id: user._id,
        name: user.name,
        email: user.email,
        role: user.role
      }
    });
  } catch (error) {
    console.error('Login error:', error);
    res.status(500).json({ error: 'Login failed' });
  }
});

// ----------------------
// Refresh token
// ----------------------
app.post('/auth/refresh', async (req, res) => {
  try {
    const { refreshToken } = req.body;
    if (!refreshToken) return res.status(401).json({ error: 'Refresh token required' });

    const user = await User.findOne({ refreshTokens: refreshToken });
    if (!user) return res.status(401).json({ error: 'Invalid refresh token' });

    const tokens = generateTokens(user._id.toString(), user.role);

    user.refreshTokens = user.refreshTokens.filter(t => t !== refreshToken);
    user.refreshTokens.push(tokens.refreshToken);
    await user.save();

    res.json(tokens);
  } catch (error) {
    console.error('Refresh error:', error);
    res.status(500).json({ error: 'Refresh failed' });
  }
});

// ----------------------
// Logout
// ----------------------
app.post('/auth/logout', authMiddleware, async (req, res) => {
  try {
    const { refreshToken } = req.body;
    const user = await User.findById(req.userId);

    if (user && refreshToken) {
      user.refreshTokens = user.refreshTokens.filter(t => t !== refreshToken);
      await user.save();
    }

    res.json({ message: 'Logged out' });
  } catch (error) {
    console.error('Logout error:', error);
    res.status(500).json({ error: 'Logout failed' });
  }
});

// ----------------------
// User Profile
// ----------------------
app.get('/me', authMiddleware, async (req, res) => {
  try {
    const u = await User.findById(req.userId);
    if (!u) return res.status(404).json({ error: 'User not found' });

    res.json({
      id: u._id,
      name: u.name,
      email: u.email,
      role: u.role,
      phone: u.phone,
      addresses: u.addresses,
      createdAt: u.createdAt,
    });
  } catch (e) {
    console.error('Profile error:', e);
    res.status(500).json({ error: 'Could not fetch profile' });
  }
});

// ----------------------
// Update Profile
// ----------------------
app.put('/me', authMiddleware, async (req, res) => {
  try {
    const { name, phone, addresses } = req.body;
    const u = await User.findById(req.userId);

    if (!u) return res.status(404).json({ error: 'User not found' });

    if (name) u.name = name;
    if (phone) u.phone = phone;
    if (addresses) u.addresses = addresses;

    await u.save();

    res.json({
      id: u._id,
      name: u.name,
      email: u.email,
      role: u.role,
      phone: u.phone,
      addresses: u.addresses
    });
  } catch (e) {
    console.error('Update error:', e);
    res.status(500).json({ error: 'Failed to update user' });
  }
});

// ----------------------
// Admin List Users
// ----------------------
app.get('/admin/users', authMiddleware, async (req, res) => {
  const admin = await User.findById(req.userId);
  if (!admin || admin.role !== 'admin')
    return res.status(403).json({ error: 'Admin permission required' });

  const users = await User.find().select('-passwordHash -refreshTokens');
  res.json(users);
});

// ----------------------
// Admin Delete User
// ----------------------
app.delete('/admin/users/:id', authMiddleware, async (req, res) => {
  const admin = await User.findById(req.userId);
  if (!admin || admin.role !== 'admin')
    return res.status(403).json({ error: 'Admin permission required' });

  await User.findByIdAndDelete(req.params.id);
  res.json({ message: 'User deleted' });
});

// ----------------------
// Start server
// ----------------------
app.listen(PORT, () => {
  console.log(`✓ Auth service running on ${PORT}`);
});
