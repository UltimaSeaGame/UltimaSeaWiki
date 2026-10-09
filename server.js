const express = require('express');
const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const path = require('path');
const cors = require('cors');
require('dotenv').config();

const app = express();
app.use(express.json());
app.use(cors());
app.use(express.static(path.join(__dirname, 'public')));

const PORT = process.env.PORT || 3000;
const MONGO_URI = process.env.MONGO_URI || 'mongodb://localhost:27017/roblox_wiki';
const JWT_SECRET = process.env.JWT_SECRET || 'supersecretkey_roblox_wiki';

// เชื่อมต่อ MongoDB
mongoose.connect(MONGO_URI)
  .then(() => console.log('MongoDB Connected successfully'))
  .catch(err => console.error('MongoDB Connection Error:', err));

// --- Schemas & Models ---
// Schema สำหรับผู้ใช้งาน (ข้อ 10, 12)
const UserSchema = new mongoose.Schema({
  username: { type: String, required: true, unique: true },
  email: { type: String, required: true, unique: true },
  password: { type: String, required: true },
  role: { 
    type: String, 
    enum: ['Guest', 'Member', 'Contributor', 'Editor', 'Admin', 'Owner'], 
    default: 'Member' 
  },
  createdAt: { type: Date, default: Date.now }
});

// Schema สำหรับบทความ Wiki / Items / Characters (ข้อ 1, 3, 4, 10)
const ArticleSchema = new mongoose.Schema({
  title: { type: String, required: true },
  slug: { type: String, required: true, unique: true },
  category: { 
    type: String, 
    enum: ['Items', 'Characters', 'Weapons', 'Skills', 'Maps', 'Guides', 'Patch Notes'], 
    required: true 
  },
  rarity: { 
    type: String, 
    enum: ['Common', 'Uncommon', 'Rare', 'Epic', 'Legendary', 'Mythic', 'Secret'], 
    default: 'Common' 
  },
  content: { type: String, required: true },
  status: { type: String, enum: ['Draft', 'Pending Review', 'Published', 'Archived'], default: 'Published' },
  author: { type: String, default: 'Admin' },
  updatedAt: { type: Date, default: Date.now }
});

const User = mongoose.model('User', UserSchema);
const Article = mongoose.model('Article', ArticleSchema);

// --- Middleware ยืนยัน ตัวตนและ สิทธิ์ ---
const authenticateToken = (req, res, next) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];
  if (!token) return res.status(401).json({ message: 'Access Denied: No token provided' });

  jwt.verify(token, JWT_SECRET, (err, user) => {
    if (err) return res.status(403).json({ message: 'Invalid or expired token' });
    req.user = user;
    next();
  });
};

const authorizeRole = (roles) => {
  return (req, res, next) => {
    if (!roles.includes(req.user.role)) {
      return res.status(403).json({ message: 'Permission Denied: Insufficient privilege' });
    }
    next();
  };
};

// --- API Routes: Auth ---
// สมัครสมาชิก
app.post('/api/auth/register', async (req, res) => {
  try {
    const { username, email, password } = req.body;
    const existingUser = await User.findOne({ $or: [{ email }, { username }] });
    if (existingUser) return res.status(400).json({ message: 'Username or Email already exists' });

    const hashedPassword = await bcrypt.hash(password, 10);
    const user = new User({ username, email, password: hashedPassword });
    await user.save();
    res.status(201).json({ message: 'User registered successfully' });
  } catch (err) {
    res.status(500).json({ message: err.message });
  }
});

// เข้าสู่ระบบ
app.post('/api/auth/login', async (req, res) => {
  try {
    const { email, password } = req.body;
    const user = await User.findOne({ email });
    if (!user) return res.status(400).json({ message: 'Invalid email or password' });

    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) return res.status(400).json({ message: 'Invalid email or password' });

    const token = jwt.sign(
      { id: user._id, username: user.username, role: user.role },
      JWT_SECRET,
      { expiresIn: '1d' }
    );
    res.json({ token, user: { username: user.username, role: user.role } });
  } catch (err) {
    res.status(500).json({ message: err.message });
  }
});

// --- API Routes: Wiki Articles & Search ---
// ดึงบทความทั้งหมด / ค้นหา (ข้อ 2)
app.get('/api/articles', async (req, res) => {
  try {
    const { q, category } = req.query;
    let query = { status: 'Published' };

    if (q) {
      query.$or = [
        { title: { $regex: q,$options: 'i' } },
        { content: { $regex: q,$options: 'i' } }
      ];
    }
    if (category) {
      query.category = category;
    }

    const articles = await Article.find(query).sort({ updatedAt: -1 });
    res.json(articles);
  } catch (err) {
    res.status(500).json({ message: err.message });
  }
});

// ดึงรายละเอียดบทความตาม Slug
app.get('/api/articles/:slug', async (req, res) => {
  try {
    const article = await Article.findOne({ slug: req.params.slug, status: 'Published' });
    if (!article) return res.status(404).json({ message: 'Article not found' });
    res.json(article);
  } catch (err) {
    res.status(500).json({ message: err.message });
  }
});

// --- API Routes: Admin Management (ข้อ 10) ---
// สร้างบทความใหม่ (เฉพาะ Admin/Editor)
app.post('/api/articles', authenticateToken, authorizeRole(['Admin', 'Owner', 'Editor']), async (req, res) => {
  try {
    const { title, slug, category, rarity, content, status } = req.body;
    const newArticle = new Article({
      title,
      slug,
      category,
      rarity,
      content,
      status,
      author: req.user.username
    });
    await newArticle.save();
    res.status(201).json({ message: 'Article created successfully', article: newArticle });
  } catch (err) {
    res.status(400).json({ message: err.message });
  }
});

// ลบบทความ (เฉพาะ Admin/Owner)
app.delete('/api/articles/:id', authenticateToken, authorizeRole(['Admin', 'Owner']), async (req, res) => {
  try {
    await Article.findByIdAndDelete(req.params.id);
    res.json({ message: 'Article deleted successfully' });
  } catch (err) {
    res.status(500).json({ message: err.message });
  }
});

// หน้าหลักของเว็บ
app.get('*', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});
