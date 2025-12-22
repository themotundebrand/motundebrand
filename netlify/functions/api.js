const express = require('express');
const serverless = require('serverless-http');
const { MongoClient, ObjectId } = require('mongodb');
const helmet = require('helmet');
const compression = require('compression');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');

const app = express();
const router = express.Router();

// --- SECURITY & OPTIMIZATION ---
app.use(helmet());
app.use(compression());
app.use(express.json());

const uri = process.env.MONGODB_URI;
const JWT_SECRET = process.env.JWT_SECRET;

// Improved Connection Pooling
let cachedClient = null;
let cachedDb = null;

async function getDb() {
    // If we already have a connection, use it immediately
    if (cachedDb) return cachedDb;

    if (!cachedClient) {
        cachedClient = new MongoClient(uri); // Modern driver doesn't need deprecated options
        await cachedClient.connect();
    }
    
    cachedDb = cachedClient.db("themotundebrand");
    return cachedDb;
}

// --- AUTH MIDDLEWARE ---
const authenticateToken = (req, res, next) => {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];

    if (!token) return res.status(401).json({ error: "Access denied. Please log in." });

    jwt.verify(token, JWT_SECRET, (err, user) => {
        if (err) return res.status(403).json({ error: "Session expired. Please log in again." });
        req.user = user;
        next();
    });
};

const authenticateAdmin = (req, res, next) => {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];

    if (!token) return res.status(401).json({ error: "Unauthorized access." });

    jwt.verify(token, JWT_SECRET, (err, user) => {
        if (err || !user.isAdmin) return res.status(403).json({ error: "Admin privileges required." });
        req.user = user;
        next();
    });
};

// --- ADMIN ROUTES ---

// Registration
router.post('/admin/register', async (req, res) => {
    try {
        const db = await getDb();
        const { name, email, password } = req.body;

        if (!email || !password || !name) {
            return res.status(400).json({ error: "All administrative fields required" });
        }

        const existingAdmin = await db.collection("users").findOne({ email: email.toLowerCase() });
        if (existingAdmin) {
            return res.status(400).json({ error: "Identity already registered" });
        }

        const hashedPassword = await bcrypt.hash(password, 12);
        await db.collection("users").insertOne({
            name,
            email: email.toLowerCase(),
            password: hashedPassword,
            isAdmin: true,
            role: "superadmin",
            createdAt: new Date()
        });

        res.status(201).json({ message: "Administrative profile initialized" });
    } catch (error) {
        console.error("Reg Error:", error);
        res.status(500).json({ error: "System enrollment failed" });
    }
});

// Login
router.post('/admin/login', async (req, res) => {
    try {
        const db = await getDb();
        const { email, password } = req.body;

        const admin = await db.collection("users").findOne({ email: email.toLowerCase(), isAdmin: true });
        if (!admin) return res.status(401).json({ error: "Access Denied" });

        const isMatch = await bcrypt.compare(password, admin.password);
        if (!isMatch) return res.status(401).json({ error: "Access Denied" });

        const token = jwt.sign({ id: admin._id, isAdmin: true }, JWT_SECRET, { expiresIn: '12h' });
        res.status(200).json({ token, isAdmin: true });
    } catch (error) {
        res.status(500).json({ error: "System error" });
    }
});

// --- PRODUCT & ORDER ROUTES ---

router.get('/products', async (req, res) => {
    try {
        const db = await getDb();
        const perfumes = await db.collection("products")
            .find({})
            .project({ name: 1, price: 1, imageUrl: 1, category: 1, featured: 1 }) 
            .toArray();
        res.status(200).json(perfumes);
    } catch (error) {
        res.status(500).json({ error: "Fetch failed" });
    }
});

router.post('/admin/products', authenticateAdmin, async (req, res) => {
    try {
        const db = await getDb();
        const product = { ...req.body, createdAt: new Date() };
        const result = await db.collection("products").insertOne(product);
        res.status(201).json({ message: "Product added", id: result.insertedId });
    } catch (error) {
        res.status(500).json({ error: "Failed to add product" });
    }
});

// --- EXPORT ---
app.use('/.netlify/functions/api', router);
app.use('/api', router);

module.exports.handler = serverless(app);