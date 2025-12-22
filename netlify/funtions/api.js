const express = require('express');
const serverless = require('serverless-http');
const { MongoClient } = require('mongodb');
const helmet = require('helmet');
const compression = require('compression');
const jwt = require('jsonwebtoken'); // Added
const bcrypt = require('bcryptjs'); // Added

const app = express();
const router = express.Router();

// --- SECURITY & OPTIMIZATION MIDDLEWARE ---
app.use(helmet());
app.use(compression());
app.use(express.json());

const uri = process.env.MONGODB_URI;
const JWT_SECRET = process.env.JWT_SECRET; // Ensure this is in your Netlify Environment Variables
let cachedClient = null;

async function getDb() {
    if (!cachedClient) {
        cachedClient = new MongoClient(uri, {
            useNewUrlParser: true,
            useUnifiedTopology: true,
            maxPoolSize: 10, 
        });
        await cachedClient.connect();
    }
    return cachedClient.db("themotundebrand");
}

// --- AUTH MIDDLEWARE (To protect specific routes) ---
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

// --- AUTH ROUTES ---

// REGISTER
router.post('/register', async (req, res) => {
    try {
        const db = await getDb();
        const { name, email, password } = req.body;

        if (!email || !password) return res.status(400).json({ error: "Missing fields" });

        const existingUser = await db.collection("users").findOne({ email });
        if (existingUser) return res.status(400).json({ error: "Account already exists" });

        const hashedPassword = await bcrypt.hash(password, 12);
        const result = await db.collection("users").insertOne({
            name,
            email,
            password: hashedPassword,
            createdAt: new Date()
        });

        const token = jwt.sign({ id: result.insertedId }, JWT_SECRET, { expiresIn: '24h' });
        res.status(201).json({ token, user: { name, email } });
    } catch (error) {
        res.status(500).json({ error: "Registration failed" });
    }
});

// LOGIN
router.post('/login', async (req, res) => {
    try {
        const db = await getDb();
        const { email, password } = req.body;

        const user = await db.collection("users").findOne({ email });
        if (!user) return res.status(404).json({ error: "User not found" });

        const isMatch = await bcrypt.compare(password, user.password);
        if (!isMatch) return res.status(400).json({ error: "Invalid password" });

        const token = jwt.sign({ id: user._id }, JWT_SECRET, { expiresIn: '24h' });
        res.status(200).json({ token, user: { name: user.name, email: user.email } });
    } catch (error) {
        res.status(500).json({ error: "Login failed" });
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
        res.set('Cache-Control', 'public, max-age=3600');
        res.status(200).json(perfumes);
    } catch (error) {
        res.status(500).json({ error: "Fetch failed" });
    }
});

// Protected Order Route (Using authenticateToken)
router.post('/orders', authenticateToken, async (req, res) => {
    try {
        const db = await getDb();
        const { items, total } = req.body;

        const orderData = {
            userId: req.user.id, // Linked to the logged-in user
            items,
            total,
            createdAt: new Date(),
            status: 'pending'
        };
        
        const result = await db.collection("orders").insertOne(orderData);
        res.status(201).json({ message: "Order placed", id: result.insertedId });
    } catch (error) {
        res.status(500).json({ error: "Order failed" });
    }
});

app.use('/.netlify/functions/api', router);
app.use('/api', router);

module.exports.handler = serverless(app);