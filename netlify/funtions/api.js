const express = require('express');
const serverless = require('serverless-http');
const { MongoClient, ObjectId } = require('mongodb');
const helmet = require('helmet');
const compression = require('compression');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');

const app = express();
const router = express.Router();

// --- SECURITY & OPTIMIZATION MIDDLEWARE ---
app.use(helmet());
app.use(compression());
app.use(express.json());

const uri = process.env.MONGODB_URI;
const JWT_SECRET = process.env.JWT_SECRET;
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

// --- ADMIN AUTH MIDDLEWARE ---
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


// ADMIN REGISTRATION (Internal Enrollment)
router.post('/admin/register', async (req, res) => {
    try {
        const db = await getDb();
        const { name, email, password } = req.body;

        if (!email || !password || !name) {
            return res.status(400).json({ error: "All administrative fields required" });
        }

        const existingAdmin = await db.collection("users").findOne({ email: email.toLowerCase() });
        if (existingAdmin) {
            return res.status(400).json({ error: "Identity already registered in system" });
        }

        const hashedPassword = await bcrypt.hash(password, 12);
        
        const result = await db.collection("users").insertOne({
            name,
            email: email.toLowerCase(),
            password: hashedPassword,
            isAdmin: true, // Forces Admin Privileges
            role: "superadmin",
            createdAt: new Date()
        });

        res.status(201).json({ message: "Administrative profile initialized" });
    } catch (error) {
        res.status(500).json({ error: "System enrollment failed" });
    }
});

// ADMIN LOGIN (Strict Check)
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

// --- PRODUCT ROUTES ---

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

// --- ADMIN PROTECTED ROUTES ---

// Add Product (Admin Only)
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

// View All Orders (Admin Only)
router.get('/admin/orders', authenticateAdmin, async (req, res) => {
    try {
        const db = await getDb();
        const orders = await db.collection("orders").find().sort({ createdAt: -1 }).toArray();
        res.status(200).json(orders);
    } catch (error) {
        res.status(500).json({ error: "Failed to fetch orders" });
    }
});

// --- AUTH ROUTES ---

// REGISTER (Supports Detailed Address)
router.post('/register', async (req, res) => {
    try {
        const db = await getDb();
        const { name, email, password, phone, whatsapp, address } = req.body;

        if (!email || !password || !name) return res.status(400).json({ error: "Required fields missing" });

        const existingUser = await db.collection("users").findOne({ email: email.toLowerCase() });
        if (existingUser) return res.status(400).json({ error: "Account already exists" });

        const hashedPassword = await bcrypt.hash(password, 12);
        const result = await db.collection("users").insertOne({
            name,
            email: email.toLowerCase(),
            password: hashedPassword,
            phone,
            whatsapp,
            address, // Contains street, city, state, country
            isAdmin: false,
            createdAt: new Date()
        });

        const token = jwt.sign({ id: result.insertedId, isAdmin: false }, JWT_SECRET, { expiresIn: '24h' });
        res.status(201).json({ token, user: { name, email: email.toLowerCase() } });
    } catch (error) {
        res.status(500).json({ error: "Registration failed" });
    }
});

// CUSTOMER LOGIN
router.post('/login', async (req, res) => {
    try {
        const db = await getDb();
        const { email, password } = req.body;

        const user = await db.collection("users").findOne({ email: email.toLowerCase() });
        if (!user) return res.status(404).json({ error: "User not found" });

        const isMatch = await bcrypt.compare(password, user.password);
        if (!isMatch) return res.status(400).json({ error: "Invalid password" });

        const token = jwt.sign({ id: user._id, isAdmin: user.isAdmin || false }, JWT_SECRET, { expiresIn: '24h' });
        res.status(200).json({ token, user: { name: user.name, email: user.email } });
    } catch (error) {
        res.status(500).json({ error: "Login failed" });
    }
});


// --- ORDER ROUTES ---

router.post('/orders', authenticateToken, async (req, res) => {
    try {
        const db = await getDb();
        const { items, total } = req.body;

        const orderData = {
            userId: req.user.id,
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