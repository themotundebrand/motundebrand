const express = require('express');
const serverless = require('serverless-http');
const { MongoClient, ObjectId } = require('mongodb');
const helmet = require('helmet');
const compression = require('compression');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const AWS = require('aws-sdk');

const app = express();
const router = express.Router();

app.use(helmet());
app.use(compression());
app.use(express.json({ limit: '10mb' }));

const uri = process.env.MONGODB_URI;
const JWT_SECRET = process.env.JWT_SECRET || 'tmb_super_secret_key_2024';

// --- IDRIVE E2 CONFIGURATION ---
let s3 = null;
if (process.env.E2_ENDPOINT) {
    s3 = new AWS.S3({
        accessKeyId: process.env.E2_ACCESS_KEY,
        secretAccessKey: process.env.E2_SECRET_KEY,
        endpoint: new AWS.Endpoint(process.env.E2_ENDPOINT),
        region: process.env.E2_REGION || 'us-west-1',
        s3ForcePathStyle: true,
        signatureVersion: 'v4'
    });
}
const BUCKET_NAME = process.env.E2_BUCKET || 'themotundebrand';

// Connection Pooling
let cachedDb = null;
async function getDb() {
    if (cachedDb) return cachedDb;
    const client = new MongoClient(uri);
    await client.connect();
    cachedDb = client.db("themotundebrand");
    return cachedDb;
}

// --- AUTH MIDDLEWARE ---
const authenticateAdmin = (req, res, next) => {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];
    if (!token) return res.status(401).json({ error: "Unauthorized" });

    jwt.verify(token, JWT_SECRET, (err, user) => {
        if (err || !user.isAdmin) return res.status(403).json({ error: "Forbidden" });
        req.user = user;
        next();
    });
};

// --- NEW: ADMIN AUTH ROUTES ---

// 1. Admin Registration
router.post('/admin/register', async (req, res) => {
    try {
        const { name, email, password } = req.body;
        const db = await getDb();
        
        const existing = await db.collection("admins").findOne({ email });
        if (existing) return res.status(400).json({ error: "Admin already exists" });

        const hashedPassword = await bcrypt.hash(password, 10);
        await db.collection("admins").insertOne({
            name, email, password: hashedPassword, isAdmin: true, createdAt: new Date()
        });
        res.status(201).json({ message: "Admin registered successfully" });
    } catch (e) { res.status(500).json({ error: "Registration failed" }); }
});

// 2. Admin Login
router.post('/admin/login', async (req, res) => {
    try {
        const { email, password } = req.body;
        const db = await getDb();
        const admin = await db.collection("admins").findOne({ email });

        if (!admin || !(await bcrypt.compare(password, admin.password))) {
            return res.status(401).json({ error: "Invalid credentials" });
        }

        const token = jwt.sign({ id: admin._id, isAdmin: true }, JWT_SECRET, { expiresIn: '24h' });
        res.json({ token, isAdmin: true });
    } catch (e) { res.status(500).json({ error: "Login failed" }); }
});

// --- PRODUCT ROUTES ---

router.get('/products', async (req, res) => {
    try {
        const db = await getDb();
        const items = await db.collection("products").find({}).toArray();
        res.json(items);
    } catch (e) { res.status(500).json({ error: "Fetch failed" }); }
});

router.post('/admin/products', authenticateAdmin, async (req, res) => {
    try {
        if (!s3) throw new Error("Storage not configured");
        const db = await getDb();
        const { name, price, size, description, category, imageBase64, fileName, contentType } = req.body;

        const buffer = Buffer.from(imageBase64, 'base64');
        const uploadKey = `${category}/${Date.now()}-${fileName}`;

        const uploadResult = await s3.upload({
            Bucket: BUCKET_NAME,
            Key: uploadKey,
            Body: buffer,
            ContentType: contentType,
            ACL: 'public-read'
        }).promise();

        const product = { name, price: parseFloat(price), size, description, category, imageUrl: uploadResult.Location, createdAt: new Date() };
        await db.collection("products").insertOne(product);
        res.status(201).json({ message: "Success", url: uploadResult.Location });
    } catch (e) { res.status(500).json({ error: e.message }); }
});

// --- EXPORT ---
app.use('/.netlify/functions/api', router);
app.use('/api', router); // Backup for local/redirect consistency
module.exports.handler = serverless(app);