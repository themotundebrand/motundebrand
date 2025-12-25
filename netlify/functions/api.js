const express = require('express');
const serverless = require('serverless-http');
const { MongoClient, ObjectId } = require('mongodb');
const helmet = require('helmet');
const compression = require('compression');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const AWS = require('aws-sdk');
const nodemailer = require('nodemailer');

const app = express();
const router = express.Router();

app.use(helmet());
app.use(compression());
app.use(express.json({ limit: '10mb' }));

const uri = process.env.MONGODB_URI;
const JWT_SECRET = process.env.JWT_SECRET;

// --- GMAIL SMTP CONFIGURATION ---
const transporter = nodemailer.createTransport({
    service: 'gmail',
    auth: {
        user: process.env.EMAIL_USER,
        pass: process.env.EMAIL_PASS 
    }
});

// --- IDRIVE E2 / S3 CONFIGURATION ---
let s3 = null;
if (process.env.E2_ENDPOINT) {
    s3 = new AWS.S3({
        accessKeyId: process.env.E2_ACCESS_KEY,
        secretAccessKey: process.env.E2_SECRET_KEY,
        endpoint: new AWS.Endpoint(process.env.E2_ENDPOINT),
        region: process.env.E2_REGION,
        s3ForcePathStyle: true,
        signatureVersion: 'v4'
    });
}
const BUCKET_NAME = process.env.E2_BUCKET;

// --- IMPROVED DATABASE CONNECTION (Prevents 502 Errors) ---
let cachedClient = null;
let cachedDb = null;

async function getDb() {
    if (cachedDb) return cachedDb;
    if (!cachedClient) {
        cachedClient = new MongoClient(uri, {
            serverSelectionTimeoutMS: 5000,
        });
        await cachedClient.connect();
    }
    cachedDb = cachedClient.db("themotundebrand");
    return cachedDb;
}

// --- AUTHENTICATION MIDDLEWARE ---
const authenticateAdmin = (req, res, next) => {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];
    
    if (!token) return res.status(401).json({ error: "Unauthorized: No token provided" });

    jwt.verify(token, JWT_SECRET, (err, decoded) => {
        if (err) return res.status(403).json({ error: "Forbidden: Invalid Token" });
        if (!decoded.isAdmin) return res.status(403).json({ error: "Forbidden: Not an Admin" });
        req.user = decoded;
        next();
    });
};

// --- ADMIN: DASHBOARD ANALYTICS ---
router.get('/admin/analytics/stock-overview', authenticateAdmin, async (req, res) => {
    try {
        const db = await getDb();
        const products = await db.collection("products").find({}).toArray();

        let stats = { women: 0, men: 0, kids: 0, mist: 0 };

        products.forEach(product => {
            const stock = (product.variants || []).reduce((sum, v) => sum + (parseInt(v.stock) || 0), 0);
            const cat = (product.category || "").toLowerCase().trim();
            if (stats.hasOwnProperty(cat)) stats[cat] += stock;
        });

        res.json(stats);
    } catch (e) {
        res.status(500).json({ error: "Failed to calculate stock" });
    }
});

// --- ADMIN: GET ALL ORDERS ---
router.get('/admin/orders', authenticateAdmin, async (req, res) => {
    try {
        const db = await getDb();
        const orders = await db.collection("orders").find({}).sort({ createdAt: -1 }).toArray();
        res.json(orders);
    } catch (e) {
        res.status(500).json({ error: "Failed to fetch orders" });
    }
});

// --- ADMIN: USER MANAGEMENT ---
router.get('/admin/users/count', authenticateAdmin, async (req, res) => {
    try {
        const db = await getDb();
        const count = await db.collection("users").countDocuments();
        res.json({ count });
    } catch (e) {
        res.status(500).json({ error: "Failed to count users" });
    }
});

router.get('/admin/users', authenticateAdmin, async (req, res) => {
    try {
        const db = await getDb();
        const users = await db.collection("users").find({}).project({ password: 0 }).sort({ createdAt: -1 }).toArray();
        res.json(users);
    } catch (e) {
        res.status(500).json({ error: "Failed to fetch users" });
    }
});

// --- ADMIN LOGIN ---
router.post('/admin/login', async (req, res) => {
    try {
        const { email, password } = req.body;
        const db = await getDb();
        const admin = await db.collection("admins").findOne({ email });

        if (!admin || !(await bcrypt.compare(password, admin.password))) {
            return res.status(401).json({ error: "Invalid credentials" });
        }

        const token = jwt.sign(
            { id: admin._id.toString(), isAdmin: true }, 
            JWT_SECRET, 
            { expiresIn: '24h' }
        );
        
        res.json({ token, isAdmin: true });
    } catch (e) { res.status(500).json({ error: "Login failed" }); }
});

// --- PRODUCT MANAGEMENT ---
router.post('/admin/products', authenticateAdmin, async (req, res) => {
    try {
        if (!s3) throw new Error("Storage not configured.");
        const db = await getDb();
        const { name, variants, description, category, subCategory, imageBase64, fileName, contentType } = req.body;

        const buffer = Buffer.from(imageBase64, 'base64');
        const uploadKey = `${category}/${Date.now()}-${fileName.replace(/\s+/g, '-')}`;

        await s3.upload({
            Bucket: BUCKET_NAME,
            Key: uploadKey,
            Body: buffer,
            ContentType: contentType || 'image/jpeg'
        }).promise();

        const product = { 
            name, 
            variants: (variants || []).map(v => ({ size: String(v.size), price: parseFloat(v.price), stock: parseInt(v.stock) })),
            description, 
            category: (category || "unassigned").toLowerCase().trim(),
            subCategory: subCategory || "", 
            imageKey: uploadKey,
            createdAt: new Date() 
        };

        await db.collection("products").insertOne(product);
        res.status(201).json({ message: "Product added" });
    } catch (e) { res.status(500).json({ error: e.message }); }
});

router.put('/admin/products/:id', authenticateAdmin, async (req, res) => {
    try {
        const db = await getDb();
        const productId = req.params.id;
        const { name, variants, description, category, subCategory, imageBase64, fileName } = req.body;

        const existing = await db.collection("products").findOne({ _id: new ObjectId(productId) });
        if (!existing) return res.status(404).json({ error: "Product not found" });

        let imageKey = existing.imageKey;
        if (imageBase64 && fileName) {
            imageKey = `${category}/${Date.now()}-${fileName.replace(/\s+/g, '-')}`;
            await s3.upload({ Bucket: BUCKET_NAME, Key: imageKey, Body: Buffer.from(imageBase64, 'base64') }).promise();
            if (existing.imageKey) await s3.deleteObject({ Bucket: BUCKET_NAME, Key: existing.imageKey }).promise();
        }

        await db.collection("products").updateOne(
            { _id: new ObjectId(productId) },
            { $set: { name, variants, description, category, subCategory, imageKey, updatedAt: new Date() } }
        );
        res.json({ message: "Updated successfully" });
    } catch (e) { res.status(500).json({ error: e.message }); }
});

// --- PUBLIC ROUTES ---
router.get('/products', async (req, res) => {
    try {
        const db = await getDb();
        const items = await db.collection("products").find({}).sort({ createdAt: -1 }).toArray();
        const processed = items.map(item => {
            if (s3 && item.imageKey) {
                item.imageUrl = s3.getSignedUrl('getObject', { Bucket: BUCKET_NAME, Key: item.imageKey, Expires: 86400 });
            }
            return item;
        });
        res.json(processed);
    } catch (e) { res.status(500).json({ error: "Load failed" }); }
});

router.post('/orders', async (req, res) => {
    try {
        const db = await getDb();
        const { items, customerDetails, totalPrice, paymentMethod, userId } = req.body; 

        const finalOrder = {
            userId: userId ? new ObjectId(userId) : "GUEST", 
            customerDetails,
            items,
            totalPrice,
            paymentMethod: paymentMethod || 'bank_transfer',
            status: 'pending',
            createdAt: new Date()
        };

        const result = await db.collection("orders").insertOne(finalOrder);
        res.status(201).json({ message: "Order successful", orderId: result.insertedId });
    } catch (e) { res.status(500).json({ error: e.message }); }
});

// --- USER AUTH & PROFILE ---
router.post('/register', async (req, res) => {
    try {
        const db = await getDb();
        const { name, email, password, phone, whatsapp, address } = req.body;
        const existingUser = await db.collection("users").findOne({ email: email.toLowerCase() });
        if (existingUser) return res.status(400).json({ error: "Email already registered" });

        const otp = Math.floor(100000 + Math.random() * 900000).toString();
        const hashedPassword = await bcrypt.hash(password, 10);

        await db.collection("users").insertOne({
            name, email: email.toLowerCase(), password: hashedPassword, phone, whatsapp, address,
            isVerified: false, otp, createdAt: new Date()
        });

        await transporter.sendMail({
            from: `"The Motunde Brand" <${process.env.EMAIL_USER}>`,
            to: email,
            subject: 'Confirm Your Access',
            html: `<h1>Your OTP is ${otp}</h1>`
        });

        res.status(201).json({ message: "OTP sent" });
    } catch (e) { res.status(500).json({ error: e.message }); }
});

router.post('/verify-otp', async (req, res) => {
    try {
        const db = await getDb();
        const { email, otp } = req.body;
        const user = await db.collection("users").findOne({ email: email.toLowerCase(), otp });
        if (!user) return res.status(400).json({ error: "Invalid OTP" });

        await db.collection("users").updateOne({ _id: user._id }, { $set: { isVerified: true }, $unset: { otp: "" } });
        const token = jwt.sign({ id: user._id, isAdmin: false }, JWT_SECRET, { expiresIn: '7d' });
        res.json({ token, user, message: "Verified" });
    } catch (e) { res.status(500).json({ error: "Failed" }); }
});

router.post('/login', async (req, res) => {
    try {
        const db = await getDb();
        const { email, password } = req.body;
        const user = await db.collection("users").findOne({ email: email.toLowerCase() });
        if (!user || !user.isVerified || !(await bcrypt.compare(password, user.password))) {
            return res.status(401).json({ error: "Invalid credentials or unverified" });
        }
        const token = jwt.sign({ id: user._id, isAdmin: false }, JWT_SECRET, { expiresIn: '7d' });
        res.json({ token, user });
    } catch (e) { res.status(500).json({ error: "Login failed" }); }
});

// --- EXPORT FOR NETLIFY ---
app.use('/.netlify/functions/api', router);
app.use('/api', router);
module.exports.handler = serverless(app);