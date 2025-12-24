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
        user: process.env.EMAIL_USER, // e.g., yourbrand@gmail.com
        pass: process.env.EMAIL_PASS  // your 16-character App Password
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

let cachedDb = null;
async function getDb() {
    if (cachedDb) return cachedDb;
    const client = new MongoClient(uri);
    await client.connect();
    cachedDb = client.db("themotundebrand");
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

// --- DASHBOARD ANALYTICS ---
router.get('/admin/analytics/stock-overview', authenticateAdmin, async (req, res) => {
    try {
        const db = await getDb();
        const products = await db.collection("products").find({}).toArray();

        let womenTotalStock = 0;
        let menTotalStock = 0;
        let kidTotalStock = 0;
        let mistTotalStock = 0;

        products.forEach(product => {
            const totalProductUnits = (product.variants || []).reduce((sum, v) => sum + (parseInt(v.stock) || 0), 0);
            const category = (product.category || "").toLowerCase().trim();
            
            if (category === 'women') womenTotalStock += totalProductUnits;
            else if (category === 'men') menTotalStock += totalProductUnits;
            else if (category === 'kids') kidTotalStock += totalProductUnits;
            else if (category === 'mist') mistTotalStock += totalProductUnits;
        });

        res.json({ womenTotalStock, menTotalStock, kidTotalStock, mistTotalStock });
    } catch (e) {
        res.status(500).json({ error: "Failed to calculate stock totals" });
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

// --- PRODUCT MANAGEMENT (CREATE) ---
router.post('/admin/products', authenticateAdmin, async (req, res) => {
    try {
        if (!s3) throw new Error("Storage not configured.");
        const db = await getDb();
        const { name, variants, description, category, subCategory, imageBase64, fileName, contentType } = req.body;

        if (!imageBase64 || !fileName) return res.status(400).json({ error: "Image required" });

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

// --- PRODUCT MANAGEMENT (UPDATE) ---
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

// --- [NEW] FETCH STOCK FOR SPECIFIC PRODUCT (Used by Shop/Cart) ---
router.get('/products/:id/stock', async (req, res) => {
    try {
        const db = await getDb();
        const product = await db.collection("products").findOne(
            { _id: new ObjectId(req.params.id) },
            { projection: { variants: 1 } }
        );
        if (!product) return res.status(404).json({ error: "Product not found" });
        res.json({ variants: product.variants || [] });
    } catch (e) { res.status(500).json({ error: "Stock fetch failed" }); }
});

// --- UPDATED ORDER HANDLING ---
router.post('/orders', async (req, res) => {
    try {
        const db = await getDb();
        const { items, customerDetails, totalPrice, paymentMethod } = req.body; 

        if (!items || items.length === 0) return res.status(400).json({ error: "Empty cart" });

        // Atomic stock decrement for each item/size combo
        const updateResults = await Promise.all(items.map(async (item) => {
            const qty = Math.abs(parseInt(item.quantity));
            const result = await db.collection("products").updateOne(
                { 
                    _id: new ObjectId(item.productId), 
                    "variants.size": item.size,
                    "variants.stock": { $gte: qty } 
                },
                { $inc: { "variants.$.stock": -qty } }
            );
            return { name: item.name, success: result.modifiedCount > 0 };
        }));

        const failed = updateResults.filter(r => !r.success);
        if (failed.length > 0) {
            return res.status(400).json({ error: "Items out of stock", failed });
        }

        const result = await db.collection("orders").insertOne({
            customerDetails,
            items,
            totalPrice,
            paymentMethod: paymentMethod || 'bank_transfer',
            status: 'pending',
            createdAt: new Date()
        });

        res.status(201).json({ message: "Order successful", orderId: result.insertedId });
    } catch (e) { res.status(500).json({ error: e.message }); }
});

// --- PUBLIC COLLECTION FETCH ---
router.get('/products', async (req, res) => {
    try {
        const db = await getDb();
        const items = await db.collection("products").find({}).sort({ createdAt: -1 }).toArray();
        
        const processed = items.map(item => {
            if (s3 && item.imageKey) {
                item.imageUrl = s3.getSignedUrl('getObject', { Bucket: BUCKET_NAME, Key: item.imageKey, Expires: 86400 });
            }
            // Fallback for missing variants
            if (!item.variants || item.variants.length === 0) {
                item.variants = [{ size: "Standard", price: item.price || 0, stock: item.stock || 0 }];
            }
            return item;
        });

        res.json(processed);
    } catch (e) { res.status(500).json({ error: "Load failed" }); }
});

// --- USER REGISTRATION (UPDATED FOR OTP) ---
router.post('/register', async (req, res) => {
    try {
        const db = await getDb();
        const { name, email, password, phone, whatsapp, address } = req.body;

        const existingUser = await db.collection("users").findOne({ email: email.toLowerCase() });
        if (existingUser) return res.status(400).json({ error: "Email already registered" });

        // Generate 6-digit OTP
        const otp = Math.floor(100000 + Math.random() * 900000).toString();
        const hashedPassword = await bcrypt.hash(password, 10);

        const newUser = {
            name,
            email: email.toLowerCase(),
            password: hashedPassword,
            phone,
            whatsapp,
            address,
            isVerified: false, // User is locked until verified
            otp: otp,
            createdAt: new Date(),
            isAdmin: false
        };

        await db.collection("users").insertOne(newUser);

        // Send Luxury-Branded Email
        const mailOptions = {
            from: `"The Motunde Brand" <${process.env.EMAIL_USER}>`,
            to: email,
            subject: 'Verify Your Account | The Motunde Brand',
            html: `
                <div style="font-family: sans-serif; background-color: #000; color: #fff; padding: 40px; text-align: center; border: 1px solid #F7C8D0;">
                    <h2 style="color: #F7C8D0; letter-spacing: 0.4em; text-transform: uppercase;">The Motunde Brand</h2>
                    <p style="font-size: 12px; letter-spacing: 0.1em; color: rgba(247,200,208,0.7);">WELCOME TO THE INNER CIRCLE</p>
                    <hr style="border: 0; border-top: 1px solid rgba(247,200,208,0.1); margin: 30px 0;">
                    <p style="font-size: 14px; margin-bottom: 30px;">Your activation code is:</p>
                    <div style="background: #1A1A1A; padding: 20px; border: 1px solid #F7C8D0; display: inline-block; letter-spacing: 0.5em; font-size: 24px; font-weight: bold; color: #F7C8D0;">
                        ${otp}
                    </div>
                    <p style="font-size: 10px; margin-top: 30px; color: #666; text-transform: uppercase;">If you did not request this, please ignore this email.</p>
                </div>
            `
        };

        await transporter.sendMail(mailOptions);
        res.status(201).json({ message: "OTP sent to email" });
    } catch (e) {
        res.status(500).json({ error: "Registration failed: " + e.message });
    }
});

// --- NEW: VERIFY OTP ROUTE ---
router.post('/verify-otp', async (req, res) => {
    try {
        const db = await getDb();
        const { email, otp } = req.body;

        const user = await db.collection("users").findOne({ 
            email: email.toLowerCase(), 
            otp: otp 
        });

        if (!user) {
            return res.status(400).json({ error: "Invalid or expired verification code" });
        }

        // Set verified to true and remove the otp from DB
        await db.collection("users").updateOne(
            { _id: user._id },
            { 
                $set: { isVerified: true },
                $unset: { otp: "" } 
            }
        );

        const token = jwt.sign(
            { id: user._id, email: user.email, isAdmin: user.isAdmin || false },
            JWT_SECRET,
            { expiresIn: '7d' }
        );

        delete user.password;
        res.json({ token, user, message: "Account activated" });
    } catch (e) {
        res.status(500).json({ error: "Verification failed" });
    }
});

// --- USER LOGIN ---
router.post('/login', async (req, res) => {
    try {
        const db = await getDb();
        const { email, password } = req.body;

        const user = await db.collection("users").findOne({ email: email.toLowerCase() });
        if (!user) return res.status(401).json({ error: "Invalid email or password" });

        const isMatch = await bcrypt.compare(password, user.password);
        if (!isMatch) return res.status(401).json({ error: "Invalid email or password" });

        const token = jwt.sign(
            { id: user._id, email: user.email, isAdmin: user.isAdmin || false },
            JWT_SECRET,
            { expiresIn: '7d' }
        );

        delete user.password;
        res.json({ token, user });
    } catch (e) {
        res.status(500).json({ error: "Login failed" });
    }
});

// --- GET USER PROFILE (Optional: for account page) ---
router.get('/profile', async (req, res) => {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];
    if (!token) return res.status(401).json({ error: "Not logged in" });

    try {
        const decoded = jwt.verify(token, JWT_SECRET);
        const db = await getDb();
        const user = await db.collection("users").findOne({ _id: new ObjectId(decoded.id) });
        if (!user) return res.status(404).json({ error: "User not found" });
        
        delete user.password;
        res.json(user);
    } catch (e) {
        res.status(401).json({ error: "Session expired" });
    }
});

app.use('/.netlify/functions/api', router);
app.use('/api', router);
module.exports.handler = serverless(app);