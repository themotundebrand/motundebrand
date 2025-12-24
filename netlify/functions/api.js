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
const JWT_SECRET = process.env.JWT_SECRET;

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

// --- [CRITICAL FIX] PRODUCT MANAGEMENT (CREATE) ---
router.post('/admin/products', authenticateAdmin, async (req, res) => {
    try {
        if (!s3) throw new Error("Storage (S3/IDrive) not configured. Check environment variables.");
        
        const db = await getDb();
        const { name, variants, description, category, subCategory, imageBase64, fileName, contentType } = req.body;

        // Validation to prevent 500 errors from missing data
        if (!imageBase64 || !fileName) {
            return res.status(400).json({ error: "Image data and file name are required." });
        }

        const buffer = Buffer.from(imageBase64, 'base64');
        const cleanFileName = fileName.replace(/\s+/g, '-');
        const uploadKey = `${category}/${Date.now()}-${cleanFileName}`;

        // S3 Upload
        await s3.upload({
            Bucket: BUCKET_NAME,
            Key: uploadKey,
            Body: buffer,
            ContentType: contentType || 'image/jpeg'
        }).promise();

        const formattedVariants = (variants || []).map(v => ({
            size: String(v.size),
            price: parseFloat(v.price) || 0,
            stock: parseInt(v.stock) || 0 
        }));

        const product = { 
            name, 
            variants: formattedVariants,
            description, 
            category: (category || "unassigned").toLowerCase().trim(),
            subCategory: subCategory || "", 
            imageKey: uploadKey,
            createdAt: new Date() 
        };

        await db.collection("products").insertOne(product);
        res.status(201).json({ message: "Product added successfully" });
    } catch (e) { 
        console.error("Product Creation Error:", e);
        res.status(500).json({ error: e.message }); 
    }
});

// --- PRODUCT MANAGEMENT (UPDATE) ---
router.put('/admin/products/:id', authenticateAdmin, async (req, res) => {
    try {
        const db = await getDb();
        const productId = req.params.id;
        const { name, variants, description, category, subCategory, imageBase64, fileName, contentType } = req.body;

        const existingProduct = await db.collection("products").findOne({ _id: new ObjectId(productId) });
        if (!existingProduct) return res.status(404).json({ error: "Product not found" });

        let updatedImageKey = existingProduct.imageKey;

        if (imageBase64 && fileName) {
            const buffer = Buffer.from(imageBase64, 'base64');
            const cleanFileName = fileName.replace(/\s+/g, '-');
            updatedImageKey = `${category}/${Date.now()}-${cleanFileName}`;

            await s3.upload({
                Bucket: BUCKET_NAME,
                Key: updatedImageKey,
                Body: buffer,
                ContentType: contentType || 'image/jpeg'
            }).promise();

            if (existingProduct.imageKey) {
                try { await s3.deleteObject({ Bucket: BUCKET_NAME, Key: existingProduct.imageKey }).promise(); } 
                catch (delErr) { console.error("Old image cleanup failed"); }
            }
        }

        const formattedVariants = (variants || []).map(v => ({
            size: String(v.size),
            price: parseFloat(v.price) || 0,
            stock: parseInt(v.stock) || 0 
        }));

        await db.collection("products").updateOne(
            { _id: new ObjectId(productId) },
            { 
                $set: { 
                    name, 
                    variants: formattedVariants, 
                    description, 
                    category: (category || "unassigned").toLowerCase().trim(), 
                    subCategory: subCategory || "",
                    imageKey: updatedImageKey, 
                    updatedAt: new Date() 
                } 
            }
        );

        res.json({ message: "Product updated successfully" });
    } catch (e) { 
        console.error("Update Error:", e);
        res.status(500).json({ error: e.message }); 
    }
});

// --- PRODUCT MANAGEMENT (DELETE) ---
router.delete('/admin/products/:id', authenticateAdmin, async (req, res) => {
    try {
        const db = await getDb();
        const productId = req.params.id;
        const product = await db.collection("products").findOne({ _id: new ObjectId(productId) });
        if (!product) return res.status(404).json({ error: "Product not found" });

        if (s3 && product.imageKey) {
            await s3.deleteObject({ Bucket: BUCKET_NAME, Key: product.imageKey }).promise();
        }

        await db.collection("products").deleteOne({ _id: new ObjectId(productId) });
        res.json({ message: "Product deleted" });
    } catch (e) { res.status(500).json({ error: e.message }); }
});

// --- ORDER HANDLING ---
router.post('/orders', async (req, res) => {
    try {
        const db = await getDb();
        const { items, customerDetails, totalPrice } = req.body; 

        const orderRecord = {
            customerDetails,
            items,
            totalPrice,
            status: 'pending',
            createdAt: new Date()
        };
        const result = await db.collection("orders").insertOne(orderRecord);

        const updatePromises = items.map(item => {
            return db.collection("products").updateOne(
                { _id: new ObjectId(item.productId), "variants.size": item.size },
                { $inc: { "variants.$.stock": -Math.abs(item.quantity) } }
            );
        });

        await Promise.all(updatePromises);
        res.status(201).json({ message: "Order successful", orderId: result.insertedId });
    } catch (e) { res.status(500).json({ error: "Order failed: " + e.message }); }
});

// --- PUBLIC COLLECTION FETCH ---
router.get('/products', async (req, res) => {
    try {
        const db = await getDb();
        const items = await db.collection("products")
            .find({})
            .sort({ createdAt: -1, _id: -1 }) 
            .toArray();
        
        const refreshedItems = items.map(item => {
            if (s3 && item.imageKey) {
                try {
                    item.imageUrl = s3.getSignedUrl('getObject', {
                        Bucket: BUCKET_NAME,
                        Key: item.imageKey,
                        Expires: 86400 
                    });
                } catch (urlErr) {
                    item.imageUrl = "https://i.imgur.com/CVKXV7R.png"; 
                }
            } else {
                item.imageUrl = item.imageUrl || "https://i.imgur.com/CVKXV7R.png";
            }

            if (!item.variants || !Array.isArray(item.variants) || item.variants.length === 0) {
                item.variants = [{ size: "Default", price: item.price || 0, stock: item.stock || 0 }];
            }
            item.category = item.category ? item.category.toLowerCase().trim() : "unassigned";

            return item;
        });

        res.json(refreshedItems);
    } catch (e) { 
        res.status(500).json({ error: "Failed to load collection" }); 
    }
});

app.use('/.netlify/functions/api', router);
app.use('/api', router);
module.exports.handler = serverless(app);