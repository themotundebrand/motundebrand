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

// --- IDRIVE E2 CONFIGURATION ---
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

// --- [UPDATED] DASHBOARD ANALYTICS ENDPOINT ---
// Now includes kidTotalStock for the new category
router.get('/admin/analytics/stock-overview', authenticateAdmin, async (req, res) => {
    try {
        const db = await getDb();
        const products = await db.collection("products").find({}).toArray();

        let womenTotalStock = 0;
        let menTotalStock = 0;
        let kidTotalStock = 0; // Added for kids

        products.forEach(product => {
            const totalProductUnits = (product.variants || []).reduce((sum, v) => sum + (parseInt(v.stock) || 0), 0);
            
            if (product.category === 'women') {
                womenTotalStock += totalProductUnits;
            } else if (product.category === 'men') {
                menTotalStock += totalProductUnits;
            } else if (product.category === 'kids') { // Added logic
                kidTotalStock += totalProductUnits;
            }
        });

        res.json({ womenTotalStock, menTotalStock, kidTotalStock });
    } catch (e) {
        res.status(500).json({ error: "Failed to calculate stock totals" });
    }
});

// --- ORDER PLACEMENT & STOCK DEDUCTION ---
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
                { 
                    _id: new ObjectId(item.productId),
                    "variants.size": item.size 
                },
                { 
                    $inc: { "variants.$.stock": -Math.abs(item.quantity) } 
                }
            );
        });

        await Promise.all(updatePromises);
        res.status(201).json({ message: "Order successful and stock updated", orderId: result.insertedId });
    } catch (e) {
        res.status(500).json({ error: "Order failed: " + e.message });
    }
});

// --- AUTH ROUTES ---
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

// --- PRODUCT CREATION ---
router.post('/admin/products', authenticateAdmin, async (req, res) => {
    try {
        if (!s3) throw new Error("Storage not configured");
        const db = await getDb();
        const { name, variants, description, category, imageBase64, fileName, contentType } = req.body;

        const buffer = Buffer.from(imageBase64, 'base64');
        const cleanFileName = fileName.replace(/\s+/g, '-');
        const uploadKey = `${category}/${Date.now()}-${cleanFileName}`;

        await s3.upload({
            Bucket: BUCKET_NAME,
            Key: uploadKey,
            Body: buffer,
            ContentType: contentType
        }).promise();

        const formattedVariants = variants.map(v => ({
            size: v.size,
            price: parseFloat(v.price),
            stock: parseInt(v.stock) || 0 
        }));

        const product = { 
            name, 
            variants: formattedVariants,
            description, 
            category, // Will correctly store 'kids', 'men', or 'women'
            imageKey: uploadKey,
            createdAt: new Date() 
        };

        await db.collection("products").insertOne(product);
        res.status(201).json({ message: "Product added successfully" });
    } catch (e) { res.status(500).json({ error: e.message }); }
});

// --- PRODUCT UPDATE ---
router.put('/admin/products/:id', authenticateAdmin, async (req, res) => {
    try {
        const db = await getDb();
        const productId = req.params.id;
        const { name, variants, description, category, imageBase64, fileName, contentType } = req.body;

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
                ContentType: contentType
            }).promise();

            if (existingProduct.imageKey) {
                try { await s3.deleteObject({ Bucket: BUCKET_NAME, Key: existingProduct.imageKey }).promise(); } 
                catch (delErr) { console.error("Old image cleanup failed"); }
            }
        }

        const formattedVariants = (variants || []).map(v => ({
            size: v.size,
            price: parseFloat(v.price),
            stock: parseInt(v.stock) || 0 
        }));

        await db.collection("products").updateOne(
            { _id: new ObjectId(productId) },
            { $set: { name, variants: formattedVariants, description, category, imageKey: updatedImageKey, updatedAt: new Date() } }
        );

        res.json({ message: "Product and stock updated" });
    } catch (e) { res.status(500).json({ error: e.message }); }
});

// --- DELETE PRODUCT ---
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

// --- PUBLIC FETCH ---
// Fetches all products and generates temporary signed URLs for images
router.get('/products', async (req, res) => {
    try {
        const db = await getDb();
        // Sort by newest first
        const items = await db.collection("products").find({}).sort({ createdAt: -1 }).toArray();
        
        const refreshedItems = items.map(item => {
            // Provide a default empty array if variants don't exist
            if (!item.variants) item.variants = [];
            
            // Generate a signed URL from IDrive E2 if an imageKey exists
            if (s3 && item.imageKey) {
                try {
                    item.imageUrl = s3.getSignedUrl('getObject', {
                        Bucket: BUCKET_NAME,
                        Key: item.imageKey,
                        Expires: 86400 // URL valid for 24 hours
                    });
                } catch (urlErr) {
                    console.error("Error generating signed URL for:", item.imageKey);
                    item.imageUrl = null;
                }
            } else {
                item.imageUrl = null; // Fallback for products without images
            }
            
            return item;
        });

        res.json(refreshedItems);
    } catch (e) { 
        console.error("Fetch Products Error:", e);
        res.status(500).json({ error: "Fetch failed: " + e.message }); 
    }
});

app.use('/.netlify/functions/api', router);
app.use('/api', router);
module.exports.handler = serverless(app);