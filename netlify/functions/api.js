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
        region: process.env.E2_REGION || 'us-west-1',
        s3ForcePathStyle: true,
        signatureVersion: 'v4'
    });
}
const BUCKET_NAME = process.env.E2_BUCKET || 'themotundebrand';

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

// --- UPDATED PRODUCT CREATION (POST) WITH STOCK ---
router.post('/admin/products', authenticateAdmin, async (req, res) => {
    try {
        if (!s3) throw new Error("Storage not configured");
        const db = await getDb();
        const { name, variants, description, category, imageBase64, fileName, contentType } = req.body;

        // Process Image
        const buffer = Buffer.from(imageBase64, 'base64');
        const cleanFileName = fileName.replace(/\s+/g, '-');
        const uploadKey = `${category}/${Date.now()}-${cleanFileName}`;

        await s3.upload({
            Bucket: BUCKET_NAME,
            Key: uploadKey,
            Body: buffer,
            ContentType: contentType
        }).promise();

        // Format Variants: Ensure prices and stock are numbers
        const formattedVariants = variants.map(v => ({
            size: v.size,
            price: parseFloat(v.price),
            stock: parseInt(v.stock) || 0 // New: Stock added as integer
        }));

        const product = { 
            name, 
            variants: formattedVariants,
            description, 
            category, 
            imageKey: uploadKey,
            createdAt: new Date() 
        };

        await db.collection("products").insertOne(product);
        res.status(201).json({ message: "Product added with variants and stock" });
    } catch (e) { 
        res.status(500).json({ error: e.message }); 
    }
});

// --- UPDATED PRODUCT UPDATE (PUT) WITH STOCK ---
router.put('/admin/products/:id', authenticateAdmin, async (req, res) => {
    try {
        if (!s3) throw new Error("Storage not configured");
        const db = await getDb();
        const productId = req.params.id;
        const { name, variants, description, category, imageBase64, fileName, contentType } = req.body;

        const existingProduct = await db.collection("products").findOne({ _id: new ObjectId(productId) });
        if (!existingProduct) return res.status(404).json({ error: "Product not found" });

        let updatedImageKey = existingProduct.imageKey;

        // Handle New Image Upload
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
                try {
                    await s3.deleteObject({ Bucket: BUCKET_NAME, Key: existingProduct.imageKey }).promise();
                } catch (delErr) { console.error("Old image cleanup failed"); }
            }
        }

        // Format Variants with Stock
        const formattedVariants = variants.map(v => ({
            size: v.size,
            price: parseFloat(v.price),
            stock: parseInt(v.stock) || 0 // New: Stock updated here
        }));

        const updateDoc = {
            $set: {
                name,
                variants: formattedVariants,
                description,
                category,
                imageKey: updatedImageKey,
                updatedAt: new Date()
            }
        };

        await db.collection("products").updateOne(
            { _id: new ObjectId(productId) },
            updateDoc
        );

        res.json({ message: "Product and stock levels updated successfully" });
    } catch (e) {
        res.status(500).json({ error: e.message });
    }
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

// --- PUBLIC PRODUCT FETCH ---
router.get('/products', async (req, res) => {
    try {
        const db = await getDb();
        const items = await db.collection("products").find({}).toArray();

        const refreshedItems = items.map(item => {
            if (s3 && item.imageKey) {
                item.imageUrl = s3.getSignedUrl('getObject', {
                    Bucket: BUCKET_NAME,
                    Key: item.imageKey,
                    Expires: 86400 // 24 Hours
                });
            }
            return item;
        });

        res.json(refreshedItems);
    } catch (e) { res.status(500).json({ error: "Fetch failed" }); }
});

app.use('/.netlify/functions/api', router);
app.use('/api', router);
module.exports.handler = serverless(app);