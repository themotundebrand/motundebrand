const express = require('express');
const serverless = require('serverless-http');
const { MongoClient, ObjectId } = require('mongodb');
const helmet = require('helmet');
const compression = require('compression');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const AWS = require('aws-sdk'); // Import AWS SDK

const app = express();
const router = express.Router();

app.use(helmet());
app.use(compression());
app.use(express.json({ limit: '10mb' })); // Increased limit for Base64 images

const uri = process.env.MONGODB_URI;
const JWT_SECRET = process.env.JWT_SECRET;

// --- IDRIVE E2 CONFIGURATION ---
const s3 = new AWS.S3({
    accessKeyId: process.env.E2_ACCESS_KEY,
    secretAccessKey: process.env.E2_SECRET_KEY,
    endpoint: new AWS.Endpoint(process.env.E2_ENDPOINT), // s3.us-west-1.idrivee2.com
    region: process.env.E2_REGION,                       // us-west-1
    s3ForcePathStyle: true,
    signatureVersion: 'v4'
});

const BUCKET_NAME = process.env.E2_BUCKET; // themotundebrand

// Improved Connection Pooling
let cachedClient = null;
let cachedDb = null;

async function getDb() {
    if (cachedDb) return cachedDb;
    if (!cachedClient) {
        cachedClient = new MongoClient(uri);
        await cachedClient.connect();
    }
    cachedDb = cachedClient.db("themotundebrand");
    return cachedDb;
}

// --- AUTH MIDDLEWARE ---
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

// --- PRODUCT ROUTES ---

// GET Products
router.get('/products', async (req, res) => {
    try {
        const db = await getDb();
        const perfumes = await db.collection("products")
            .find({})
            .project({ name: 1, price: 1, imageUrl: 1, category: 1, size: 1, description: 1 }) 
            .toArray();
        res.status(200).json(perfumes);
    } catch (error) {
        res.status(500).json({ error: "Fetch failed" });
    }
});

// POST Admin Product (Uploads to IDrive E2 + Saves to MongoDB)
router.post('/admin/products', authenticateAdmin, async (req, res) => {
    try {
        const db = await getDb();
        const { 
            name, price, size, description, category, 
            imageBase64, fileName, contentType 
        } = req.body;

        if (!imageBase64 || !name || !price) {
            return res.status(400).json({ error: "Missing required product data or image." });
        }

        // 1. Process and Upload Image to IDrive e2
        const buffer = Buffer.from(imageBase64, 'base64');
        const uploadKey = `${category}/${Date.now()}-${fileName.replace(/\s+/g, '-')}`;

        const uploadParams = {
            Bucket: BUCKET_NAME,
            Key: uploadKey,
            Body: buffer,
            ContentType: contentType,
            ACL: 'public-read' // Allows the public to view the image via URL
        };

        const uploadResult = await s3.upload(uploadParams).promise();

        // 2. Save Product Info to MongoDB
        const product = {
            name,
            price: parseFloat(price),
            size,
            description,
            category, // 'women' or 'men'
            imageUrl: uploadResult.Location,
            createdAt: new Date()
        };

        const result = await db.collection("products").insertOne(product);
        
        res.status(201).json({ 
            message: "Product added and image stored", 
            id: result.insertedId,
            url: uploadResult.Location 
        });

    } catch (error) {
        console.error("Upload Error:", error);
        res.status(500).json({ error: "Failed to process product inventory update" });
    }
} );

// --- EXPORT ---
app.use('/.netlify/functions/api', router);
module.exports.handler = serverless(app);